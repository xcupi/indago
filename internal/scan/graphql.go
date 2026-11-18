package scan

// GraphQL API checks.
//
// One job targets one endpoint that speaks GraphQL. Discovery registers those
// endpoints from the conventional paths (/graphql, /api/graphql, /v1/graphql,
// /query — see internal/discovery/wellknown.go); the job type that runs this
// engine is wired by handlers.go, which this file deliberately does not touch.
//
// The engine asks four questions, each with its own bounded request:
//
//	1. introspection   POST {"query":"{__schema{types{name}}}"}
//	2. batching        POST {"query":"{a:__typename b:__typename c:__typename}"}
//	                   POST [{"query":"{__typename}"},{"query":"{__typename}"}]
//	3. verbose errors  POST {"query":"{__schema{queryTypee{name}}}"}
//	4. GET acceptance  GET  <endpoint>?query={__typename}
//	                   POST {"query":"{__typename}"} as text/plain
//
// Every document in this file is a constant, and every field it names is a
// built-in meta field: __typename and __schema. No mutation, subscription,
// user object, variable, fragment or directive is ever referenced, so no
// request can change target state and none can read application data — the
// most a confirmed check returns is the schema's type names. The batch probe is
// three aliases and, at most, two operations: enough to prove the endpoint does
// not enforce one-operation-per-request, never an amplification vector.
//
// At most seven requests leave per endpoint (one baseline plus up to six
// probes); a check whose primary probe already confirmed skips its fallback,
// which is why an exposed endpoint is usually done in five.
//
// A check is Confirmed only from a parsed JSON response that contains the field
// the probe asked for. A response that merely echoes the request is not
// evidence, and nothing here is decided by an LLM.
//
// The state-changing opt-in is consulted for POST transport. Without
// AllowStateChanging, the engine runs a GET baseline and the GET query check
// only; the POST-only checks (introspection, batching, verbose errors, and the
// text/plain GET-check fallback) are recorded as skipped. With
// AllowStateChanging, those read-only POST probes run too. Every document above
// is still a constant read-only query, so even the opt-in path never sends a
// mutation; the opt-in gates the transport method, not a change in intent.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const graphQLEngine = "graphql"

// Check identifiers. Stable strings: they appear in TestCase/Finding detail and
// let a report diff the same check across runs.
const (
	graphQLCheckIntrospection = "introspection"
	graphQLCheckBatching      = "batching"
	graphQLCheckVerboseErrors = "verbose_errors"
	graphQLCheckGETQueries    = "get_queries"

	// graphQLPostChecksSkippedReason is recorded on every check that needs a
	// POST transport when the operator has not opted into state-changing
	// methods. It is a coverage statement, not a verdict.
	graphQLPostChecksSkippedReason = "POST transport requires AllowStateChanging; check skipped"
)

// Probe documents. Constant on purpose — see the file header.
const (
	// graphQLTypenameQuery is the cheapest valid operation on any schema.
	graphQLTypenameQuery = "{__typename}"
	// graphQLIntrospectionQuery asks only for type names, never for fields,
	// directives or descriptions: the smallest disclosure that still proves
	// introspection is on.
	graphQLIntrospectionQuery = "{__schema{types{name}}}"
	// graphQLAliasBatchQuery resolves three aliases in ONE operation; a server
	// that executes all three has no per-operation field budget.
	graphQLAliasBatchQuery = "{a:__typename b:__typename c:__typename}"
	// graphQLVerboseErrorQuery names one field that cannot exist
	// ("queryTypee"), which is exactly what triggers a field suggestion in a
	// server that leaks validation detail.
	graphQLVerboseErrorQuery = "{__schema{queryTypee{name}}}"
	// graphQLArrayBatchBody is two independent operations in one request body.
	graphQLArrayBatchBody = `[{"query":"{__typename}"},{"query":"{__typename}"}]`
)

// maxGraphQLResponseBytes bounds what this engine parses. Every probe answer is
// tiny; anything larger is not the response to this probe.
const maxGraphQLResponseBytes = 1 << 20

// maxGraphQLTypeExamples bounds how many schema type names are quoted in a
// signal string.
const maxGraphQLTypeExamples = 6

type graphQLCheckResult struct {
	Name      string      `json:"name"`
	Confirmed bool        `json:"confirmed"`
	Skipped   bool        `json:"skipped,omitempty"`
	Status    int         `json:"status,omitempty"`
	Signal    string      `json:"signal,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Evidence  []domain.ID `json:"evidence_ids,omitempty"`
}

type graphQLDetail struct {
	Engine            string               `json:"engine"`
	Endpoint          string               `json:"endpoint"`
	IsGraphQL         bool                 `json:"graphql_endpoint"`
	BaselineMethod    string               `json:"baseline_method,omitempty"`
	POSTChecksSkipped bool                 `json:"post_checks_skipped,omitempty"`
	SkippedChecks     []string             `json:"skipped_checks,omitempty"`
	BaselineStatus    int                  `json:"baseline_status,omitempty"`
	TypeName          string               `json:"root_typename,omitempty"`
	Checks            []graphQLCheckResult `json:"checks,omitempty"`
	ConfirmedChecks   []string             `json:"confirmed_checks,omitempty"`
	Verdict           domain.Verdict       `json:"verdict"`
	Reason            string               `json:"reason,omitempty"`
	EvidenceIDs       []domain.ID          `json:"evidence_ids,omitempty"`
}

type graphQLExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

// NewGraphQLExecutorForTest exposes the executor to the external scan_test
// package without exporting production wiring.
func NewGraphQLExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *graphQLExecutor {
	return newGraphQLExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newGraphQLExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *graphQLExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &graphQLExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*graphQLExecutor)(nil)

// Handle runs every check against one endpoint and records one TestCase plus
// one Confirmed Finding per confirmed check.
func (e *graphQLExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, err := e.resolveEndpoint(ctx, job)
	if err != nil {
		return err
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishGraphQLUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}

	d := graphQLDetail{Engine: graphQLEngine, Endpoint: ep.URL}
	baseReq, err := e.graphQLBaselineRequest(ep)
	if err != nil {
		return fmt.Errorf("build graphql baseline: %w", err)
	}
	d.BaselineMethod = baseReq.Method
	baseResp, outcome, reqErr := e.send(ctx, job, baseReq, "graphql baseline", &d)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishGraphQLError(ctx, job, started, ep, baseReq.Method, outcome, reqErr)
	}
	d.BaselineStatus = baseResp.Status
	typename, isGraphQL := graphQLTypename(baseResp.Body)
	if !isGraphQL {
		// Not a GraphQL API (or one that refuses the cheapest valid query).
		// Running the exposure probes anyway would be payload noise against an
		// endpoint that never asked for them.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "endpoint did not answer the __typename probe as a GraphQL API"
		if !e.cfg.AllowStateChanging {
			d.POSTChecksSkipped = true
			d.Reason += " over GET; the POST baseline and POST-only checks are skipped because AllowStateChanging is off"
		}
		e.persistGraphQLCase(ctx, job, ep, d, domain.TestCaseSkipped, domain.OutcomeSuccess, "graphql skipped: "+d.Reason)
		return nil
	}
	d.IsGraphQL = true
	d.TypeName = typename
	if !e.cfg.AllowStateChanging {
		d.POSTChecksSkipped = true
		d.SkippedChecks = []string{graphQLCheckIntrospection, graphQLCheckBatching, graphQLCheckVerboseErrors}
	}

	d.Checks = append(d.Checks,
		e.checkIntrospection(ctx, job, ep, &d),
		e.checkBatching(ctx, job, ep, &d),
		e.checkVerboseErrors(ctx, job, ep, &d),
		e.checkGETQueries(ctx, job, ep, &d),
	)

	for _, check := range d.Checks {
		if check.Confirmed {
			d.ConfirmedChecks = append(d.ConfirmedChecks, check.Name)
		}
	}
	if len(d.ConfirmedChecks) == 0 {
		d.Verdict = domain.VerdictRejected
		d.Reason = "the endpoint speaks GraphQL but none of the exposure checks succeeded"
		if d.POSTChecksSkipped {
			d.Reason += "; POST-only checks skipped because AllowStateChanging is off"
		}
		e.persistGraphQLCase(ctx, job, ep, d, domain.TestCaseCompleted, domain.OutcomeSuccess, graphQLCaseNote("graphql: no exposure check confirmed", d))
		return nil
	}
	d.Verdict = domain.VerdictConfirmed
	d.Reason = "confirmed GraphQL exposure: " + strings.Join(d.ConfirmedChecks, ", ")
	if d.POSTChecksSkipped {
		d.Reason += "; POST-only checks skipped because AllowStateChanging is off"
	}
	e.persistGraphQLCase(ctx, job, ep, d, domain.TestCaseCompleted, domain.OutcomeSuccess, graphQLCaseNote("confirmed GraphQL exposure: "+strings.Join(d.ConfirmedChecks, ", "), d))
	e.correlateGraphQL(ctx, job, ep, d)
	return nil
}

// graphQLBaselineRequest is the one probe that decides whether the endpoint is
// GraphQL at all. Without the state-changing opt-in it must be a GET: a POST
// baseline would violate the default no-state-changing contract before any
// check could be skipped.
func (e *graphQLExecutor) graphQLBaselineRequest(ep *domain.Endpoint) (*httpengine.Request, error) {
	if e.cfg.AllowStateChanging {
		return graphQLPOST(ep.URL, graphQLTypenameQuery)
	}
	getURL, err := graphQLGETURL(ep.URL)
	if err != nil {
		return nil, err
	}
	return httpengine.GET(getURL), nil
}

// graphQLCaseNote makes the transport policy visible in the TestCase note, not
// only in the JSON detail.
func graphQLCaseNote(note string, d graphQLDetail) string {
	if d.POSTChecksSkipped {
		return note + " (POST-only checks skipped: AllowStateChanging is off)"
	}
	return note
}

// checkIntrospection asks for the type system. Confirmed only when the parsed
// response actually carries a non-empty __schema.types array.
func (e *graphQLExecutor) checkIntrospection(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d *graphQLDetail) graphQLCheckResult {
	res := graphQLCheckResult{Name: graphQLCheckIntrospection}
	if !e.cfg.AllowStateChanging {
		res.Skipped = true
		res.Reason = graphQLPostChecksSkippedReason
		return res
	}
	req, err := graphQLPOST(ep.URL, graphQLIntrospectionQuery)
	if err != nil {
		return res
	}
	before := len(d.EvidenceIDs)
	resp, outcome, _ := e.send(ctx, job, req, "graphql introspection", d)
	res.Evidence = d.EvidenceIDs[before:]
	if resp != nil {
		res.Status = resp.Status
	}
	if outcome != domain.OutcomeSuccess || resp == nil {
		return res
	}
	count, examples, ok := graphQLSchemaTypes(resp.Body)
	if !ok {
		return res
	}
	res.Confirmed = true
	res.Signal = fmt.Sprintf("schema introspection returned %d type names", count)
	if len(examples) > 0 {
		res.Signal += " (e.g. " + strings.Join(examples, ", ") + ")"
	}
	return res
}

// checkBatching proves the endpoint executes more than one operation per
// request: three aliases in one document, and — only if that did not already
// answer — two operations in one JSON array. Both are bounded at 3 and 2, so
// the probe demonstrates the primitive without any amplification.
func (e *graphQLExecutor) checkBatching(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d *graphQLDetail) graphQLCheckResult {
	res := graphQLCheckResult{Name: graphQLCheckBatching}
	if !e.cfg.AllowStateChanging {
		res.Skipped = true
		res.Reason = graphQLPostChecksSkippedReason
		return res
	}
	req, err := graphQLPOST(ep.URL, graphQLAliasBatchQuery)
	if err != nil {
		return res
	}
	before := len(d.EvidenceIDs)
	resp, outcome, _ := e.send(ctx, job, req, "graphql alias batch", d)
	res.Evidence = d.EvidenceIDs[before:]
	if resp != nil {
		res.Status = resp.Status
	}
	if outcome == domain.OutcomeSuccess && resp != nil {
		if values, ok := graphQLAliasValues(resp.Body, "a", "b", "c"); ok {
			res.Confirmed = true
			res.Signal = fmt.Sprintf("one operation resolved %d aliased fields (a=%s b=%s c=%s)",
				len(values), values["a"], values["b"], values["c"])
			return res
		}
	}
	// Array batching is the other shape (Apollo-style transport batching).
	arrayReq, err := graphQLPOSTRaw(ep.URL, graphQLArrayBatchBody, "application/json")
	if err != nil {
		return res
	}
	arrayBefore := len(d.EvidenceIDs)
	arrayResp, arrayOutcome, _ := e.send(ctx, job, arrayReq, "graphql operation batch", d)
	res.Evidence = append(res.Evidence, d.EvidenceIDs[arrayBefore:]...)
	if res.Status == 0 && arrayResp != nil {
		res.Status = arrayResp.Status
	}
	if arrayOutcome != domain.OutcomeSuccess || arrayResp == nil {
		return res
	}
	if n, ok := graphQLBatchOperations(arrayResp.Body); ok {
		res.Confirmed = true
		res.Signal = fmt.Sprintf("one request executed %d operations", n)
	}
	return res
}

// checkVerboseErrors sends a query with one impossible field name. A server that
// answers with a "did you mean" suggestion or a stack trace is disclosing its
// schema and its internals; a bare validation error is not enough to confirm.
func (e *graphQLExecutor) checkVerboseErrors(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d *graphQLDetail) graphQLCheckResult {
	res := graphQLCheckResult{Name: graphQLCheckVerboseErrors}
	if !e.cfg.AllowStateChanging {
		res.Skipped = true
		res.Reason = graphQLPostChecksSkippedReason
		return res
	}
	req, err := graphQLPOST(ep.URL, graphQLVerboseErrorQuery)
	if err != nil {
		return res
	}
	before := len(d.EvidenceIDs)
	resp, outcome, _ := e.send(ctx, job, req, "graphql verbose error", d)
	res.Evidence = d.EvidenceIDs[before:]
	if resp != nil {
		res.Status = resp.Status
	}
	if outcome != domain.OutcomeSuccess || resp == nil {
		return res
	}
	if signal := graphQLVerboseErrorSignal(resp.Body); signal != "" {
		res.Confirmed = true
		res.Signal = signal
	}
	return res
}

// checkGETQueries tests the CSRF precondition: a browser can send a GET (as an
// image/link navigation) or a text/plain POST cross-origin without a preflight.
// If either executes a query, a third-party page can drive this API with the
// victim's session.
func (e *graphQLExecutor) checkGETQueries(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d *graphQLDetail) graphQLCheckResult {
	res := graphQLCheckResult{Name: graphQLCheckGETQueries}
	getURL, err := graphQLGETURL(ep.URL)
	if err != nil {
		return res
	}
	before := len(d.EvidenceIDs)
	resp, outcome, _ := e.send(ctx, job, httpengine.GET(getURL), "graphql get query", d)
	res.Evidence = d.EvidenceIDs[before:]
	if resp != nil {
		res.Status = resp.Status
	}
	if outcome == domain.OutcomeSuccess && resp != nil {
		if _, ok := graphQLTypename(resp.Body); ok {
			res.Confirmed = true
			res.Signal = "a query supplied in the URL query string was executed"
			return res
		}
	}
	if !e.cfg.AllowStateChanging {
		res.Reason = "text/plain POST fallback skipped: AllowStateChanging is off"
		return res
	}
	// text/plain is the other "simple request" content type: no preflight, so
	// a cross-site form can send it.
	plainReq, err := graphQLPOSTRaw(ep.URL, `{"query":"`+graphQLTypenameQuery+`"}`, "text/plain")
	if err != nil {
		return res
	}
	plainBefore := len(d.EvidenceIDs)
	plainResp, plainOutcome, _ := e.send(ctx, job, plainReq, "graphql text/plain query", d)
	res.Evidence = append(res.Evidence, d.EvidenceIDs[plainBefore:]...)
	if res.Status == 0 && plainResp != nil {
		res.Status = plainResp.Status
	}
	if plainOutcome != domain.OutcomeSuccess || plainResp == nil {
		return res
	}
	if _, ok := graphQLTypename(plainResp.Body); ok {
		res.Confirmed = true
		res.Signal = "a text/plain POST was executed as a query (no preflight required)"
	}
	return res
}

// send runs one probe through the scope-enforcing engine and stores its
// request/response evidence. A failed request still returns its outcome so the
// caller can classify it.
func (e *graphQLExecutor) send(ctx context.Context, job *domain.TestJob, req *httpengine.Request, role string, d *graphQLDetail) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, fmt.Errorf("nil request")
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	var outcome domain.TestOutcome
	switch {
	case err == nil:
		outcome = domain.OutcomeSuccess
	case ctx.Err() != nil:
		outcome = domain.OutcomeCancelled
	default:
		outcome = domain.OutcomeError
	}
	if resp != nil {
		if ids, evErr := persistHTTPExchange(ctx, e.store, e.evidence, job.ScanID, resp, role); evErr == nil {
			d.EvidenceIDs = append(d.EvidenceIDs, ids...)
		}
	}
	return resp, outcome, err
}

// resolveEndpoint prefers the persisted endpoint (provenance, method, source)
// and falls back to the job's own URL so a job queued before discovery
// persisted the row still runs.
func (e *graphQLExecutor) resolveEndpoint(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, error) {
	if !job.Target.EndpointID.Empty() {
		if ep, err := e.store.Endpoints().Get(ctx, job.Target.EndpointID); err == nil && ep != nil {
			return ep, nil
		}
	}
	raw := strings.TrimSpace(job.Target.URL)
	if raw == "" {
		return nil, fmt.Errorf("graphql: job has no target endpoint")
	}
	return &domain.Endpoint{
		ID: job.Target.EndpointID, ScanID: job.ScanID, URL: raw,
		Method: domain.MethodPOST, Source: domain.SourceCrawler,
	}, nil
}

func (e *graphQLExecutor) persistGraphQLCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d graphQLDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	method := d.BaselineMethod
	if method == "" {
		method = string(domain.MethodGET)
	}
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnGraphQL,
		Status: status, Outcome: outcome, Method: method, URL: job.Target.URL,
		HTTPStatus: d.BaselineStatus, Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail,
		StartedAt: &now, FinishedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	if tc.URL == "" {
		tc.URL = ep.URL
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("graphql: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *graphQLExecutor) finishGraphQLUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	e.persistGraphQLSkip(ctx, job, ep, started, string(domain.MethodGET), reason)
	return nil
}

func (e *graphQLExecutor) finishGraphQLError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, method string, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		e.persistGraphQLSkip(ctx, job, ep, started, method, "redirect target is outside the scan scope")
		return nil
	}
	if isTLSRedirectMismatch(reqErr) {
		e.persistGraphQLSkip(ctx, job, ep, started, method, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
		return nil
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnGraphQL, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: method, URL: job.Target.URL, Error: msg, Note: "graphql baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist failed graphql case: %w", err)
	}
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("graphql baseline failed: %s", msg)
}

func (e *graphQLExecutor) persistGraphQLSkip(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, started time.Time, method, reason string) {
	if method == "" {
		method = string(domain.MethodGET)
	}
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnGraphQL, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: method, URL: ep.URL, Note: "graphql skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("graphql: persist skipped case", "scan", job.ScanID, "err", err)
	}
}

// correlateGraphQL persists one Confirmed Finding per confirmed check. A
// re-run of the same job must not duplicate a finding, so an existing
// (endpoint, title) pair is left untouched.
func (e *graphQLExecutor) correlateGraphQL(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d graphQLDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("graphql: resolve scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	existing, _ := e.store.Findings().ListByScan(ctx, job.ScanID)
	for _, check := range d.Checks {
		if !check.Confirmed {
			continue
		}
		title, summary, severity, ok := graphQLFindingCopy(check)
		if !ok || graphQLFindingExists(existing, ep.ID, title) {
			continue
		}
		now := time.Now()
		detail, _ := json.Marshal(struct {
			graphQLCheckResult
			Endpoint string `json:"endpoint"`
		}{check, ep.URL})
		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
			// InfoDisclosure is the closest class the domain currently models
			// for an API exposure/misconfiguration; Detail.name and the title
			// carry the exact check, so the taxonomy gap stays visible instead
			// of being hidden behind a wrong class.
			VulnClass: domain.VulnGraphQL,
			Verdict:   domain.VerdictConfirmed, Severity: severity, Confidence: domain.ConfidenceHigh,
			Title: title, Summary: summary,
			EndpointID:  ep.ID,
			EvidenceIDs: check.Evidence, Detail: detail,
			Provenance: domain.Provenance{Engine: graphQLEngine, DiscoverySource: ep.Source, DetectedAt: now},
			CreatedAt:  now, UpdatedAt: now,
		}
		if len(f.EvidenceIDs) == 0 {
			f.EvidenceIDs = d.EvidenceIDs
		}
		e.findingsMu.Lock()
		err := e.store.Findings().Create(ctx, f)
		e.findingsMu.Unlock()
		if err != nil {
			e.log.Warn("graphql: persist finding", "scan", job.ScanID, "check", check.Name, "err", err)
			continue
		}
		existing = append(existing, f)
	}
}

func graphQLFindingExists(findings []*domain.Finding, endpointID domain.ID, title string) bool {
	for _, f := range findings {
		if f == nil {
			continue
		}
		if f.EndpointID == endpointID && f.Title == title && f.Verdict == domain.VerdictConfirmed {
			return true
		}
	}
	return false
}

// graphQLFindingCopy maps a confirmed check to its reporting text. The severity
// reflects what the exposure actually buys an attacker: a schema map (medium),
// a batching primitive (low: it bypasses per-request limits but needs an
// existing way in), internal detail in errors (low), and CSRF-capable transport
// (medium: it turns a third-party page into a GraphQL client).
func graphQLFindingCopy(check graphQLCheckResult) (title, summary string, severity domain.Severity, ok bool) {
	switch check.Name {
	case graphQLCheckIntrospection:
		return "GraphQL introspection is enabled",
			"The endpoint answered a __schema query and disclosed its type system, which maps every query, mutation and object available to an attacker.",
			domain.SeverityMedium, true
	case graphQLCheckBatching:
		return "GraphQL endpoint accepts batched queries",
			"Multiple aliased fields or operations were executed from a single request, so per-request limits do not bound how much work one request can ask for.",
			domain.SeverityLow, true
	case graphQLCheckVerboseErrors:
		return "GraphQL endpoint discloses verbose validation errors",
			"A query with an impossible field name returned a field suggestion or an internal stack trace instead of a bare validation error.",
			domain.SeverityLow, true
	case graphQLCheckGETQueries:
		return "GraphQL endpoint accepts GET-based queries",
			"A GraphQL query supplied in the URL query string (or as a text/plain POST) was executed. Such a request needs no preflight, so a third-party page can drive this API with the visitor's session if cookies are sent.",
			domain.SeverityMedium, true
	default:
		return "", "", "", false
	}
}

// ---------------------------------------------------------------------------
// request builders
// ---------------------------------------------------------------------------

func graphQLPOST(endpoint, query string) (*httpengine.Request, error) {
	return httpengine.POSTJSON(endpoint, map[string]string{"query": query})
}

func graphQLPOSTRaw(endpoint, body, contentType string) (*httpengine.Request, error) {
	req := httpengine.NewRequest("POST", endpoint)
	req.Body = []byte(body)
	req.ContentType = contentType
	return req, nil
}

// graphQLGETURL puts the probe into the query string without disturbing any
// query the endpoint already carries.
func graphQLGETURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("query", graphQLTypenameQuery)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ---------------------------------------------------------------------------
// response parsers (pure)
// ---------------------------------------------------------------------------

type graphQLResponseDoc struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors"`
}

type graphQLError struct {
	Message string          `json:"message"`
	Stack   json.RawMessage `json:"stack,omitempty"`
}

// parseGraphQLDoc parses a GraphQL response envelope. A JSON document with
// neither "data" nor "errors" is not a GraphQL response, whatever else it
// contains.
func parseGraphQLDoc(body []byte) (graphQLResponseDoc, bool) {
	var doc graphQLResponseDoc
	if len(body) == 0 || len(body) > maxGraphQLResponseBytes {
		return doc, false
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, false
	}
	if doc.Data == nil && doc.Errors == nil {
		return doc, false
	}
	return doc, true
}

// graphQLTypename returns the value of the __typename field the probe asked
// for. Only a parsed, non-empty string counts: an echoed request body does not.
func graphQLTypename(body []byte) (string, bool) {
	doc, ok := parseGraphQLDoc(body)
	if !ok || len(doc.Data) == 0 || string(doc.Data) == "null" {
		return "", false
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(doc.Data, &data); err != nil {
		return "", false
	}
	raw, present := data["__typename"]
	if !present {
		return "", false
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil || strings.TrimSpace(name) == "" {
		return "", false
	}
	return name, true
}

// graphQLSchemaTypes returns how many type names the schema disclosed, plus a
// bounded sample for evidence.
func graphQLSchemaTypes(body []byte) (int, []string, bool) {
	var payload struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name string `json:"name"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if len(body) == 0 || len(body) > maxGraphQLResponseBytes {
		return 0, nil, false
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, nil, false
	}
	types := payload.Data.Schema.Types
	if len(types) == 0 {
		return 0, nil, false
	}
	examples := make([]string, 0, maxGraphQLTypeExamples)
	for _, t := range types {
		name := truncate(strings.TrimSpace(t.Name), 40)
		if name == "" || name == "__typename" {
			continue // the meta field the probe itself asked for is not a disclosure
		}
		examples = append(examples, name)
		if len(examples) >= maxGraphQLTypeExamples {
			break
		}
	}
	return len(types), examples, true
}

// graphQLAliasValues returns the alias values in a batched response, but only
// when every requested alias answered with a non-empty string.
func graphQLAliasValues(body []byte, aliases ...string) (map[string]string, bool) {
	doc, ok := parseGraphQLDoc(body)
	if !ok || len(doc.Data) == 0 || string(doc.Data) == "null" {
		return nil, false
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(doc.Data, &data); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		raw, present := data[alias]
		if !present {
			return nil, false
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || strings.TrimSpace(value) == "" {
			return nil, false
		}
		out[alias] = truncate(value, 40)
	}
	return out, true
}

// graphQLBatchOperations counts how many operations of a JSON-array batch
// executed, and reports success only when at least two did.
func graphQLBatchOperations(body []byte) (int, bool) {
	if len(body) == 0 || len(body) > maxGraphQLResponseBytes {
		return 0, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err != nil || len(items) < 2 {
		return 0, false
	}
	executed := 0
	for _, item := range items {
		if _, ok := graphQLTypename(item); ok {
			executed++
		}
	}
	return executed, executed >= 2
}

// graphQLVerboseErrorSignal returns a short label when the response leaks a
// field suggestion or an internal stack trace. A bare validation error
// ("Cannot query field ...") is standard GraphQL behaviour and deliberately not
// enough on its own.
func graphQLVerboseErrorSignal(body []byte) string {
	doc, ok := parseGraphQLDoc(body)
	if !ok || len(doc.Errors) == 0 {
		return ""
	}
	// JSON escapes the newlines in a stack, so decode the string fields before
	// looking for frame markers; the raw body is still scanned as a fallback
	// for servers that put the trace somewhere other than "stack".
	var text strings.Builder
	for _, e := range doc.Errors {
		text.WriteString(strings.ToLower(e.Message))
		text.WriteString("\n")
		if len(e.Stack) > 0 {
			var stack string
			if json.Unmarshal(e.Stack, &stack) == nil {
				text.WriteString(strings.ToLower(stack))
				text.WriteString("\n")
			}
		}
	}
	joined := text.String()
	for _, marker := range []string{"did you mean", "didyoumean", "similar field", "perhaps you meant"} {
		if strings.Contains(joined, marker) {
			return "validation error suggests a field name (" + marker + ")"
		}
	}
	lowerBody := strings.ToLower(string(body))
	for _, marker := range []string{
		"traceback (most recent call last)",
		"graphql.validation",
		"graphql.execution",
		"at object.<anonymous>",
		"    at ", // stack frame indentation
		"node_modules/",
		".java:",
		".js:",
		".rb:",
		`file "`, // Python traceback frame
	} {
		if strings.Contains(joined, marker) || strings.Contains(lowerBody, marker) {
			return "validation error returns an internal stack trace"
		}
	}
	return ""
}

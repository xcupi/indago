package scan

// NoSQL query-operator injection engine (CWE-943).
//
// One JobNoSQLi is enqueued per eligible injection point. Only a GET-style,
// non-state-changing endpoint is ever tested, and only through its QUERY
// parameters: the engine copies the request that discovery already made and
// changes the shape of ONE parameter. Nothing here is an exploit:
//
//   - no update/delete operator ($set, $unset, $inc, $push, $rename, ...) is
//     ever sent, and no JavaScript execution operator ($where, $function,
//     mapReduce) is ever sent;
//   - the only operators used are SELECTION operators ($ne, $gt), which can
//     only make the server's existing read query match more or fewer
//     documents;
//   - the array shapes ("param[]=value") only change the parameter's TYPE,
//     which is what a framework such as Express/Mongoose hands to the driver;
//   - the endpoint must not be write-like, and the state-changing opt-in does
//     NOT relax that: this pass is read-only by construction.
//
// Two deterministic signals are used, and a verdict is CONFIRMED only with two
// independent signals (exactly like the SQL engine):
//
//  1. Error-based. A bracket-shaped or operator-shaped request returns a
//     recognized document-database error message (MongoDB/Mongoose casting,
//     Mongo operator parsing, Elasticsearch query parsing) that the BASELINE
//     and the BENIGN CONTROL (the same parameter with an ordinary nonexistent
//     string value) did not contain. The control suppression is what keeps a
//     plain value-validation bug — an endpoint that throws a cast error for
//     any unknown id — from being counted as operator injection.
//
//  2. Differential. The benign plain control ("param=indago_absent_...") must
//     return a DIFFERENT page from the baseline, proving that a value which
//     matches nothing is distinguishable. Then an operator probe
//     ("param[$ne]=indago_absent_...", "param[$gt]=") must reproduce the
//     BASELINE page while the array control ("param[]=indago_absent_..."),
//     which carries the same value and the same bracket family, does NOT. The
//     only remaining difference is the operator itself, so the server's query
//     predicate — not merely the value — was changed by the caller.
//
// Transport errors, throttling and ordinary pages are never promoted to a
// finding. A single signal is INCONCLUSIVE, never Confirmed.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	nosqliEngine = "nosqli"

	// nosqliPriority runs the NoSQL pass just after the SQL engine. Neither
	// depends on the other; the ordering only keeps the queue deterministic.
	nosqliPriority = 48

	// maxNoSQLiProbes bounds target requests per injection point: one baseline
	// plus at most five probes (plain control, array control, empty array and
	// two operator shapes). The engine stops as soon as two signals are
	// confirmed, so a vulnerable point usually costs fewer.
	maxNoSQLiProbes = 8
)

// The differential compares response SHAPE, not bytes: a page may carry a
// timestamp or a CSRF token that changes on every request, and a byte diff
// would then call every probe a divergence and invent findings. These reuse
// the SQL engine's size-ratio thresholds on purpose — the underlying question
// ("is this the same page?") is identical.
const nosqliDifferentThreshold = sqlDifferentThreshold

// nosqliMatchesBaseline reports whether resp looks like the same page the
// baseline returned: same status and essentially the same size.
func nosqliMatchesBaseline(base, resp *httpengine.Response) bool {
	return sqlMatchesBaseline(base, resp)
}

// nosqliDivergesFromBaseline reports whether resp is clearly a different page
// from the baseline: a different status, or a size well outside the baseline's.
func nosqliDivergesFromBaseline(base, resp *httpengine.Response) bool {
	return sqlDivergesFromBaseline(base, resp)
}

// nosqliRicherThan reports whether a is clearly a larger response than b with
// the same status. Some endpoints answer a match with the whole collection
// rather than the one row the baseline showed, so "reproduced the baseline" is
// not the only way operator semantics reveal themselves; a response that is
// unambiguously larger than the shape control (same value, same bracket
// family, no operator) is the other.
func nosqliRicherThan(a, b *httpengine.Response) bool {
	if a == nil || b == nil || a.Status != b.Status || len(a.Body) <= len(b.Body) {
		return false
	}
	return sqlBodyRatio(a.Body, b.Body) < nosqliDifferentThreshold
}

type nosqliExecutor struct {
	*commandInjectionExecutor
}

// NewNoSQLiExecutorForTest exposes the executor to tests without exporting the
// production constructor.
func NewNoSQLiExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *nosqliExecutor {
	return newNoSQLiExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newNoSQLiExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *nosqliExecutor {
	return &nosqliExecutor{commandInjectionExecutor: newCommandInjectionExecutor(st, eng, ev, cfg, log, findingsMu)}
}

var _ worker.Handler = (*nosqliExecutor)(nil)

type nosqliAttempt struct {
	Payload string `json:"payload"`
	// Kind is control, array, array-empty, operator-ne or operator-gt.
	Kind string `json:"kind,omitempty"`
	Key  string `json:"key,omitempty"`
	// Role is control for the two benign controls and probe for anything that
	// carries operator syntax.
	Role              string `json:"role,omitempty"`
	Status            int    `json:"status,omitempty"`
	BodyLength        int    `json:"body_length,omitempty"`
	ErrorSignature    string `json:"error_signature,omitempty"`
	Product           string `json:"product,omitempty"`
	MatchesBaseline   bool   `json:"matches_baseline,omitempty"`
	DivergesBaseline  bool   `json:"diverges_baseline,omitempty"`
	DivergesFromShape bool   `json:"diverges_from_array_control,omitempty"`
}

// nosqliPoC is the exact request shape that produced a confirmed signal,
// recorded so a triager can reproduce it without reconstructing the parameter
// set.
type nosqliPoC struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Payload string `json:"payload"`
	Key     string `json:"key"`
}

type nosqliDetail struct {
	Engine         string               `json:"engine"`
	Parameter      string               `json:"parameter"`
	Location       domain.ParamLocation `json:"location"`
	BaselineStatus int                  `json:"baseline_status,omitempty"`
	BaselineLength int                  `json:"baseline_length,omitempty"`
	// ControlJudgeable records that the benign plain control returned a
	// different page from the baseline, which is what makes the operator
	// differential meaningful at all.
	ControlJudgeable bool            `json:"control_judgeable"`
	Attempts         []nosqliAttempt `json:"attempts,omitempty"`
	// ErrorSignals counts distinct probes that produced a recognized database
	// error signature neither the baseline NOR the benign control carried.
	// DifferentialSignals counts operator probes that reproduced the baseline
	// (or a clearly larger result) while the controls behaved as a no-match.
	ErrorSignals        int            `json:"error_signals"`
	DifferentialSignals int            `json:"differential_signals"`
	ConfirmedCount      int            `json:"confirmed_count"`
	IdentifiedProduct   string         `json:"identified_product,omitempty"`
	PoC                 *nosqliPoC     `json:"poc,omitempty"`
	Throttled           bool           `json:"throttled,omitempty"`
	Verdict             domain.Verdict `json:"verdict"`
	ConfirmMethod       string         `json:"confirm_method,omitempty"` // error, error_differential or differential
	Reason              string         `json:"reason,omitempty"`
	EvidenceIDs         []domain.ID    `json:"evidence_ids,omitempty"`
}

// nosqlErrorSignature is one recognized document-database error message.
type nosqlErrorSignature struct {
	product string
	label   string
	pattern *regexp.Regexp
}

func nosqlSignature(product, label, expr string) nosqlErrorSignature {
	return nosqlErrorSignature{product: product, label: label, pattern: regexp.MustCompile("(?i)" + expr)}
}

// nosqlErrorSignatures is the bounded recognition table. Every entry is a
// message a document database or its driver emits when a query value cannot be
// interpreted; a generic page that merely mentions MongoDB never matches.
var nosqlErrorSignatures = []nosqlErrorSignature{
	// MongoDB server and the BSON layer.
	nosqlSignature("MongoDB", "MongoServerError", `MongoServerError`),
	nosqlSignature("MongoDB", "MongoError", `MongoError`),
	nosqlSignature("MongoDB", "BSONError", `BSONError`),
	nosqlSignature("MongoDB", "BSONTypeError", `BSONTypeError`),
	nosqlSignature("MongoDB", "MongoParseError", `MongoParseError`),
	nosqlSignature("MongoDB", "unknown top level operator", `unknown top level operator`),
	nosqlSignature("MongoDB", "unknown operator", `unknown operator:?\s*\$`),

	// Mongoose casting — the most common Node/Mongo stack. A plain string id
	// that fails to cast is suppressed by the benign control; a bracket shape
	// that fails to cast is not.
	nosqlSignature("Mongoose", "Cast to string failed", `Cast to string failed`),
	nosqlSignature("Mongoose", "Cast to ObjectId failed", `Cast to ObjectId failed`),
	nosqlSignature("Mongoose", "CastError", `CastError`),

	// Elasticsearch query parser.
	nosqlSignature("Elasticsearch", "search_phase_execution_exception", `search_phase_execution_exception`),
	nosqlSignature("Elasticsearch", "query_shard_exception", `query_shard_exception`),
}

// nosqlErrorSignaturesIn returns the labels of every recognized signature
// present in body.
func nosqlErrorSignaturesIn(body []byte) map[string]bool {
	found := map[string]bool{}
	for _, sig := range nosqlErrorSignatures {
		if sig.pattern.Match(body) {
			found[sig.label] = true
		}
	}
	return found
}

// nosqlNewErrorSignature returns the first recognized signature present in
// body that none of the suppressed signatures covers.
func nosqlNewErrorSignature(body []byte, suppressed map[string]bool) (nosqlErrorSignature, bool) {
	for _, sig := range nosqlErrorSignatures {
		if suppressed[sig.label] {
			continue
		}
		if sig.pattern.Match(body) {
			return sig, true
		}
	}
	return nosqlErrorSignature{}, false
}

// nosqliProbe is one request shape for one parameter. Key is the query-string
// key written to the wire (the brackets are percent-encoded by the request
// builder); Value is its value.
type nosqliProbe struct {
	Name     string
	Key      string
	Value    string
	Kind     string
	Operator bool
}

// nosqliOperatorProbes is the bounded read-only operator set. Both operators
// only SELECT: $ne matches documents whose field differs from the value, $gt
// matches documents whose field sorts after the empty string. Neither can
// modify a document.
func nosqliOperatorProbes(paramName, absent string) []nosqliProbe {
	return []nosqliProbe{
		{Name: "operator-ne", Key: paramName + "[$ne]", Value: absent, Kind: "operator-ne", Operator: true},
		{Name: "operator-gt", Key: paramName + "[$gt]", Value: "", Kind: "operator-gt", Operator: true},
	}
}

// nosqliArrayProbes is the bounded array-shape set. An empty array and an
// array carrying a nonexistent value are the two shapes a framework hands to
// a document driver as a non-string query value.
func nosqliArrayProbes(paramName, absent string) []nosqliProbe {
	return []nosqliProbe{
		{Name: "array-absent", Key: paramName + "[]", Value: absent, Kind: "array"},
		{Name: "array-empty", Key: paramName + "[]", Value: "", Kind: "array-empty"},
	}
}

// nosqliShapeRequest rewrites ONE query parameter of base into an explicit
// shape (key=value), leaving every other query parameter at its observed
// value. key and value are percent-encoded, so "param[]" and "param[$ne]"
// reach the server exactly as a browser's URLSearchParams would send them and
// are decoded back to the same key by the framework.
func nosqliShapeRequest(base *httpengine.Request, paramName, key, value string) (*httpengine.Request, error) {
	if base == nil {
		return nil, fmt.Errorf("nil base request")
	}
	u, err := url.Parse(base.URL)
	if err != nil {
		return nil, fmt.Errorf("endpoint URL %q: %w", base.URL, err)
	}
	q := u.Query()
	// Remove every shape of the focused parameter: the plain value the
	// baseline carried and any bracket form an earlier probe left behind.
	q.Del(paramName)
	for _, suffix := range []string{"[]", "[$ne]", "[$gt]"} {
		q.Del(paramName + suffix)
	}
	encoded := q.Encode()
	pair := url.QueryEscape(key) + "=" + url.QueryEscape(value)
	if encoded != "" {
		encoded += "&"
	}
	u.RawQuery = encoded + pair
	req := *base
	req.URL = u.String()
	return &req, nil
}

// nosqliEligibleLocation reports whether this engine may test the location.
// Only query parameters are in scope: a header/cookie/path/body operator would
// need a different request shape, and this pass is deliberately GET-only.
func nosqliEligibleLocation(loc domain.ParamLocation) bool {
	return loc == domain.LocationQuery
}

// nosqliSafeEndpoint reports whether the endpoint may be touched at all. It is
// stricter than the other payload engines on purpose: the state-changing
// opt-in does NOT widen it, because a NoSQL check is only ever a read.
func nosqliSafeEndpoint(ep *domain.Endpoint, params []*domain.Parameter) bool {
	if ep == nil {
		return false
	}
	switch ep.Method {
	case domain.MethodGET, "":
	default:
		return false
	}
	return !isWriteLikeEndpoint(ep, params)
}

func (e *nosqliExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve nosqli target: %w", err)
	}
	if focus == nil {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !nosqliEligibleLocation(focus.Location) || isDynamicTokenName(focus.Name) {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "parameter location is not a GET query parameter")
	}
	if !nosqliSafeEndpoint(ep, params) {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}

	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build nosqli baseline: %w", err)
	}
	baseResp, outcome, reqErr := e.do(ctx, base)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishNoSQLiError(ctx, job, started, ep, focus, outcome, reqErr)
	}

	d := nosqliDetail{Engine: nosqliEngine, Parameter: focus.Name, Location: focus.Location,
		BaselineStatus: baseResp.Status, BaselineLength: len(baseResp.Body)}
	baseEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "nosqli baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baseEvidence...)

	// 429/503 is backpressure or downtime, not a judgement on the query. No
	// probe is sent: every result would describe the throttle, not the sink.
	if isThrottleStatus(baseResp.Status) {
		d.Throttled = true
		d.Verdict = domain.VerdictInconclusive
		d.Reason = fmt.Sprintf("the target answered HTTP %d to the unmutated baseline, so no operator was sent", baseResp.Status)
		e.persistNoSQLiCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess,
			"nosqli skipped: target throttled the baseline request")
		return nil
	}
	// A gate status means the parameter was never evaluated. Sending operator
	// syntax anyway would spend requests against the gate and record a
	// negative-looking result for a sink that was never reached.
	if gate, gated := commandInjectionGateFor(baseResp.Status); gated {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = gate.Reason
		e.persistNoSQLiCase(ctx, job, ep, focus, d, domain.TestCaseSkipped, domain.OutcomeSuccess,
			fmt.Sprintf("nosqli skipped: %s (HTTP %d): %s; no operator was sent", gate.Note, baseResp.Status, gate.Reason))
		return nil
	}

	absent := nosqliAbsentMarker(job, focus)
	p := &nosqliProber{
		e: e, job: job, ep: ep, focus: focus, params: params, base: baseResp,
		baseErrors: nosqlErrorSignaturesIn(baseResp.Body), d: &d,
	}

	// Phase 1: benign plain control. It answers two questions at once — does a
	// nonexistent value look different (so a differential is judgeable), and
	// which error signatures belong to ordinary value validation (so they are
	// never attributed to operator syntax).
	d.ControlJudgeable = p.runPlainControl(ctx, absent)

	// Phase 2: array shapes. These are the error-based signal and, together
	// with the plain control, the reference that keeps an operator match from
	// being explained by bracket syntax or by the value alone.
	shapeControl := p.runArrayProbes(ctx, absent)

	// Phase 3: read-only selection operators. Only meaningful when the plain
	// control diverged (a nonexistent VALUE is distinguishable) and the array
	// control did not already reproduce the baseline (brackets ALONE are not
	// the cause).
	p.runOperators(ctx, absent, shapeControl)

	d.ConfirmedCount = d.ErrorSignals + d.DifferentialSignals
	switch {
	case d.ErrorSignals >= 2:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "error"
		d.Reason = "two independent bracket/operator shapes produced a document-database error signature neither the baseline nor a benign control value contained"
	case d.ErrorSignals >= 1 && d.DifferentialSignals >= 1:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "error_differential"
		d.Reason = "a new document-database error signature and an independent operator differential agree"
	case d.DifferentialSignals >= 2:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "differential"
		d.Reason = "two read-only selection operators reproduced the baseline while the plain and array controls behaved as a no-match"
	case d.ErrorSignals == 1:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one new document-database error signature was observed; a second independent signal is required"
	case d.DifferentialSignals == 1:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one operator differential was observed; a second independent operator is required"
	case !d.ControlJudgeable:
		d.Verdict = domain.VerdictRejected
		d.Reason = "a benign nonexistent value returned the baseline page, so an operator differential cannot be distinguished from ordinary empty-result handling"
	default:
		d.Verdict = domain.VerdictRejected
	}
	if d.Throttled && d.Verdict != domain.VerdictConfirmed {
		// The pass did not finish: say so instead of pretending the sink was
		// clean.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the target throttled a probe (HTTP 429/503), so the operator set was not completed"
	}

	note := "no NoSQL query-operator signal observed"
	if d.Verdict == domain.VerdictConfirmed {
		note = "confirmed NoSQL injection: " + d.Reason
		e.persistNoSQLiCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
		e.correlateNoSQLi(ctx, job, ep, focus, d)
		return nil
	}
	if d.Verdict == domain.VerdictInconclusive {
		note = d.Reason
	}
	e.persistNoSQLiCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
	return nil
}

// nosqliAbsentMarker is a deterministic, unique value that no real document is
// expected to carry. It is derived from the job and the parameter so a re-run
// of the same job sends the same bytes (reproducibility) while two different
// injection points never share a marker.
func nosqliAbsentMarker(job *domain.TestJob, focus *domain.Parameter) string {
	id := string(job.ID)
	if len(id) > 12 {
		id = id[:12]
	}
	name := strings.NewReplacer("[", "", "]", "", "$", "").Replace(focus.Name)
	if len(name) > 24 {
		name = name[:24]
	}
	return "indago_absent_" + strings.ToLower(name) + "_" + strings.ToLower(id)
}

// nosqliProber carries one job's probe state so every phase shares the same
// request construction, evidence persistence and refreshed-parameter handling.
type nosqliProber struct {
	e           *nosqliExecutor
	job         *domain.TestJob
	ep          *domain.Endpoint
	focus       *domain.Parameter
	params      []*domain.Parameter
	base        *httpengine.Response
	baseErrors  map[string]bool
	controlErrs map[string]bool
	d           *nosqliDetail
	sent        int
	throttled   bool
	poc         *nosqliPoC
}

// budgetLeft reports whether another target request still fits inside
// maxNoSQLiProbes.
func (p *nosqliProber) budgetLeft() bool { return p.sent < maxNoSQLiProbes }

// sendPlain sends the focused parameter at an ordinary string value, exactly
// like every other GET probe in the scanner.
func (p *nosqliProber) sendPlain(ctx context.Context, value, role string) (*httpengine.Response, domain.TestOutcome) {
	p.sent++
	p.params = fillEmptyCommandParams(p.e.refreshParams(ctx, p.ep, p.params, p.focus), p.focus)
	req, err := buildRequest(p.ep, p.params, &injection{param: p.focus, value: value})
	if err != nil {
		return nil, domain.OutcomeError
	}
	resp, outcome, _ := p.e.do(ctx, req)
	if outcome == domain.OutcomeSuccess && resp != nil {
		ids, _ := p.e.persistEvidence(ctx, p.job.ScanID, resp, role)
		p.d.EvidenceIDs = append(p.d.EvidenceIDs, ids...)
	}
	return resp, outcome
}

// sendShape sends the focused parameter in an explicit bracket/operator shape.
func (p *nosqliProber) sendShape(ctx context.Context, key, value, role string) (*httpengine.Response, domain.TestOutcome) {
	p.sent++
	p.params = fillEmptyCommandParams(p.e.refreshParams(ctx, p.ep, p.params, p.focus), p.focus)
	baseReq, err := buildRequest(p.ep, p.params, nil)
	if err != nil {
		return nil, domain.OutcomeError
	}
	req, err := nosqliShapeRequest(baseReq, p.focus.Name, key, value)
	if err != nil {
		return nil, domain.OutcomeError
	}
	resp, outcome, _ := p.e.do(ctx, req)
	if outcome == domain.OutcomeSuccess && resp != nil {
		ids, _ := p.e.persistEvidence(ctx, p.job.ScanID, resp, role)
		p.d.EvidenceIDs = append(p.d.EvidenceIDs, ids...)
	}
	return resp, outcome
}

// throttledNow records a 429/503 answer and reports whether probing must stop.
func (p *nosqliProber) throttledNow(resp *httpengine.Response, outcome domain.TestOutcome) bool {
	if outcome == domain.OutcomeSuccess && resp != nil && isThrottleStatus(resp.Status) {
		p.throttled = true
		p.d.Throttled = true
		return true
	}
	return false
}

// runPlainControl sends the benign control value as a plain string. It returns
// true when the control clearly differs from the baseline, which is the
// precondition for any differential; it also records the control's error
// signatures so an ordinary "unknown id" cast error can never be counted as
// operator injection.
func (p *nosqliProber) runPlainControl(ctx context.Context, absent string) bool {
	attempt := nosqliAttempt{Payload: absent, Kind: "control", Role: "control", Key: p.focus.Name}
	resp, outcome := p.sendPlain(ctx, absent, "nosqli benign control")
	if resp != nil {
		attempt.Status = resp.Status
		attempt.BodyLength = len(resp.Body)
	}
	if p.throttledNow(resp, outcome) || outcome != domain.OutcomeSuccess || resp == nil {
		p.d.Attempts = append(p.d.Attempts, attempt)
		return false
	}
	attempt.DivergesBaseline = nosqliDivergesFromBaseline(p.base, resp)
	attempt.MatchesBaseline = nosqliMatchesBaseline(p.base, resp)
	p.d.Attempts = append(p.d.Attempts, attempt)
	p.controlErrs = nosqlErrorSignaturesIn(resp.Body)
	// The control is a benign value, never a probe: an error here is a
	// value-validation artifact, not an operator signal.
	return attempt.DivergesBaseline
}

// runArrayProbes sends the two array shapes and returns the array control
// response (the nonexistent value in array form). The empty-array shape is the
// second independent error probe; the array control is the reference that
// keeps bracket syntax from being mistaken for an operator effect.
func (p *nosqliProber) runArrayProbes(ctx context.Context, absent string) *httpengine.Response {
	var shapeControl *httpengine.Response
	for _, probe := range nosqliArrayProbes(p.focus.Name, absent) {
		if !p.budgetLeft() {
			break
		}
		attempt := nosqliAttempt{Payload: probe.Value, Kind: probe.Kind, Role: "probe", Key: probe.Key}
		resp, outcome := p.sendShape(ctx, probe.Key, probe.Value, "nosqli array probe "+probe.Name)
		if resp != nil {
			attempt.Status = resp.Status
			attempt.BodyLength = len(resp.Body)
		}
		if p.throttledNow(resp, outcome) {
			p.d.Attempts = append(p.d.Attempts, attempt)
			break
		}
		if outcome == domain.OutcomeSuccess && resp != nil {
			attempt.MatchesBaseline = nosqliMatchesBaseline(p.base, resp)
			attempt.DivergesBaseline = nosqliDivergesFromBaseline(p.base, resp)
			p.countErrorSignal(resp, &attempt)
		}
		p.d.Attempts = append(p.d.Attempts, attempt)
		if probe.Kind == "array" {
			shapeControl = resp
		}
		if p.d.ErrorSignals >= 2 {
			break
		}
	}
	return shapeControl
}

// runOperators sends the read-only selection operators. A probe counts as a
// differential only when:
//
//   - the plain benign control diverged from the baseline (a nonexistent VALUE
//     is distinguishable at all),
//   - the array control did NOT reproduce the baseline (bracket syntax alone
//     is not the cause), and
//   - the operator reproduced the baseline, or returned a clearly larger
//     result than the array control with the same status.
func (p *nosqliProber) runOperators(ctx context.Context, absent string, shapeControl *httpengine.Response) {
	if p.throttled || !p.d.ControlJudgeable || p.d.ErrorSignals >= 2 {
		return
	}
	if shapeControl != nil && nosqliMatchesBaseline(p.base, shapeControl) {
		// Brackets alone already return the baseline page, so an operator
		// match would prove nothing about operator semantics.
		return
	}
	for _, probe := range nosqliOperatorProbes(p.focus.Name, absent) {
		if !p.budgetLeft() || p.d.DifferentialSignals >= 2 {
			return
		}
		attempt := nosqliAttempt{Payload: probe.Value, Kind: probe.Kind, Role: "probe", Key: probe.Key}
		resp, outcome := p.sendShape(ctx, probe.Key, probe.Value, "nosqli operator probe "+probe.Name)
		if resp != nil {
			attempt.Status = resp.Status
			attempt.BodyLength = len(resp.Body)
		}
		if p.throttledNow(resp, outcome) {
			p.d.Attempts = append(p.d.Attempts, attempt)
			return
		}
		if outcome != domain.OutcomeSuccess || resp == nil {
			p.d.Attempts = append(p.d.Attempts, attempt)
			continue
		}
		attempt.MatchesBaseline = nosqliMatchesBaseline(p.base, resp)
		attempt.DivergesBaseline = nosqliDivergesFromBaseline(p.base, resp)
		if shapeControl != nil {
			attempt.DivergesFromShape = nosqliDivergesFromBaseline(shapeControl, resp)
			attempt.DivergesFromShape = attempt.DivergesFromShape || nosqliRicherThan(resp, shapeControl)
		}
		// An error signature is evidence in its own right; it is not also a
		// differential (an error page is not a reproduced baseline).
		if p.countErrorSignal(resp, &attempt) {
			p.d.Attempts = append(p.d.Attempts, attempt)
			continue
		}
		if attempt.MatchesBaseline || nosqliRicherThan(resp, shapeControl) {
			p.d.DifferentialSignals++
			if p.poc == nil {
				p.capturePoC(resp, probe)
			}
		}
		p.d.Attempts = append(p.d.Attempts, attempt)
	}
}

// countErrorSignal records a new recognized signature for one probe and
// reports whether one was found.
func (p *nosqliProber) countErrorSignal(resp *httpengine.Response, attempt *nosqliAttempt) bool {
	suppressed := map[string]bool{}
	for label := range p.baseErrors {
		suppressed[label] = true
	}
	for label := range p.controlErrs {
		suppressed[label] = true
	}
	sig, ok := nosqlNewErrorSignature(resp.Body, suppressed)
	if !ok {
		return false
	}
	attempt.ErrorSignature = sig.label
	attempt.Product = sig.product
	p.d.IdentifiedProduct = sig.product
	p.d.ErrorSignals++
	if p.poc == nil {
		p.capturePoC(resp, nosqliProbe{Key: attempt.Key, Value: attempt.Payload})
	}
	return true
}

// capturePoC records the exact request that produced the first signal.
func (p *nosqliProber) capturePoC(resp *httpengine.Response, probe nosqliProbe) {
	poc := &nosqliPoC{Method: "GET", Payload: probe.Value, Key: probe.Key}
	if resp != nil && resp.Request != nil {
		if resp.Request.Method != "" {
			poc.Method = resp.Request.Method
		}
		poc.URL = resp.Request.URL
	}
	if poc.URL == "" {
		poc.URL = p.ep.URL
	}
	p.poc = poc
	p.d.PoC = poc
}

func (e *nosqliExecutor) persistNoSQLiCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d nosqliDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnNoSQLi,
		Status: status, Outcome: outcome, Method: string(ep.Method), URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("nosqli: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *nosqliExecutor) finishNoSQLiUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnNoSQLi, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "nosqli skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped nosqli case: %w", err)
	}
	return nil
}

func (e *nosqliExecutor) finishNoSQLiError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "redirect target is outside the scan scope")
	}
	if isTLSRedirectMismatch(reqErr) {
		return e.finishNoSQLiUnavailable(ctx, job, started, ep, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnNoSQLi, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "nosqli baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("nosqli baseline failed: %s", msg)
}

func nosqliFindingSummary(d nosqliDetail) string {
	switch d.ConfirmMethod {
	case "error_differential":
		return "A new document-database error signature and an independent operator differential both confirm NoSQL query-operator injection."
	case "differential":
		return "Two read-only selection operators reproduced the baseline response while a benign plain control and an array control behaved as a no-match; NoSQL query-operator injection is confirmed."
	default:
		return "Two independent bracket/operator shapes produced a document-database error signature neither the baseline nor a benign control value contained."
	}
}

func (e *nosqliExecutor) correlateNoSQLi(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d nosqliDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnNoSQLi, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "NoSQL injection in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    nosqliFindingSummary(d),
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: nosqliEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("nosqli: persist finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueNoSQLiProbes queues one bounded job per eligible GET query-parameter
// injection point. The enqueue is deliberately stricter than the other
// payload engines: non-GET and write-like endpoints are never queued, even
// when the scan allows state-changing requests.
func (c *Controller) enqueueNoSQLiProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableNoSQLi {
		return
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	queued := 0
	for _, ip := range ips {
		if ip == nil || !nosqliEligibleLocation(ip.Location) {
			continue
		}
		ep, err := c.store.Endpoints().Get(ctx, ip.EndpointID)
		if err != nil || ep == nil {
			continue
		}
		params, err := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if err != nil {
			continue
		}
		if !nosqliSafeEndpoint(ep, params) {
			continue
		}
		if sc.Config.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
			continue
		}
		var focus *domain.Parameter
		for _, p := range params {
			if p.ID == ip.ParameterID {
				focus = p
				break
			}
		}
		if focus == nil || isDynamicTokenName(focus.Name) {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"endpoint_id": string(ep.ID), "parameter_id": string(focus.ID)})
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobNoSQLi,
			State: domain.JobQueued, Priority: nosqliPriority, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("nosqli: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("nosql probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

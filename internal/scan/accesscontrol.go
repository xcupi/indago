package scan

// Access-control engine (function/role-level authorization).
//
// ONE executor serves the four cases this capability covers. Every case asks
// the same underlying question — can the caller reach a privileged surface, and
// does that surface expose a privileged ACTION? — but each supplies the
// evidence differently:
//
//	case 19  panel        an administrative path discovery disclosed (robots.txt
//	                      / sitemap) answered ANONYMOUSLY with admin actions.
//	case 19  page         a page's own scripts disclosed an "unpredictable"
//	                      administrative path; the same anonymous panel probe
//	                      runs against the disclosed path.
//	case 20  role_flag    a client-controlled flag (query parameter or cookie)
//	                      decides authorization: the SAME privileged endpoint is
//	                      fetched with the flag absent and then with an
//	                      admin-like value.
//	case 21  role_field   a profile update accepts a role field the client
//	                      should not control; a privileged surface denied
//	                      BEFORE the write must be reachable AFTER it.
//
// Case 22 (IDOR over sequential numeric ids) is object-level authorization,
// not function-level: it stays in the existing IDOR engine
// (internal/scan/idor.go), whose decision layer gained the shared
// object-attribution rule (internal/idor/attribution.go). It is not duplicated
// here.
//
// The verdicts are pure decisions from the pure package internal/accesscontrol;
// this file only fetches, stores evidence and correlates. Nothing here is
// decided by an LLM.
//
// Boundaries that apply to every mode:
//   - every request goes through the scan's SAME scope-enforcing engine,
//     limiter, proxy and session policy;
//   - a 2xx status alone is never a finding: an actionable administrative
//     capability must be observed;
//   - only GET is sent for cases 19 and 20; case 21's single profile write
//     requires BOTH this engine's opt-in AND the server's AllowStateChanging;
//   - no admin action is ever invoked, no other principal's profile is touched,
//     and no path is guessed from a wordlist.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/accesscontrol"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	// accessControlEngine is the engine name recorded in provenance, detail
	// records and finding correlation.
	accessControlEngine = "access_control"

	// maxAccessControlProbesPerScan bounds the anonymous panel probe pass.
	// Each candidate costs at most two GETs (anonymous + non-admin), so the
	// pass is capped regardless of how many paths discovery disclosed.
	maxAccessControlProbesPerScan = 20

	// maxAccessControlPagesPerScan bounds how many discovered pages one scan
	// analyses for script-disclosed administrative paths (case 19's
	// "unpredictable" source).
	maxAccessControlPagesPerScan = 12

	// maxAccessControlRefsPerPage bounds how many disclosed paths one page may
	// contribute to the probe pass.
	maxAccessControlRefsPerPage = 5

	// maxAccessControlScriptBytes bounds one external script body. A larger
	// body is skipped whole, never truncated.
	maxAccessControlScriptBytes = 256 << 10

	// maxAccessControlFlagProbesPerScan is the hard budget shared by every
	// role-flag differential request (baseline included).
	maxAccessControlFlagProbesPerScan = 40

	// maxRoleFlagOrigins bounds how many distinct origins the flag
	// differential probes: it tests an authorization boundary, it is not a
	// host scanner.
	maxRoleFlagOrigins = 4

	// maxPrivilegedTargetsPerOrigin bounds how many discovered privileged
	// endpoints one origin contributes (the conventional fallback paths are
	// used only when discovery found none).
	maxPrivilegedTargetsPerOrigin = 2
)

// Access-control job modes. The mode travels in the job's opaque Payload so the
// domain keeps ONE job type for the capability; a payload-less job (every job
// enqueued before this consolidation, including persisted ones) means "panel".
const (
	accessModePanel     = "panel"      // probe one disclosed administrative path
	accessModePage      = "page"       // analyse one page's scripts, probe what it discloses
	accessModeRoleFlag  = "role_flag"  // client-controlled flag differential (case 20)
	accessModeRoleField = "role_field" // profile role-field write (case 21)
)

// accessControlPayload is the handler-specific job payload.
type accessControlPayload struct {
	Mode string `json:"mode,omitempty"`
}

func accessControlMode(job *domain.TestJob) string {
	if job == nil || len(job.Payload) == 0 {
		return accessModePanel
	}
	var p accessControlPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil || p.Mode == "" {
		return accessModePanel
	}
	return p.Mode
}

// accessControlDetail is the TestCase/Finding detail record. It is one record
// for the whole capability: the panel fields are populated by the two case-19
// modes, the differential fields by cases 20 and 21, and Attempts holds one
// entry per probe in every mode.
type accessControlDetail struct {
	Engine          string                 `json:"engine"`
	Kind            string                 `json:"kind,omitempty"`
	Method          domain.HTTPMethod      `json:"method,omitempty"`
	URL             string                 `json:"url"`
	EndpointID      domain.ID              `json:"endpoint_id,omitempty"`
	DiscoverySource domain.DiscoverySource `json:"discovery_source,omitempty"`

	// Case 19 — anonymous panel probe.
	AnonymousStatus   int                    `json:"anonymous_status,omitempty"`
	AnonymousFinalURL string                 `json:"anonymous_final_url,omitempty"`
	AnonymousLogin    bool                   `json:"anonymous_login,omitempty"`
	Actions           []accesscontrol.Action `json:"actions,omitempty"`
	Compared          bool                   `json:"compared,omitempty"`
	NonAdminStatus    int                    `json:"non_admin_status,omitempty"`
	NonAdminLogin     bool                   `json:"non_admin_login,omitempty"`
	NonAdminActions   []accesscontrol.Action `json:"non_admin_actions,omitempty"`
	AnonymousEvidence []domain.ID            `json:"anonymous_evidence,omitempty"`
	NonAdminEvidence  []domain.ID            `json:"non_admin_evidence,omitempty"`

	// Case 19 — the page that DISCLOSED the probed path.
	PageURL         string               `json:"page_url,omitempty"`
	PageStatus      int                  `json:"page_status,omitempty"`
	InlineScripts   int                  `json:"inline_scripts,omitempty"`
	ExternalScripts int                  `json:"external_scripts,omitempty"`
	SkippedScripts  []accesscontrol.Skip `json:"skipped_scripts,omitempty"`
	Refs            []accesscontrol.Ref  `json:"refs,omitempty"`
	PageEvidence    []domain.ID          `json:"page_evidence,omitempty"`

	// Cases 20 and 21 — the differential.
	PrivilegedURL   string                 `json:"privileged_url,omitempty"`
	FlagName        string                 `json:"flag_name,omitempty"`
	FlagLocation    accesscontrol.Location `json:"flag_location,omitempty"`
	FlagValue       string                 `json:"flag_value,omitempty"`
	FlagSource      string                 `json:"flag_source,omitempty"`
	RoleField       string                 `json:"role_field,omitempty"`
	RoleFieldFrom   string                 `json:"role_field_source,omitempty"`
	RoleValueBefore string                 `json:"role_value_before,omitempty"`
	RoleValueAfter  string                 `json:"role_value_after,omitempty"`
	ProfileChange   string                 `json:"profile_change,omitempty"`
	BeforeStatus    int                    `json:"before_status,omitempty"`
	AfterStatus     int                    `json:"after_status,omitempty"`
	BeforeReach     accesscontrol.Reach    `json:"before_reach,omitempty"`
	AfterReach      accesscontrol.Reach    `json:"after_reach,omitempty"`
	Capabilities    []accesscontrol.Action `json:"capabilities,omitempty"`
	SurfacesTested  []string               `json:"surfaces_tested,omitempty"`

	Attempts        []accessControlAttempt `json:"attempts,omitempty"`
	Verdict         domain.Verdict         `json:"verdict,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	ProbesBudget    int                    `json:"probes_budget,omitempty"`
	ProbesLeft      int                    `json:"probes_left,omitempty"`
	BudgetExhausted bool                   `json:"probe_budget_exhausted,omitempty"`
	Skipped         bool                   `json:"skipped,omitempty"`
	SkipReason      string                 `json:"skip_reason,omitempty"`
}

// accessControlAttempt is one probe made by any mode.
type accessControlAttempt struct {
	Kind           string                 `json:"kind"`
	URL            string                 `json:"url,omitempty"`
	DisclosedBy    string                 `json:"disclosed_by,omitempty"`
	FlagName       string                 `json:"flag_name,omitempty"`
	FlagLocation   accesscontrol.Location `json:"flag_location,omitempty"`
	FlagValue      string                 `json:"flag_value,omitempty"`
	FlagSource     string                 `json:"flag_source,omitempty"`
	Field          string                 `json:"field,omitempty"`
	FieldValue     string                 `json:"field_value,omitempty"`
	FieldKind      string                 `json:"field_kind,omitempty"`
	ProfileChange  string                 `json:"profile_change,omitempty"`
	Status         int                    `json:"status,omitempty"`
	BaselineStatus int                    `json:"baseline_status,omitempty"`
	BeforeReach    accesscontrol.Reach    `json:"before_reach,omitempty"`
	AfterReach     accesscontrol.Reach    `json:"after_reach,omitempty"`
	Capabilities   []accesscontrol.Action `json:"capabilities,omitempty"`
	Outcome        string                 `json:"outcome"`
	Reason         string                 `json:"reason,omitempty"`
	EvidenceIDs    []domain.ID            `json:"evidence_ids,omitempty"`
}

// accessControlFindingDetail is the correlated Finding's detail record. It
// carries the same evidence trail plus the dedup key and occurrence count the
// correlation layer needs. Panel findings keep the flat case-19 fields they
// always had; the differential cases populate their own fields.
type accessControlFindingDetail struct {
	Engine          string                 `json:"engine"`
	Kind            string                 `json:"kind,omitempty"`
	Method          domain.HTTPMethod      `json:"method,omitempty"`
	URL             string                 `json:"url"`
	DiscoverySource domain.DiscoverySource `json:"discovery_source,omitempty"`

	AnonymousStatus   int                    `json:"anonymous_status,omitempty"`
	AnonymousFinalURL string                 `json:"anonymous_final_url,omitempty"`
	Actions           []accesscontrol.Action `json:"actions,omitempty"`
	Compared          bool                   `json:"compared,omitempty"`
	NonAdminStatus    int                    `json:"non_admin_status,omitempty"`
	NonAdminActions   []accesscontrol.Action `json:"non_admin_actions,omitempty"`
	AnonymousEvidence []domain.ID            `json:"anonymous_evidence,omitempty"`
	NonAdminEvidence  []domain.ID            `json:"non_admin_evidence,omitempty"`

	PageURL         string                 `json:"page_url,omitempty"`
	Refs            []accesscontrol.Ref    `json:"refs,omitempty"`
	PrivilegedURL   string                 `json:"privileged_url,omitempty"`
	FlagName        string                 `json:"flag_name,omitempty"`
	FlagLocation    accesscontrol.Location `json:"flag_location,omitempty"`
	FlagValue       string                 `json:"flag_value,omitempty"`
	FlagSource      string                 `json:"flag_source,omitempty"`
	RoleField       string                 `json:"role_field,omitempty"`
	RoleValueBefore string                 `json:"role_value_before,omitempty"`
	RoleValueAfter  string                 `json:"role_value_after,omitempty"`
	BeforeStatus    int                    `json:"before_status,omitempty"`
	AfterStatus     int                    `json:"after_status,omitempty"`
	BeforeReach     accesscontrol.Reach    `json:"before_reach,omitempty"`
	AfterReach      accesscontrol.Reach    `json:"after_reach,omitempty"`
	Capabilities    []accesscontrol.Action `json:"capabilities,omitempty"`

	Attempts    []accessControlAttempt `json:"attempts,omitempty"`
	Verdict     domain.Verdict         `json:"verdict,omitempty"`
	Reason      string                 `json:"reason,omitempty"`
	DedupKey    string                 `json:"dedup_key,omitempty"`
	Occurrences int                    `json:"occurrences,omitempty"`
	TestCaseIDs []domain.ID            `json:"test_case_ids,omitempty"`
}

// accessControlBudget is the scan-wide, concurrency-safe probe budget. Several
// access-control jobs run at once on the HTTP worker group, so the counters and
// the "already probed" set must be shared: one disclosed path is fetched once,
// and the whole pass stays inside its stated bound.
type accessControlBudget struct {
	mu          sync.Mutex
	panelLeft   int
	flagLeft    int
	writeLeft   int
	panelProbed map[string]bool
}

func newAccessControlBudget() *accessControlBudget {
	return &accessControlBudget{
		panelLeft:   maxAccessControlProbesPerScan,
		flagLeft:    maxAccessControlFlagProbesPerScan,
		writeLeft:   accesscontrol.MaxWritesPerScan,
		panelProbed: map[string]bool{},
	}
}

// reservePanel reserves one anonymous panel probe for a directly discovered
// endpoint. A repeat run at the same path is still probed: correlation, not
// suppression, is what keeps the finding single. The reservation marks the path
// so a page-disclosure job does not fetch it again.
func (b *accessControlBudget) reservePanel(probeURL string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.panelLeft <= 0 {
		return false
	}
	b.panelProbed[probeURL] = true
	b.panelLeft--
	return true
}

// reserveDisclosed reserves one anonymous probe for a path a page disclosed.
// A path already probed by any other job in this scan is skipped: one request
// per disclosed path is the bound.
func (b *accessControlBudget) reserveDisclosed(probeURL string) (ok, duplicate bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.panelProbed[probeURL] {
		return false, true
	}
	if b.panelLeft <= 0 {
		return false, false
	}
	b.panelProbed[probeURL] = true
	b.panelLeft--
	return true, false
}

func (b *accessControlBudget) panelRemaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.panelLeft
}

func (b *accessControlBudget) takeFlag() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.flagLeft <= 0 {
		return false
	}
	b.flagLeft--
	return true
}

func (b *accessControlBudget) flagRemaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flagLeft
}

func (b *accessControlBudget) takeWrite() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeLeft <= 0 {
		return false
	}
	b.writeLeft--
	return true
}

func (b *accessControlBudget) writeRemaining() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writeLeft
}

// accessControlExecutor runs JobAccessControl jobs in every mode.
type accessControlExecutor struct {
	store    store.Store
	engine   httpengine.Engine
	evidence evidence.Store
	cfg      ExecutorConfig
	log      *slog.Logger
	// findingsMu serializes Finding correlation with every other engine's
	// correlation in this scan.
	findingsMu *sync.Mutex
	// hasSession says the scan carries authenticated storage state, so the
	// non-admin comparison request is meaningful. Without it the anonymous
	// exposure alone is still a finding (nobody had to authenticate).
	hasSession bool
	// budget is the scan-wide probe/write budget shared by every mode.
	budget *accessControlBudget
}

func newAccessControlExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex, hasSession bool) *accessControlExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &accessControlExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(),
		log: log, findingsMu: findingsMu, hasSession: hasSession, budget: newAccessControlBudget()}
}

var _ worker.Handler = (*accessControlExecutor)(nil)

// Handle implements worker.Handler with the same return-value contract as the
// other executors: skipped/completed → nil; cancellation → context error;
// transport errors → retryable; permanent resolution errors → ErrPermanent.
func (e *accessControlExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	// Cookie values are credentials. One job-local redactor collects the
	// values this job's own requests/responses carry, so every piece of
	// evidence and detail it persists can be sanitised without inventing a
	// secret. It lives only inside this call.
	ctx, _ = withCookieRedaction(ctx)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnAccessControl, Status: domain.TestCaseRunning, URL: job.Target.URL,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist test case: %w", err)
	}

	d, outcome, err, permanent, skipped := e.run(ctx, job, tc)

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	e.finish(wctx, tc, d, outcome, err, skipped)

	switch {
	case skipped, outcome == domain.OutcomeSuccess:
		return nil
	case outcome == domain.OutcomeCancelled:
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return context.Canceled
	case permanent:
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	default:
		return err
	}
}

// run dispatches one job to its per-case entry point. Cases 19 and 20/21 share
// the executor, the evidence store, the budget and the correlation layer; they
// do not share the request shape, which is exactly why they are separate
// functions rather than one function with four branches inside the loop.
func (e *accessControlExecutor) run(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	switch accessControlMode(job) {
	case accessModePage:
		return e.runPageDisclosure(ctx, job, tc)
	case accessModeRoleFlag:
		return e.runRoleFlag(ctx, job, tc)
	case accessModeRoleField:
		return e.runRoleField(ctx, job, tc)
	default:
		return e.runPanel(ctx, job, tc)
	}
}

// ---------------------------------------------------------------------------
// case 19: anonymous access to a disclosed administrative panel
// ---------------------------------------------------------------------------

// runPanel probes ONE administrative path that discovery already disclosed.
func (e *accessControlExecutor) runPanel(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	ep, _, _, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return accessControlDetail{Engine: accessControlEngine, Kind: accessModePanel}, domain.OutcomeError, err, true, false
	}
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModePanel,
		Method: ep.Method, URL: ep.URL, EndpointID: ep.ID, DiscoverySource: ep.Source}
	tc.Method, tc.URL = string(ep.Method), ep.URL

	skip := func(reason string) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason = true, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}
	// A path outside the candidate set is never requested: the pass only
	// enqueues robots/sitemap-derived admin-like GET paths, and a job for
	// anything else would be a request nobody authorized.
	if !isAccessControlCandidate(ep) {
		return skip("not a robots/sitemap-discovered admin-like GET path")
	}
	if !e.budget.reservePanel(ep.URL) {
		d.BudgetExhausted = true
		return skip("the scan-wide anonymous-probe budget was exhausted")
	}

	p, outcome, reqErr := e.probePanel(ctx, tc, ep.URL, nil)
	if outcome != domain.OutcomeSuccess {
		return d, outcome, reqErr, false, false
	}
	d.AnonymousStatus, d.AnonymousFinalURL = p.status, p.finalURL
	d.AnonymousLogin, d.Actions = p.loginPage, p.actions
	d.Compared, d.NonAdminStatus = p.compared, p.nonAdminStatus
	d.NonAdminLogin, d.NonAdminActions = p.nonAdminLogin, p.nonAdminActions
	d.AnonymousEvidence, d.NonAdminEvidence = p.anonymousEvidence, p.nonAdminEvidence
	d.Verdict, d.Reason = verdictOf(p.decision.Outcome), p.decision.Reason
	d.Actions = p.decision.Privileged
	d.Attempts = append(d.Attempts, accessControlAttempt{
		Kind: accessModePanel, URL: ep.URL, DisclosedBy: string(ep.Source),
		Status: p.status, Capabilities: p.decision.Privileged,
		Outcome: string(p.decision.Outcome), Reason: p.decision.Reason,
		EvidenceIDs: appendUniqueIDs(p.anonymousEvidence, p.nonAdminEvidence),
	})
	d.ProbesBudget = maxAccessControlProbesPerScan
	d.ProbesLeft = e.budget.panelRemaining()

	if d.Verdict == domain.VerdictConfirmed {
		e.correlate(ctx, job.ScanID, accessControlFinding{
			Key:             accessControlFindingDedupKey(ep),
			Title:           fmt.Sprintf("Access control: anonymous access to admin actions at %s %s", ep.Method, endpointLabel(ep.URL)),
			Summary:         d.Reason,
			Severity:        accessControlSeverity(d.Actions),
			EndpointID:      ep.ID,
			DiscoverySource: ep.Source,
			Detail:          findingDetailFrom(d, p.anonymousEvidence, p.nonAdminEvidence),
			Evidence:        appendUniqueIDs(p.anonymousEvidence, p.nonAdminEvidence),
		}, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// runPageDisclosure analyses ONE discovered page for administrative paths its
// own scripts disclose, then runs the SAME anonymous panel probe against each
// disclosed path. This is case 19's "unpredictable URL" source: the path is
// never guessed, it is read out of the target's own bytes.
func (e *accessControlExecutor) runPageDisclosure(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
	pageURL := strings.TrimSpace(job.Target.URL)
	d := accessControlDetail{Engine: accessControlEngine, Kind: accessModePage, URL: pageURL,
		PageURL: pageURL, EndpointID: job.Target.EndpointID}
	tc.URL = pageURL

	skip := func(reason string) (accessControlDetail, domain.TestOutcome, error, bool, bool) {
		d.Skipped, d.SkipReason = true, reason
		return d, domain.OutcomeSuccess, nil, false, true
	}
	page, err := url.Parse(pageURL)
	if err != nil || page.Host == "" || (page.Scheme != "http" && page.Scheme != "https") {
		return d, domain.OutcomeError, fmt.Errorf("access-control page job has no usable URL: %q", pageURL), true, false
	}
	if !accesscontrol.PageAnalyzable(pageURL) {
		return skip("not an HTML page whose scripts could disclose a path")
	}

	// The page response is where the anonymous session cookie and the path it
	// unlocks are disclosed together, so its Set-Cookie is job-local state:
	// it is handed to the immediately related panel probe as a value
	// (continuityCookies) and nowhere else. The fetch therefore must not read
	// or write the HTTP client's jar — that jar is shared by every scoped
	// engine in the process, so a stored cookie here would be visible to
	// unrelated requests and to other scans. NoJar hides the jar in both
	// directions while still attaching the scan's explicit saved session
	// cookies, so an authenticated page stays fetchable.
	pageReq := httpengine.GET(pageURL)
	pageReq.NoJar = true
	resp, outcome, reqErr := e.do(ctx, pageReq)
	if outcome != domain.OutcomeSuccess {
		return d, outcome, reqErr, false, false
	}
	d.PageStatus = resp.Status
	if resp.Status < 200 || resp.Status >= 300 {
		return skip(fmt.Sprintf("the page was not available (HTTP %d)", resp.Status))
	}
	// The page is evidence of the DISCLOSURE; each probe below adds evidence
	// of REACHABILITY. Without the first, a finding could not be told apart
	// from a lucky guess.
	if ids, evErr := e.persistPair(ctx, tc, resp, "access control disclosure page"); evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | page evidence incomplete: " + truncate(evErr.Error(), 200))
	} else {
		d.PageEvidence = ids
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	}

	scripts := accesscontrol.ExtractScripts(pageURL, resp.Body)
	d.InlineScripts, d.ExternalScripts = len(scripts.Inline), len(scripts.External)
	d.SkippedScripts = append(d.SkippedScripts, scripts.Skipped...)

	var refs []accesscontrol.Ref
	for _, inline := range scripts.Inline {
		refs = append(refs, accesscontrol.RefsFromScript(inline, "inline script")...)
	}
	for _, scriptURL := range scripts.External {
		body, ok := e.fetchDisclosingScript(ctx, tc, scriptURL, &d)
		if !ok {
			continue
		}
		found := accesscontrol.RefsFromScript(string(body), scriptURL)
		if len(found) == 0 {
			continue
		}
		// Persist the script that actually disclosed something: it is the
		// literal the finding's provenance names.
		if e.evidence != nil {
			if _, evErr := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceOther,
				".js", "text/javascript", cookieRedactorFrom(ctx).redactBytes(body),
				cookieRedactorFrom(ctx).redact("access-control disclosing script "+scriptURL)); evErr != nil {
				tc.Note = strings.TrimSpace(tc.Note + " | script evidence incomplete: " + truncate(evErr.Error(), 200))
			}
		}
		refs = append(refs, found...)
	}
	refs = dedupeAccessRefs(refs, maxAccessControlRefsPerPage)
	d.Refs = refs
	if len(refs) == 0 {
		return skip("no administrative path is referenced by this page's own scripts")
	}

	d.ProbesBudget = maxAccessControlProbesPerScan
	verdict := domain.VerdictInconclusive
	sawRejected := false
	var reasons []string
	var confirmation *accessControlAttempt
	for _, ref := range refs {
		probeURL := page.Scheme + "://" + page.Host + ref.Path
		okProbe, dup := e.budget.reserveDisclosed(probeURL)
		if !okProbe {
			if dup {
				d.Attempts = append(d.Attempts, accessControlAttempt{
					Kind: accessModePage, URL: probeURL, DisclosedBy: ref.Describe(),
					Outcome: "skipped", Reason: "this path was already probed by this scan"})
				continue
			}
			d.BudgetExhausted = true
			reasons = append(reasons, "the scan-wide anonymous-probe budget was exhausted before every disclosed path was tested")
			break
		}

		// The disclosed path may only be reachable with the anonymous cookie
		// THIS page response minted (an "unpredictable" path bound to the
		// session that disclosed it). Carry exactly that cookie set — nothing
		// ambient — into the probe; it is derived per probe URL, so a path that
		// resolves off this origin can never receive it.
		carry := continuityCookies(resp.FinalURL, resp.Headers, probeURL)
		p, outcome, reqErr := e.probePanel(ctx, tc, probeURL, carry)
		if outcome != domain.OutcomeSuccess {
			if outcome == domain.OutcomeCancelled && ctx.Err() != nil {
				return d, outcome, reqErr, false, false
			}
			d.Attempts = append(d.Attempts, accessControlAttempt{
				Kind: accessModePage, URL: probeURL, DisclosedBy: ref.Describe(),
				Outcome: string(domain.OutcomeError), Reason: "request failed: " + truncate(errText(reqErr), 200)})
			continue
		}
		reason := p.decision.Reason + "; path " + ref.Describe()
		a := accessControlAttempt{
			Kind: accessModePage, URL: probeURL, DisclosedBy: ref.Describe(),
			Status: p.status, Capabilities: p.decision.Privileged,
			Outcome: string(p.decision.Outcome), Reason: reason,
			EvidenceIDs: appendUniqueIDs(p.anonymousEvidence, p.nonAdminEvidence),
		}
		d.Attempts = append(d.Attempts, a)
		reasons = append(reasons, reason)
		switch p.decision.Outcome {
		case accesscontrol.OutcomeConfirmed:
			verdict = domain.VerdictConfirmed
			d.AnonymousStatus, d.AnonymousFinalURL = p.status, p.finalURL
			d.Actions = p.decision.Privileged
			d.Reason = reason
			confirmation = &a
		case accesscontrol.OutcomeRejected:
			sawRejected = true
		}
		if verdict == domain.VerdictConfirmed {
			break // one anonymously reachable admin page is the finding; stop
		}
	}
	if verdict != domain.VerdictConfirmed {
		if sawRejected && !attemptsInconclusive(d.Attempts) {
			verdict = domain.VerdictRejected
		}
		if d.Reason == "" {
			d.Reason = joinReasons(reasons)
			if d.Reason == "" {
				d.Reason = "no disclosed administrative path could be probed"
			}
		}
	}
	d.Verdict = verdict
	d.ProbesLeft = e.budget.panelRemaining()
	if verdict == domain.VerdictConfirmed && confirmation != nil {
		disclosedURL := confirmation.URL
		e.correlate(ctx, job.ScanID, accessControlFinding{
			Key:      accessControlPathDedupKey(disclosedURL),
			Title:    fmt.Sprintf("Access control: anonymous access to admin actions at GET %s", endpointLabel(disclosedURL)),
			Summary:  d.Reason,
			Severity: accessControlSeverity(d.Actions),
			// The disclosed path was never a discovered endpoint of its own;
			// the page that disclosed it is the endpoint we can attribute.
			EndpointID:      job.Target.EndpointID,
			DiscoverySource: domain.SourceCrawler,
			Detail:          findingDetailFrom(d, nil, nil),
			Evidence:        appendUniqueIDs(d.PageEvidence, confirmation.EvidenceIDs),
		}, tc.ID)
	}
	return d, domain.OutcomeSuccess, nil, false, false
}

// panelProbe is the result of one anonymous panel request plus its optional
// non-admin comparison. Both case-19 sources produce exactly this, so the
// probe (and its evidence discipline) exists once.
type panelProbe struct {
	status            int
	finalURL          string
	loginPage         bool
	actions           []accesscontrol.Action
	decision          accesscontrol.Decision
	anonymousEvidence []domain.ID
	nonAdminEvidence  []domain.ID
	compared          bool
	nonAdminStatus    int
	nonAdminLogin     bool
	nonAdminActions   []accesscontrol.Action
}

// probePanel sends the anonymous request (and, when a session exists, the same
// request as the authenticated non-admin), stores both pairs as evidence and
// applies the pure decision. A Confirmed decision whose evidence could not be
// stored is downgraded: never ship a finding that is not reproducible from the
// bytes the scan kept.
//
// carry, when non-empty, is the ephemeral cookie set an immediately preceding
// disclosure response issued for this exact origin and path (see
// continuityCookies). It makes the anonymous request "jarless": the browser's
// own behaviour after receiving that response, with no stored jar, no other
// scan's state and — critically — no part of the scan's authenticated session.
func (e *accessControlExecutor) probePanel(ctx context.Context, tc *domain.TestCase, rawURL string, carry []*http.Cookie) (*panelProbe, domain.TestOutcome, error) {
	// Request 1: genuinely anonymous. NoCookies suppresses both the scan's
	// saved session cookies and the HTTP client's jar, which may hold cookies
	// set by an earlier response. When carry is set, the ONLY cookie state the
	// request may see is the one the disclosure response just issued.
	anonReq := httpengine.GET(rawURL)
	if len(carry) > 0 {
		anonReq.Jarless = true
		anonReq.Cookies = carry
	} else {
		anonReq.NoCookies = true
	}
	anonResp, outcome, reqErr := e.do(ctx, anonReq)
	if outcome != domain.OutcomeSuccess {
		return nil, outcome, reqErr
	}

	p := &panelProbe{status: anonResp.Status, finalURL: anonResp.FinalURL}
	if ids, evErr := e.persistPair(ctx, tc, anonResp, "access control anonymous"); evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | anonymous evidence incomplete: " + truncate(evErr.Error(), 200))
	} else {
		p.anonymousEvidence = ids
		tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	}
	anonSnap := acSnapshot(anonResp)
	anonObs := accesscontrol.Analyze(anonSnap)
	p.loginPage, p.actions = anonObs.LoginPage, anonObs.Actions

	// Request 2: the same path as the scan's authenticated (non-admin)
	// session. It is only useful when the anonymous response itself could be
	// a finding; a rejected anonymous response needs no comparison.
	//
	// The comparison carries the scan's EXPLICIT saved session (scopedEngine
	// attaches it) and nothing else: NoJar hides the process-wide jar in both
	// directions, so an ambient cookie some earlier request or other scan
	// stored can neither authenticate this comparison nor let the comparison's
	// own Set-Cookie escape into that jar.
	var nonAdmin *accesscontrol.Snapshot
	if e.hasSession && anonResp.Status >= 200 && anonResp.Status < 300 && len(anonObs.Actions) > 0 {
		compareReq := httpengine.GET(rawURL)
		compareReq.NoJar = true
		authResp, authOutcome, _, _ := e.send(ctx, compareReq)
		if authOutcome == domain.OutcomeSuccess && authResp != nil {
			p.compared, p.nonAdminStatus = true, authResp.Status
			if ids, evErr := e.persistPair(ctx, tc, authResp, "access control non-admin session"); evErr != nil {
				tc.Note = strings.TrimSpace(tc.Note + " | non-admin evidence incomplete: " + truncate(evErr.Error(), 200))
			} else {
				p.nonAdminEvidence = ids
				tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
			}
			snap := acSnapshot(authResp)
			authObs := accesscontrol.Analyze(snap)
			p.nonAdminLogin, p.nonAdminActions = authObs.LoginPage, authObs.Actions
			nonAdmin = &snap
		}
	}

	dec := accesscontrol.Decide(anonSnap, nonAdmin)
	p.decision = dec
	// Evidence integrity: a Confirmed finding must be reproducible from the
	// stored anonymous request/response pair (and the comparison pair when a
	// comparison was performed).
	if dec.Outcome == accesscontrol.OutcomeConfirmed && e.evidence != nil {
		if len(p.anonymousEvidence) < 2 || (p.compared && len(p.nonAdminEvidence) < 2) {
			p.decision.Outcome = accesscontrol.OutcomeInconclusive
			p.decision.Reason = "the anonymous response exposed a privileged action, but the request/response evidence could not all be stored; not Confirmed without reproducible evidence"
		}
	}
	return p, domain.OutcomeSuccess, nil
}

// fetchDisclosingScript reads one same-origin external script. Every refusal is
// recorded in the detail: "not read" is never reported as "contains no path".
func (e *accessControlExecutor) fetchDisclosingScript(ctx context.Context, tc *domain.TestCase, scriptURL string, d *accessControlDetail) ([]byte, bool) {
	// Same isolation as the disclosure page fetch: a script response's
	// Set-Cookie is not continuity evidence and has no reason to enter the
	// shared jar, where unrelated requests (and other scans) would see it.
	scriptReq := httpengine.GET(scriptURL)
	scriptReq.NoJar = true
	resp, outcome, err, _ := e.send(ctx, scriptReq)
	if outcome != domain.OutcomeSuccess {
		d.SkippedScripts = append(d.SkippedScripts, accesscontrol.Skip{URL: scriptURL, Reason: "fetch failed: " + truncate(errText(err), 120)})
		return nil, false
	}
	if resp.Status < 200 || resp.Status >= 300 {
		d.SkippedScripts = append(d.SkippedScripts, accesscontrol.Skip{URL: scriptURL, Reason: fmt.Sprintf("fetch returned HTTP %d", resp.Status)})
		return nil, false
	}
	// The script response is not persisted as a request/response pair, but its
	// own Set-Cookie values are still credentials: record them so the body blob
	// below is sanitised if the script echoes them.
	cookieRedactorFrom(ctx).observe(resp)
	if resp.Truncated || len(resp.Body) > maxAccessControlScriptBytes {
		d.SkippedScripts = append(d.SkippedScripts, accesscontrol.Skip{URL: scriptURL, Reason: "exceeds the per-file size cap"})
		return nil, false
	}
	return resp.Body, true
}

func dedupeAccessRefs(refs []accesscontrol.Ref, limit int) []accesscontrol.Ref {
	seen := make(map[string]bool, len(refs))
	out := make([]accesscontrol.Ref, 0, len(refs))
	for _, ref := range refs {
		if seen[ref.Path] {
			continue
		}
		seen[ref.Path] = true
		out = append(out, ref)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func attemptsInconclusive(attempts []accessControlAttempt) bool {
	for _, a := range attempts {
		if a.Outcome == string(accesscontrol.OutcomeInconclusive) || a.Outcome == string(domain.OutcomeError) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// persistence, evidence and correlation (shared by every mode)
// ---------------------------------------------------------------------------

// finish persists the probe result. Skipped probes still write a row so the
// report can say the candidate existed and why it was not tested.
func (e *accessControlExecutor) finish(ctx context.Context, tc *domain.TestCase, d accessControlDetail, outcome domain.TestOutcome, runErr error, skipped bool) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.VulnClass = domain.VulnAccessControl
	if d.Engine == "" {
		d.Engine = accessControlEngine
	}
	// The detail is derived from response bytes (an action's target, a
	// disclosed path), so a target that echoes a cookie value into its HTML can
	// push that value here. Detail is persisted through this one function;
	// rewriting the serialised record keeps every derived field covered without
	// touching the decision that produced it.
	red := cookieRedactorFrom(ctx)
	tc.Detail = red.redactJSON(encodeAccessControlDetail(d))
	switch {
	case skipped:
		tc.Status = domain.TestCaseSkipped
		tc.Note = red.redact("access control skipped: " + d.SkipReason)
	case outcome == domain.OutcomeSuccess:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = outcome
		if d.Verdict == "" {
			d.Verdict = domain.VerdictInconclusive
			d.Reason = "no access-control decision was produced"
			tc.Detail = red.redactJSON(encodeAccessControlDetail(d))
		}
		tc.Note = fmt.Sprintf("access control: %s (%s)", d.Verdict, truncate(d.Reason, 300))
		tc.Note = red.redact(tc.Note)
	default:
		tc.Outcome = outcome
		tc.Status = domain.TestCaseFailed
		if outcome == domain.OutcomeCancelled {
			tc.Status = domain.TestCaseCancelled
		}
		if runErr != nil {
			tc.Error = red.redact(truncate(runErr.Error(), 1024))
		}
	}
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Error("persist access-control test case", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

func encodeAccessControlDetail(d accessControlDetail) []byte {
	b, _ := json.Marshal(d)
	return b
}

func encodeAccessControlFindingDetail(d accessControlFindingDetail) []byte {
	b, _ := json.Marshal(d)
	return b
}

// send executes one request through the scan's scope-enforcing engine with the
// per-request timeout.
func (e *accessControlExecutor) send(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error, time.Duration) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err, 0
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	t0 := time.Now()
	resp, err := e.engine.Do(ctx, &timed)
	dur := time.Since(t0)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil, resp.Duration
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err(), dur
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err, dur
	default:
		return nil, domain.OutcomeError, err, dur
	}
}

// do is send without the (unused) duration, for callers that only care about
// the response/outcome/error triple.
func (e *accessControlExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	resp, outcome, err, _ := e.send(ctx, req)
	return resp, outcome, err
}

// persistPair stores the request and response of one probe as evidence.
//
// Cookie values are credentials and are ALWAYS redacted here, on both sides:
// every Set-Cookie value, and the value of every cookie in the request's
// replayed Cookie header. The access-control decision never depends on the
// value (a fresh disclosure re-issues its own), so storing it would add
// nothing but a leaked credential to the evidence store, reports or exported
// detail. Cookie NAMES, paths, domains, flags and expiry are kept, so the pair
// still documents exactly what was sent and what scope the response set.
func (e *accessControlExecutor) persistPair(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, role string) ([]domain.ID, error) {
	var ids []domain.ID
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return ids, nil
	}

	// The pair's own cookie values are what this job has just seen; recording
	// them lets every blob this job stores — this one included — rewrite the
	// same values if a target reflects them into a body.
	red := cookieRedactorFrom(ctx)
	red.observe(resp)

	captured := *resp.Request
	captured.Headers = resp.Request.Headers.Clone()
	reqNote := "test_case=" + string(tc.ID) + " " + role + " request"
	if redactRequestCookieValues(captured.Headers) {
		reqNote += " (cookie values redacted)"
	}
	id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
		red.redactBytes(dumpRequest(&captured)), reqNote)
	if err != nil {
		return ids, err
	}
	ids = append(ids, id)
	note := "test_case=" + string(tc.ID) + " " + role + " response"
	if resp.Truncated {
		note += " (body truncated at the engine's size cap)"
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	if redactSetCookieValues(recorded.Headers) {
		note += " (Set-Cookie values redacted)"
	}
	id, err = putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		red.redactBytes(dumpResponse(&recorded)), note)
	if err != nil {
		return ids, err
	}
	ids = append(ids, id)
	return ids, nil
}

// redactRequestCookieValues blanks the value of every cookie in each Cookie
// header line, keeping the names: the pair still shows that (and which) cookies
// were sent, without persisting the credential itself. Reports true when at
// least one cookie value was rewritten.
func redactRequestCookieValues(h http.Header) bool {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return false
	}
	h.Del("Cookie")
	redacted := false
	for _, line := range lines {
		parts := strings.Split(line, ";")
		for i, part := range parts {
			name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || name == "" {
				continue
			}
			parts[i] = " " + name + "=<redacted>"
			redacted = true
		}
		h.Add("Cookie", strings.TrimSpace(strings.Join(parts, ";")))
	}
	return redacted
}

// redactSetCookieValues blanks every Set-Cookie value in place, keeping the
// cookie name and its attributes (Domain, Path, Secure, HttpOnly, SameSite,
// expiry). Reports true when at least one header was rewritten.
func redactSetCookieValues(h http.Header) bool {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return false
	}
	h.Del("Set-Cookie")
	for _, line := range lines {
		name, rest, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(name) == "" {
			h.Add("Set-Cookie", "<redacted>")
			continue
		}
		attrs := ""
		if i := strings.IndexByte(rest, ';'); i >= 0 {
			attrs = rest[i:]
		}
		h.Add("Set-Cookie", strings.TrimSpace(name)+"=<redacted>"+attrs)
	}
	return true
}

// accessControlFinding is one confirmed result handed to correlation.
type accessControlFinding struct {
	Key             string
	Title           string
	Summary         string
	Severity        domain.Severity
	EndpointID      domain.ID
	DiscoverySource domain.DiscoverySource
	Detail          accessControlFindingDetail
	Evidence        []domain.ID
}

// correlate upserts the Confirmed finding. A later run at the same site (a
// resumed execution re-enqueues the pass) absorbs into the same finding and
// unions evidence instead of duplicating it. It only ever moves the Verdict
// toward Confirmed: a weaker later result at a correlated site never downgrades
// it.
func (e *accessControlExecutor) correlate(ctx context.Context, scanID domain.ID, draft accessControlFinding, tcID domain.ID) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	// The finding copies fields that were derived from response bytes (an
	// action target, a reason quoted from the decision). Redact the persisted
	// copy with the same job-local redactor the evidence used, so the finding
	// never becomes a second place a reflected cookie value survives.
	red := cookieRedactorFrom(ctx)
	draft.Title = red.redact(draft.Title)
	draft.Summary = red.redact(draft.Summary)

	draft.Detail.DedupKey = draft.Key
	draft.Detail.Engine = accessControlEngine
	if draft.Detail.TestCaseIDs == nil {
		draft.Detail.TestCaseIDs = []domain.ID{tcID}
	} else {
		draft.Detail.TestCaseIDs = appendUniqueID(draft.Detail.TestCaseIDs, tcID)
	}
	draft.Detail.Occurrences = 1
	draft.Detail.Verdict = domain.VerdictConfirmed
	draft.Detail.Reason = draft.Summary

	existing, err := e.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		e.log.Warn("list findings for access-control correlation", "scan", scanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnAccessControl {
			continue
		}
		var prev accessControlFindingDetail
		_ = json.Unmarshal(f.Detail, &prev)
		if prev.DedupKey != draft.Key {
			continue
		}
		prev.Occurrences++
		prev.TestCaseIDs = appendUniqueID(prev.TestCaseIDs, tcID)
		prev.Verdict = domain.VerdictConfirmed
		prev.Reason = draft.Summary
		prev.Attempts = mergeAccessControlAttempts(prev.Attempts, draft.Detail.Attempts)
		prev.Capabilities = mergeAccessControlActions(prev.Capabilities, draft.Detail.Capabilities)
		prev.Actions = mergeAccessControlActions(prev.Actions, draft.Detail.Actions)
		prev.AnonymousEvidence = appendUniqueIDs(prev.AnonymousEvidence, draft.Detail.AnonymousEvidence)
		prev.NonAdminEvidence = appendUniqueIDs(prev.NonAdminEvidence, draft.Detail.NonAdminEvidence)
		prev.Compared = prev.Compared || draft.Detail.Compared
		if draft.Detail.NonAdminStatus != 0 {
			prev.NonAdminStatus = draft.Detail.NonAdminStatus
		}
		if draft.Detail.PageURL != "" {
			prev.PageURL = draft.Detail.PageURL
		}
		if draft.Detail.FlagName != "" {
			prev.FlagName, prev.FlagLocation, prev.FlagValue = draft.Detail.FlagName, draft.Detail.FlagLocation, draft.Detail.FlagValue
		}
		if draft.Detail.RoleField != "" {
			prev.RoleField = draft.Detail.RoleField
		}
		if draft.Detail.BeforeReach != "" {
			prev.BeforeReach, prev.AfterReach = draft.Detail.BeforeReach, draft.Detail.AfterReach
		}
		f.Detail = red.redactJSON(encodeAccessControlFindingDetail(prev))
		f.Verdict = domain.VerdictConfirmed
		f.Summary = draft.Summary
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, draft.Evidence)
		f.UpdatedAt = time.Now()
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("update access-control finding", "finding", f.ID, "err", err)
		}
		return
	}

	sc, err := e.store.Scans().Get(ctx, scanID)
	if err != nil {
		e.log.Warn("load scan for access-control finding", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnAccessControl,
		Verdict: domain.VerdictConfirmed, Severity: draft.Severity, Confidence: domain.ConfidenceHigh,
		Title:       draft.Title,
		Summary:     draft.Summary,
		EndpointID:  draft.EndpointID,
		EvidenceIDs: appendUniqueIDs(nil, draft.Evidence),
		Provenance:  domain.Provenance{Engine: accessControlEngine, DiscoverySource: draft.DiscoverySource, DetectedAt: now, AIAssisted: false},
		Detail:      red.redactJSON(encodeAccessControlFindingDetail(draft.Detail)),
		CreatedAt:   now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("create access-control finding", "scan", scanID, "err", err)
	}
}

// findingDetailFrom maps a probe detail onto the correlated record.
func findingDetailFrom(d accessControlDetail, anonEvidence, nonAdminEvidence []domain.ID) accessControlFindingDetail {
	kind := d.Kind
	if kind == "" {
		kind = accessModePanel
	}
	return accessControlFindingDetail{
		Kind: kind, Method: d.Method, URL: d.URL, DiscoverySource: d.DiscoverySource,
		AnonymousStatus: d.AnonymousStatus, AnonymousFinalURL: d.AnonymousFinalURL,
		Actions: d.Actions, Compared: d.Compared, NonAdminStatus: d.NonAdminStatus, NonAdminActions: d.NonAdminActions,
		AnonymousEvidence: appendUniqueIDs(d.AnonymousEvidence, anonEvidence),
		NonAdminEvidence:  appendUniqueIDs(d.NonAdminEvidence, nonAdminEvidence),
		PageURL:           d.PageURL, Refs: d.Refs,
		Attempts: d.Attempts, Verdict: domain.VerdictConfirmed, Reason: d.Reason,
	}
}

func mergeAccessControlAttempts(existing, add []accessControlAttempt) []accessControlAttempt {
	for _, a := range add {
		found := false
		for _, x := range existing {
			if x.Kind == a.Kind && x.URL == a.URL && x.FlagName == a.FlagName &&
				x.FlagValue == a.FlagValue && x.Field == a.Field && x.Status == a.Status {
				found = true
				break
			}
		}
		if !found {
			existing = append(existing, a)
		}
	}
	return existing
}

func mergeAccessControlActions(existing, add []accesscontrol.Action) []accesscontrol.Action {
	for _, a := range add {
		seen := false
		for _, x := range existing {
			if x.Kind == a.Kind && x.Target == a.Target && x.Evidence == a.Evidence {
				seen = true
				break
			}
		}
		if !seen {
			existing = append(existing, a)
		}
	}
	return existing
}

func accessControlSeverity(actions []accesscontrol.Action) domain.Severity {
	for _, a := range actions {
		switch a.Kind {
		case accesscontrol.ActionDeleteUser, accesscontrol.ActionRoleControl, accesscontrol.ActionPrivilegedAction:
			return domain.SeverityHigh
		}
	}
	return domain.SeverityMedium
}

func accessControlFindingDedupKey(ep *domain.Endpoint) string {
	return "access_control\x00" + string(ep.Method) + "\x00" + ep.URL
}

// accessControlPathDedupKey identifies one anonymously reachable admin path on
// one host, whatever disclosed it. A page-disclosed and a robots-disclosed
// /admin are the same underlying site, so they collapse into one finding.
func accessControlPathDedupKey(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return "access_control\x00GET\x00" + strings.TrimSpace(rawURL)
	}
	return "access_control\x00GET\x00" + strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path
}

// isAccessControlCandidate reports whether an endpoint is one the panel mode
// may probe: a GET path discovery actually disclosed through robots.txt or a
// sitemap, whose path looks administrative.
func isAccessControlCandidate(ep *domain.Endpoint) bool {
	if ep == nil || ep.Method != domain.MethodGET {
		return false
	}
	if ep.Source != domain.SourceRobots && ep.Source != domain.SourceSitemap {
		return false
	}
	return accesscontrol.AdminLikePath(ep.URL)
}

func acSnapshot(r *httpengine.Response) accesscontrol.Snapshot {
	if r == nil {
		return accesscontrol.Snapshot{}
	}
	return accesscontrol.Snapshot{Status: r.Status, FinalURL: r.FinalURL, Truncated: r.Truncated, Body: r.Body}
}

func acSurfaceSnapshot(r *httpengine.Response) accesscontrol.Snapshot {
	return acSnapshot(r)
}

func verdictOf(o accesscontrol.Outcome) domain.Verdict {
	switch o {
	case accesscontrol.OutcomeConfirmed:
		return domain.VerdictConfirmed
	case accesscontrol.OutcomeRejected:
		return domain.VerdictRejected
	default:
		return domain.VerdictInconclusive
	}
}

// ---------------------------------------------------------------------------
// probe passes: one JobAccessControl per candidate, one job type for all modes
// ---------------------------------------------------------------------------

// enqueueAccessControlProbes runs once per execution when the ordinary queue
// goes quiet. It is bounded by what discovery actually disclosed (robots.txt
// Disallow/Allow entries and sitemap URLs) and by a fixed vocabulary of
// administrative path segments; it never guesses a path. No authentication is
// required to run it: an anonymous scan can still prove that an admin surface
// is reachable without a session.
func (c *Controller) enqueueAccessControlProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	seen := make(map[string]struct{})
	n := 0
	for _, ep := range endpoints {
		if !isAccessControlCandidate(ep) {
			continue
		}
		if _, dup := seen[ep.URL]; dup {
			continue
		}
		if n >= maxAccessControlProbesPerScan {
			c.log.Info("access-control probes: per-scan budget reached",
				"scan", scanID, "limit", maxAccessControlProbesPerScan)
			break
		}
		seen[ep.URL] = struct{}{}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 30, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("access-control probes: enqueue job", "scan", scanID, "url", ep.URL, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("access-control probes: enqueued", "scan", scanID, "jobs", n)
	}
}

// enqueueAccessControlDisclosureProbes queues the page-disclosure half of case
// 19: discovered HTML pages are analysed for administrative paths their own
// scripts name. It is bounded and one-shot; a restarted execution does not
// re-analyse a page whose TestCase already exists.
func (c *Controller) enqueueAccessControlDisclosureProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control disclosure: load scan", "scan", scanID, "err", err)
		return
	}
	if !sc.Config.EnableAccessControlPages {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("access-control disclosure: list endpoints", "scan", scanID, "err", err)
		return
	}
	sort.SliceStable(endpoints, func(i, j int) bool { return endpoints[i].URL < endpoints[j].URL })

	done := map[string]bool{}
	if cases, cerr := c.store.TestCases().ListByScan(ctx, scanID); cerr == nil {
		for _, tc := range cases {
			if tc.VulnClass != domain.VulnAccessControl || tc.URL == "" {
				continue
			}
			var d accessControlDetail
			if len(tc.Detail) > 0 && json.Unmarshal(tc.Detail, &d) == nil && d.Kind == accessModePage {
				done[d.PageURL] = true
			}
		}
	}

	now := time.Now()
	n := 0
	for _, ep := range endpoints {
		if n >= maxAccessControlPagesPerScan {
			break
		}
		if ep == nil || (ep.Method != domain.MethodGET && ep.Method != domain.MethodHEAD) {
			continue
		}
		if strings.EqualFold(pathOf(ep.URL), "/robots.txt") || !accesscontrol.PageAnalyzable(ep.URL) {
			continue
		}
		if done[ep.URL] {
			continue
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobAccessControl, State: domain.JobQueued,
			Priority: 25, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload:     accessControlModePayload(accessModePage),
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("access-control disclosure: enqueue job", "scan", scanID, "url", ep.URL, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("access-control disclosure: enqueued", "scan", scanID, "jobs", n)
	}
}

func accessControlModePayload(mode string) []byte {
	b, _ := json.Marshal(accessControlPayload{Mode: mode})
	return b
}

func pathOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Path
}

// sameOriginURL reports whether two absolute URLs share scheme, host and
// effective port.
func sameOriginURL(a, b string) bool {
	ua, err := url.Parse(strings.TrimSpace(a))
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(strings.TrimSpace(b))
	if err != nil || ub.Host == "" {
		return false
	}
	return accesscontrol.SameOrigin(ua, ub)
}

// sessionCookieCount reports whether the engine carries stored session
// cookies. Kept next to the engine so the "has session" decision has one home.
func sessionCookieCount(eng httpengine.Engine) int {
	if se, ok := eng.(*scopedEngine); ok && se != nil {
		return len(se.cookies)
	}
	return 0
}

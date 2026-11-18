package scan

// Path traversal / local file inclusion engine (READ-ONLY).
//
// One JobPathTraversal is enqueued per eligible injection point. The engine
// sends an untouched baseline, then a negative control (a path that cannot
// exist), then a small fixed set of traversal payloads that ask the endpoint to
// return a well-known system file: /etc/passwd on Unix and windows\win.ini on
// Windows. Nothing is written, uploaded, executed or deleted at any point —
// every payload is a READ of a file the operating system ships by default.
//
// Applicability. A parameter is a candidate when its name denotes a file or
// page selector (file/path/page/template/view/doc/include/lang/locale/dir/
// folder/download/read/load/report/resource/src/url/name — matched as words, so
// "file_name", "templatePath" and "download" all qualify) or when the endpoint
// itself is file-shaped (/file, /page, /viewer, /download, /include, ...).
// Candidates are accepted in the query string and an urlencoded form body.
// JSON bodies and headers are not tested: this engine substitutes a filesystem
// path, and those surfaces rarely carry one. A path-SEGMENT injection point is
// discovered and queued but recorded as a skip: the scan's scope validator
// refuses dot segments, encoded slashes/backslashes, NUL bytes and duplicate
// slashes in a request path (it fails closed), so no traversal payload could be
// delivered there without weakening scope enforcement.
//
// Confirmation is only ever evidence the TARGET produced:
//   - the response status is 2xx, AND
//   - the body carries the file's own multi-token content — either the
//     /etc/passwd shape ("root:...:0:0:" plus daemon:/bin:/nobody/nologin) or
//     the win.ini shape ("[fonts]" plus "[extensions]" or "[mci extensions]"),
//     AND
//   - NEITHER the untouched baseline NOR the nonexistent-path control produced
//     that signature.
//
// The baseline and the negative control are what keep a page that simply quotes
// an /etc/passwd example, or an endpoint that returns a fixed file for any
// value, from being reported as traversal. A match is never taken from a
// redirect, an error page or a reflection of the payload.
//
// Safety policy:
//   - Read-only and bounded: at most ptMaxPayloads payload requests per
//     injection point, and the pass stops at the first confirmed signature.
//   - State-changing endpoints need the server's explicit AllowStateChanging
//     opt-in, exactly like every other payload-bearing engine.
//   - ScanConfig.SkipWriteEndpoints keeps the engine away from non-GET/HEAD/
//     OPTIONS methods and write-like routes even when AllowStateChanging is on,
//     and SkipDownloadEndpoints keeps it off export/download routes that can
//     stream a large body or hold a worker open.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	ptEngine = "path_traversal"

	// ptVulnClass is the class every TestCase and Finding this engine writes
	// carries.
	ptVulnClass domain.VulnClass = domain.VulnPathTraversal

	// ptConfirmUnixPasswd / ptConfirmWindowsINI identify WHICH file signature
	// confirmed a finding. They are also the payload families.
	ptConfirmUnixPasswd = "unix_passwd"
	ptConfirmWindowsINI = "windows_win.ini"

	// ptMaxPayloads is the ceiling for one injection point: the fixed payload
	// set below. No payload is generated, adapted or repeated.
	ptMaxPayloads = 9

	// ptRawMarker is an alphanumeric placeholder substituted into the request
	// so an encoding-trick payload (..%2f, %00) can be written to the wire
	// EXACTLY as written here. It must stay alphanumeric so the URL/body
	// encoders leave it untouched and the substitution is byte-exact.
	ptRawMarker = "indagoPathTraversalProbe"
)

// ptPayload is one bounded traversal probe.
type ptPayload struct {
	// Family is the file signature this payload targets.
	Family string
	// Value is the exact value sent.
	Value string
	// Raw marks a payload whose percent escapes ARE the bypass: the value must
	// reach the target verbatim, not be encoded a second time.
	Raw bool
}

// ptPayloads is the whole payload set: the /etc/passwd shapes the engine
// documents plus the Windows win.ini shapes. It is fixed, ordered and never
// derived from the response.
func ptPayloads() []ptPayload {
	return []ptPayload{
		{Family: ptConfirmUnixPasswd, Value: "/etc/passwd"},
		{Family: ptConfirmUnixPasswd, Value: "../../../../../../../../etc/passwd"},
		{Family: ptConfirmUnixPasswd, Value: "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", Raw: true},
		{Family: ptConfirmUnixPasswd, Value: "....//....//....//....//....//....//....//....//etc/passwd"},
		{Family: ptConfirmUnixPasswd, Value: "../../../../../../../../etc/passwd%00", Raw: true},
		{Family: ptConfirmUnixPasswd, Value: "../../../../../../../../etc/passwd%00.php", Raw: true},
		{Family: ptConfirmUnixPasswd, Value: "../../../../../../../../etc/passwd%00.txt", Raw: true},
		{Family: ptConfirmWindowsINI, Value: `..\..\..\..\..\..\..\..\windows\win.ini`},
		{Family: ptConfirmWindowsINI, Value: "../../../../../../../../windows/win.ini"},
	}
}

var (
	// ptUnixRootLine is the passwd entry that only a real passwd file has:
	// root with uid 0 and gid 0 wherever the fields sit.
	ptUnixRootLine = regexp.MustCompile(`(?m)^root:[^:\r\n]*:0:0:`)
)

// ptFileSignature reports which well-known file the response body contains, or
// "" when it contains neither. It looks only at file content the target would
// have to have READ; it never trusts the request URL or a reflection.
func ptFileSignature(body string) string {
	if body == "" {
		return ""
	}
	if ptUnixPasswdMatch(body) {
		return ptConfirmUnixPasswd
	}
	if ptWindowsINIMatch(body) {
		return ptConfirmWindowsINI
	}
	return ""
}

// ptUnixPasswdMatch requires the root account line AND at least two further
// account/shell tokens. One token can appear in documentation; a real passwd
// file always carries several.
func ptUnixPasswdMatch(body string) bool {
	if !ptUnixRootLine.MatchString(body) {
		return false
	}
	tokens := 0
	for _, tok := range []string{"daemon:", "/bin:", "nobody:", "nologin"} {
		if strings.Contains(body, tok) {
			tokens++
		}
	}
	return tokens >= 2
}

// ptWindowsINIMatch requires the [fonts] section AND a second section win.ini
// always carries. Section names are matched case-insensitively, exactly as the
// Windows INI reader treats them.
func ptWindowsINIMatch(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "[fonts]") {
		return false
	}
	return strings.Contains(lower, "[extensions]") || strings.Contains(lower, "[mci extensions]")
}

type ptAttempt struct {
	Payload string `json:"payload"`
	Family  string `json:"family"`
	Status  int    `json:"status,omitempty"`
	// Signature names the file the response body contained, when it matched.
	Signature string `json:"signature,omitempty"`
	Matched   bool   `json:"matched"`
	// Error records that the request itself did not complete.
	Error string `json:"error,omitempty"`
}

type ptDetail struct {
	Engine                string               `json:"engine"`
	Parameter             string               `json:"parameter"`
	Location              domain.ParamLocation `json:"location"`
	BaselineStatus        int                  `json:"baseline_status,omitempty"`
	BaselineSignature     string               `json:"baseline_signature,omitempty"`
	NegativeControl       string               `json:"negative_control,omitempty"`
	NegativeControlStatus int                  `json:"negative_control_status,omitempty"`
	// NegativeControlSignature records a signature the control produced. Any
	// value here means the endpoint returns file content for a path that does
	// not exist, so nothing can be attributed to the payloads.
	NegativeControlSignature string `json:"negative_control_signature,omitempty"`
	// NegativeControlSeen records that the control completed with a response.
	// Without it a match is inconclusive (see decidePT).
	NegativeControlSeen bool           `json:"negative_control_seen,omitempty"`
	Attempts            []ptAttempt    `json:"attempts,omitempty"`
	SentCount           int            `json:"sent_count"`
	FailedCount         int            `json:"failed_count,omitempty"`
	MatchedCount        int            `json:"matched_count,omitempty"`
	ConfirmedPayload    string         `json:"confirmed_payload,omitempty"`
	ConfirmSignature    string         `json:"confirm_signature,omitempty"`
	Verdict             domain.Verdict `json:"verdict"`
	Reason              string         `json:"reason,omitempty"`
	EvidenceIDs         []domain.ID    `json:"evidence_ids,omitempty"`
	// DedupKey collapses repeated confirmations at the same injection point and
	// signature into ONE Finding; Occurrences counts how many jobs saw it.
	DedupKey    string `json:"dedup_key,omitempty"`
	Occurrences int    `json:"occurrences,omitempty"`
}

type pathTraversalExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

// NewPathTraversalExecutorForTest exposes the executor to tests without
// exporting production wiring.
func NewPathTraversalExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *pathTraversalExecutor {
	return newPathTraversalExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newPathTraversalExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *pathTraversalExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &pathTraversalExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

var _ worker.Handler = (*pathTraversalExecutor)(nil)

func (e *pathTraversalExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve path traversal target: %w", err)
	}
	if focus == nil {
		return e.finishPTUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if focus.Location == domain.LocationPath {
		// The scope validator refuses dot segments, encoded slashes/backslashes,
		// NUL bytes and duplicate slashes in a request path — by design, so a
		// traversal payload can never be delivered through a path segment
		// without weakening that enforcement. Recorded as a coverage boundary
		// instead of sending requests the scope layer will refuse.
		return e.finishPTUnavailable(ctx, job, started, ep, "path-segment injection point cannot carry a traversal payload: the scope validator refuses dot segments, encoded slashes, NUL bytes and duplicate slashes in the request path")
	}
	if !ptInjectableLocation(focus.Location) {
		return e.finishPTUnavailable(ctx, job, started, ep, "parameter location cannot carry a filesystem path")
	}
	if focus.Location == domain.LocationForm && !hasBody(ep.Method) {
		return e.finishPTUnavailable(ctx, job, started, ep, "form parameter on a method that carries no body")
	}
	if !ptCandidate(ep, focus) {
		return e.finishPTUnavailable(ctx, job, started, ep, "parameter is not a file/page selector and the endpoint is not file-shaped")
	}
	if isDynamicTokenName(focus.Name) {
		return e.finishPTUnavailable(ctx, job, started, ep, "parameter looks like an anti-CSRF/session token")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishPTUnavailable(ctx, job, started, ep, "export/download endpoint skipped by policy (skip_download_endpoints)")
	}
	if e.cfg.SkipWriteEndpoints && (!isSafeMethod(ep.Method) || isWriteLikeEndpoint(ep, params)) {
		return e.finishPTUnavailable(ctx, job, started, ep, "write endpoint skipped by policy (skip_write_endpoints)")
	}
	if isWriteLikeEndpoint(ep, params) && !e.cfg.AllowStateChanging {
		return e.finishPTUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy (AllowStateChanging is off)")
	}

	// Filled blanks let a required form field reach the handler; the focused
	// parameter is always replaced by the payload.
	params = ptFillEmptyParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build path traversal baseline: %w", err)
	}
	baseResp, outcome, reqErr := e.do(ctx, base)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishPTError(ctx, job, started, ep, outcome, reqErr)
	}

	d := ptDetail{Engine: ptEngine, Parameter: focus.Name, Location: focus.Location, BaselineStatus: baseResp.Status}
	baselineEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "path traversal baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baselineEvidence...)
	d.BaselineSignature = ptFileSignature(string(baseResp.Body))

	// The untouched baseline already serves the file: nothing a payload does
	// can be attributed to traversal, and sending one would only add traffic.
	if d.BaselineSignature != "" {
		d.Verdict = domain.VerdictRejected
		d.Reason = "the untouched baseline already contains the " + d.BaselineSignature + " file signature, so a payload match cannot be attributed to path traversal"
		e.persistPTCase(ctx, job, ep, focus, d, d.Reason)
		return nil
	}

	// Negative control: a path that cannot exist. A 2xx that still carries a
	// file signature proves the endpoint ignores or fabricates the value.
	d.NegativeControl = ptNegativeControlPath()
	if req, err := buildRequest(ep, params, &injection{param: focus, value: d.NegativeControl}); err != nil {
		e.log.Warn("path traversal: build negative control", "scan", job.ScanID, "err", err)
	} else if resp, _, _ := e.do(ctx, req); resp != nil {
		d.NegativeControlSeen = true
		d.NegativeControlStatus = resp.Status
		d.NegativeControlSignature = ptFileSignature(string(resp.Body))
		ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "path traversal negative control")
		d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	}
	if d.NegativeControlSignature != "" {
		d.Verdict = domain.VerdictRejected
		d.Reason = "a nonexistent path produced the " + d.NegativeControlSignature + " file signature, so the response does not depend on the supplied path"
		e.persistPTCase(ctx, job, ep, focus, d, d.Reason)
		return nil
	}

	payloads := ptPayloads()
	if len(payloads) > ptMaxPayloads {
		payloads = payloads[:ptMaxPayloads]
	}
	for _, p := range payloads {
		attempt, sent := e.probe(ctx, job, ep, params, focus, p, &d)
		if sent {
			d.SentCount++
		} else if attempt.Error != "" {
			d.FailedCount++
		}
		d.Attempts = append(d.Attempts, attempt)
		if attempt.Matched {
			d.MatchedCount++
			d.ConfirmedPayload = p.Value
			d.ConfirmSignature = attempt.Signature
			// The signature is the whole evidence; stop sending.
			break
		}
	}

	e.decidePT(&d)
	if d.Verdict == domain.VerdictConfirmed {
		e.persistPTCase(ctx, job, ep, focus, d, "confirmed path traversal: the endpoint returned "+d.ConfirmSignature+" content")
		e.correlatePT(ctx, job, ep, focus, d)
		return nil
	}
	e.persistPTCase(ctx, job, ep, focus, d, ptNote(d))
	return nil
}

// decidePT fills d.Verdict and d.Reason from the attempts already recorded.
//
// A match is CONFIRMED only when the baseline and the negative control both
// completed clean and the matching response was a 2xx. A match without a
// completed negative control stays INCONCLUSIVE: without that control the same
// body could be a fixed response for any value.
func (e *pathTraversalExecutor) decidePT(d *ptDetail) {
	switch {
	case d.MatchedCount > 0 && d.NegativeControlSeen:
		d.Verdict = domain.VerdictConfirmed
		d.Reason = "the endpoint returned " + d.ConfirmSignature + " content for a traversal payload over a clean baseline, while a nonexistent-path control returned no such content"
	case d.MatchedCount > 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "a traversal payload produced the " + d.ConfirmSignature + " signature, but the nonexistent-path control did not complete, so the response cannot be attributed to the payload"
	case d.SentCount == 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "no traversal payload completed; the target was left untested"
	default:
		d.Verdict = domain.VerdictRejected
		d.Reason = "no traversal payload returned a recognised system file"
	}
}

func ptNote(d ptDetail) string {
	switch d.Verdict {
	case domain.VerdictConfirmed:
		return "confirmed path traversal: " + d.ConfirmSignature + " content returned"
	case domain.VerdictInconclusive:
		return "path traversal inconclusive: " + d.Reason
	default:
		return "no path traversal: " + d.Reason
	}
}

// probe substitutes one payload into the focused parameter and records what the
// response contained.
func (e *pathTraversalExecutor) probe(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter, p ptPayload, d *ptDetail) (ptAttempt, bool) {
	attempt := ptAttempt{Payload: p.Value, Family: p.Family}
	req, err := ptBuildPayloadRequest(ep, params, focus, p)
	if err != nil {
		attempt.Error = truncate(err.Error(), 200)
		e.log.Warn("path traversal: build payload request", "scan", job.ScanID, "err", err)
		return attempt, false
	}
	resp, outcome, reqErr := e.do(ctx, req)
	if resp == nil {
		if reqErr != nil {
			attempt.Error = truncate(reqErr.Error(), 200)
		}
		return attempt, false
	}
	attempt.Status = resp.Status
	ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "path traversal payload "+p.Family)
	d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	if resp.Status < 200 || resp.Status >= 300 {
		return attempt, outcome == domain.OutcomeSuccess
	}
	attempt.Signature = ptFileSignature(string(resp.Body))
	attempt.Matched = attempt.Signature != ""
	return attempt, outcome == domain.OutcomeSuccess
}

// ptBuildPayloadRequest builds the one request that carries p. A payload marked
// Raw (..%2f, %00) is written to the wire verbatim: routing it through the
// normal form/query encoder would turn "%2f" into "%252f" and remove the bypass
// the payload exists to test. Every other payload uses the shared builder, so
// its escaping matches every other engine's requests byte for byte.
func ptBuildPayloadRequest(ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter, p ptPayload) (*httpengine.Request, error) {
	if !p.Raw {
		return buildRequest(ep, params, &injection{param: focus, value: p.Value})
	}
	req, err := buildRequest(ep, params, &injection{param: focus, value: ptRawMarker})
	if err != nil {
		return nil, err
	}
	replaced := 0
	if n := strings.Count(req.URL, ptRawMarker); n > 0 {
		if n != 1 {
			return nil, fmt.Errorf("raw payload appears %d times in the request URL, want 1", n)
		}
		req.URL = strings.Replace(req.URL, ptRawMarker, p.Value, 1)
		replaced++
	}
	if len(req.Body) > 0 {
		if n := strings.Count(string(req.Body), ptRawMarker); n > 0 {
			if n != 1 {
				return nil, fmt.Errorf("raw payload appears %d times in the request body, want 1", n)
			}
			req.Body = []byte(strings.Replace(string(req.Body), ptRawMarker, p.Value, 1))
			replaced++
		}
	}
	if replaced != 1 {
		return nil, fmt.Errorf("raw payload landed in %d places, want 1", replaced)
	}
	return req, nil
}

func (e *pathTraversalExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, errors.New("nil request")
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	default:
		return nil, domain.OutcomeError, err
	}
}

// refreshParams keeps a rotating anti-CSRF token usable for every request. It
// only touches parameters OTHER than the focused one.
func (e *pathTraversalExecutor) refreshParams(ctx context.Context, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	if !hasDynamicParam(params, focus) {
		return params
	}
	return refreshDynamicParams(ctx, e.engine, e.cfg.RequestTimeout, ep, params, focus)
}

// ptFillEmptyParams gives blank required-looking fields a harmless value so a
// form reaches the code that consumes the path. The focused parameter is left
// to the payload builder and CSRF tokens to refreshParams.
func ptFillEmptyParams(params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	out := append([]*domain.Parameter(nil), params...)
	for i, p := range out {
		if p == nil || p == focus || strings.TrimSpace(p.Example) != "" {
			continue
		}
		if p.Location == domain.LocationHeader || p.Location == domain.LocationCookie || isDynamicTokenName(p.Name) {
			continue
		}
		cp := *p
		cp.Example = "1"
		out[i] = &cp
	}
	return out
}

// ptNegativeControlPath is a path that cannot exist on the target. It traverses
// the same way the payloads do, so an endpoint that ignores the parameter and
// serves a fixed page is compared like for like.
func ptNegativeControlPath() string {
	return "../../../../../../../../indago-nonexistent-" + ptNewToken() + ".txt"
}

func ptNewToken() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// A token only has to be unlikely, never secret; the timestamp keeps it
		// unique enough if the system entropy source is unavailable.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

// ---------------------------------------------------------------------------
// applicability
// ---------------------------------------------------------------------------

func ptInjectableLocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationPath:
		return true
	default:
		return false
	}
}

// ptParamSinks are the words that make a parameter name a file/page selector.
// They are matched as whole words (handling snake_case/kebab-case/camelCase),
// so "file_name" and "templatePath" qualify while "profile" does not.
var ptParamSinks = map[string]bool{
	"file": true, "files": true, "filename": true, "filepath": true,
	"path": true, "paths": true, "dir": true, "dirname": true, "directory": true,
	"folder": true, "folders": true,
	"page": true, "pages": true, "template": true, "templates": true,
	"view": true, "views": true, "doc": true, "docs": true, "document": true, "documents": true,
	"include": true, "includes": true, "inc": true,
	"lang": true, "language": true, "locale": true, "locales": true,
	"download": true, "downloads": true, "read": true, "load": true,
	"report": true, "reports": true, "resource": true, "resources": true,
	"src": true, "source": true, "sources": true, "url": true, "urls": true,
	"name": true, "names": true,
}

// ptEndpointWords make an ENDPOINT file-shaped even when its parameter names
// are generic. The five words are the conventional read surfaces this engine
// targets; plurals and "view" are included because routes use them.
var ptEndpointWords = map[string]bool{
	"file": true, "files": true,
	"page": true, "pages": true,
	"viewer": true, "view": true, "views": true,
	"download": true, "downloads": true,
	"include": true, "includes": true,
}

func ptParamName(name string) bool {
	for _, w := range paramNameWords(name) {
		if ptParamSinks[w] {
			return true
		}
	}
	return false
}

// ptEndpointFileShape reports whether any path segment names a file-reading
// surface ("/download.php", "/view/doc", "/files/report").
func ptEndpointFileShape(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	u, err := url.Parse(ep.URL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(strings.Trim(u.Path, "/")), "/") {
		if seg == "" {
			continue
		}
		for _, w := range paramNameWords(seg) {
			if ptEndpointWords[w] {
				return true
			}
		}
	}
	return false
}

// ptCandidate reports whether this injection point can plausibly carry a
// filesystem path: the parameter name says so, or the endpoint is file-shaped.
func ptCandidate(ep *domain.Endpoint, focus *domain.Parameter) bool {
	if focus != nil && ptParamName(focus.Name) {
		return true
	}
	return ptEndpointFileShape(ep)
}

// ---------------------------------------------------------------------------
// persistence
// ---------------------------------------------------------------------------

func (e *pathTraversalExecutor) persistEvidence(ctx context.Context, scanID domain.ID, resp *httpengine.Response, role string) ([]domain.ID, error) {
	return persistHTTPExchange(ctx, e.store, e.evidence, scanID, resp, role)
}

func (e *pathTraversalExecutor) persistPTCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d ptDetail, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: ptVulnClass,
		Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: note,
		EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("path traversal: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *pathTraversalExecutor) finishPTUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	method := ""
	if ep != nil {
		method = string(ep.Method)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: ptVulnClass, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: method, URL: job.Target.URL, Note: "path traversal skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped path traversal case: %w", err)
	}
	return nil
}

func (e *pathTraversalExecutor) finishPTError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		return e.finishPTUnavailable(ctx, job, started, ep, "redirect target is outside the scan scope")
	}
	if isTLSRedirectMismatch(reqErr) {
		return e.finishPTUnavailable(ctx, job, started, ep, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	method := ""
	if ep != nil {
		method = string(ep.Method)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: ptVulnClass, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: method, URL: job.Target.URL, Error: msg, Note: "path traversal baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("path traversal baseline failed: %s", msg)
}

func ptFindingSummary(d ptDetail) string {
	switch d.ConfirmSignature {
	case ptConfirmUnixPasswd:
		return "A traversal payload made the endpoint return the contents of /etc/passwd (the response carries the root account line plus the system-account/shell fields), which an untouched baseline and a nonexistent-path control did not."
	case ptConfirmWindowsINI:
		return "A traversal payload made the endpoint return the contents of windows\\win.ini (the response carries the [fonts] section plus a second INI section), which an untouched baseline and a nonexistent-path control did not."
	default:
		return "Evidence is insufficient for a verdict."
	}
}

// ptFindingDedupKey identifies one underlying traversal site: the same
// injection point confirming the same file signature is one Finding, no matter
// how many jobs observe it.
func ptFindingDedupKey(job *domain.TestJob, focus *domain.Parameter, signature string) string {
	key := "path_traversal\x00" + string(job.Target.InjectionPointID) + "\x00" + string(focus.Location) + "\x00" + focus.Name
	return key + "\x00" + signature
}

// correlatePT upserts one Confirmed Finding per (injection point, parameter,
// signature). Re-confirming the same site increments its occurrence count and
// unions the evidence instead of creating a near-duplicate row.
func (e *pathTraversalExecutor) correlatePT(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d ptDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	key := ptFindingDedupKey(job, focus, d.ConfirmSignature)
	d.DedupKey = key
	d.Occurrences = 1
	now := time.Now()

	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	if existing, err := e.store.Findings().ListByScan(ctx, job.ScanID); err == nil {
		for _, cur := range existing {
			if cur == nil || cur.VulnClass != ptVulnClass {
				continue
			}
			var prev ptDetail
			if err := json.Unmarshal(cur.Detail, &prev); err != nil || prev.DedupKey != key {
				continue
			}
			prev.Occurrences++
			prev.Verdict = d.Verdict
			prev.Reason = d.Reason
			prev.Attempts = d.Attempts
			prev.SentCount = d.SentCount
			prev.FailedCount = d.FailedCount
			prev.MatchedCount = d.MatchedCount
			prev.ConfirmedPayload = d.ConfirmedPayload
			prev.ConfirmSignature = d.ConfirmSignature
			prev.BaselineStatus = d.BaselineStatus
			prev.NegativeControlStatus = d.NegativeControlStatus
			prev.NegativeControl = d.NegativeControl
			if b, err := json.Marshal(prev); err == nil {
				cur.Detail = b
			}
			cur.EvidenceIDs = appendUniqueIDs(cur.EvidenceIDs, d.EvidenceIDs)
			cur.UpdatedAt = now
			if err := e.store.Findings().Update(ctx, cur); err != nil {
				e.log.Warn("path traversal: update finding", "scan", job.ScanID, "err", err)
			}
			return
		}
	}

	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: ptVulnClass, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "Path traversal / file inclusion in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    ptFindingSummary(d),
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: ptEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("path traversal: persist finding", "scan", job.ScanID, "err", err)
	}
}

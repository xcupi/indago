package scan

// XML external entity (XXE) engine.
//
// XXE is only applicable to an endpoint whose observed request body is XML and
// whose parser is asked to resolve an external entity. The engine never guesses
// an XML endpoint or sprays XML at a form/JSON route: discovery must have
// captured an XML request body in the browser network, and the operator must
// provide a callback. The entity itself is a marker-only callback; no local
// file is read and no target data is exfiltrated.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

const xxeEngine = "xxe"

var xxeRootRe = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.:-]*)(\s[^>]*)?>`)

type xxeAttempt struct {
	Payload  string `json:"payload"`
	Status   int    `json:"status,omitempty"`
	Callback bool   `json:"callback"`
}

type xxeDetail struct {
	Engine      string         `json:"engine"`
	Attempts    []xxeAttempt   `json:"attempts,omitempty"`
	Verdict     domain.Verdict `json:"verdict"`
	Reason      string         `json:"reason,omitempty"`
	EvidenceIDs []domain.ID    `json:"evidence_ids,omitempty"`
}

type xxeExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
	callback   string
	poll       string
}

func NewXXEExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *xxeExecutor {
	return newXXEExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newXXEExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *xxeExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &xxeExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

func (e *xxeExecutor) withCallback(url, poll string) {
	e.callback = strings.TrimSpace(url)
	e.poll = strings.TrimSpace(poll)
}

var _ worker.Handler = (*xxeExecutor)(nil)

func isXMLBodyEndpoint(ep *domain.Endpoint) bool {
	if ep == nil || strings.TrimSpace(ep.RequestBody) == "" {
		return false
	}
	if !strings.Contains(strings.ToLower(ep.ContentType), "xml") {
		return false
	}
	switch ep.Method {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH:
		return strings.Contains(ep.RequestBody, "<")
	default:
		return false
	}
}

func (e *xxeExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	ep, err := e.store.Endpoints().Get(ctx, job.Target.EndpointID)
	if err != nil {
		return fmt.Errorf("resolve xxe endpoint: %w", err)
	}
	if !isXMLBodyEndpoint(ep) {
		return e.finishXXEUnavailable(ctx, job, "no observed XML request body")
	}
	if e.cfg.SkipWriteEndpoints || !e.cfg.AllowStateChanging {
		return e.finishXXEUnavailable(ctx, job, "state-changing XML endpoint skipped by policy")
	}
	if e.callback == "" || e.poll == "" {
		return e.finishXXEUnavailable(ctx, job, "no XXE callback configured")
	}
	req := &httpengine.Request{
		Method:      string(ep.Method),
		URL:         ep.URL,
		Body:        []byte(ep.RequestBody),
		ContentType: ep.ContentType,
	}
	baseResp, baseOutcome, _ := e.do(ctx, req)
	if baseOutcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishXXEUnavailable(ctx, job, "baseline XML request did not succeed")
	}
	d := xxeDetail{Engine: xxeEngine}
	if ev, err := e.persistEvidence(ctx, job.ScanID, baseResp, "xxe baseline"); err == nil {
		d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	}
	marker := fmt.Sprintf("indago-xxe-%d", time.Now().UnixNano()%1000000000)
	callback := strings.TrimRight(e.callback, "/") + "/" + marker
	payload, ok := injectXXE(ep.RequestBody, callback)
	if !ok {
		return e.finishXXEUnavailable(ctx, job, "XML body has no injectable root element")
	}
	attempt := xxeAttempt{Payload: truncate(payload, 300)}
	req.Body = []byte(payload)
	resp, outcome, _ := e.do(ctx, req)
	if resp != nil {
		attempt.Status = resp.Status
		if ev, err := e.persistEvidence(ctx, job.ScanID, resp, "xxe entity request"); err == nil {
			d.EvidenceIDs = append(d.EvidenceIDs, ev...)
		}
	}
	d.Attempts = append(d.Attempts, attempt)
	if outcome != domain.OutcomeSuccess {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "XXE request did not complete"
		e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeError, "xxe request did not complete")
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 8; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
		pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, e.poll, nil)
		if err != nil {
			break
		}
		pollResp, err := client.Do(pollReq)
		if err != nil {
			continue
		}
		body := make([]byte, 1<<20)
		n, _ := pollResp.Body.Read(body)
		pollResp.Body.Close()
		if strings.Contains(string(body[:n]), marker) {
			attempt.Callback = true
			d.Attempts = append(d.Attempts, attempt)
			d.Verdict = domain.VerdictConfirmed
			d.Reason = "the XML parser resolved an external entity and called the collaborator"
			e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed XML external entity processing")
			e.correlateXXE(ctx, job, ep, d)
			return nil
		}
	}
	d.Verdict = domain.VerdictRejected
	d.Reason = "no external entity callback observed"
	e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "no external entity callback observed")
	return nil
}

func injectXXE(body, callback string) (string, bool) {
	loc := xxeRootRe.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	root := xxeRootRe.FindStringSubmatch(body)
	if len(root) < 2 {
		return "", false
	}
	name := root[1]
	open := body[loc[0]:loc[1]]
	if strings.HasSuffix(strings.TrimSpace(open), "/>") {
		return "", false
	}
	doctype := "<!DOCTYPE " + name + " [<!ENTITY xxe SYSTEM \"" + xmlEntityEscape(callback) + "\">]>"
	insert := loc[0]
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "<?xml") {
		if idx := strings.Index(body, "?>"); idx >= 0 {
			insert = idx + 2
		}
	}
	out := body[:insert] + doctype + body[insert:]
	// Re-find the root opening tag after the doctype insert.
	loc = xxeRootRe.FindStringIndex(out)
	if loc == nil {
		return "", false
	}
	out = out[:loc[1]] + "&xxe;" + out[loc[1]:]
	return out, true
}

func xmlEntityEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func (e *xxeExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, fmt.Errorf("nil request")
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	if err == nil {
		return resp, domain.OutcomeSuccess, nil
	}
	if ctx.Err() != nil {
		return nil, domain.OutcomeCancelled, ctx.Err()
	}
	return nil, domain.OutcomeError, err
}

func (e *xxeExecutor) persistEvidence(ctx context.Context, scanID domain.ID, resp *httpengine.Response, role string) ([]domain.ID, error) {
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

func (e *xxeExecutor) persistXXECase(ctx context.Context, job *domain.TestJob, d xxeDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnXXE, Status: status, Outcome: outcome, URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("xxe: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *xxeExecutor) finishXXEUnavailable(ctx context.Context, job *domain.TestJob, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnXXE, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		URL: job.Target.URL, Note: "xxe skipped: " + reason, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped xxe case: %w", err)
	}
	return nil
}

func (e *xxeExecutor) correlateXXE(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d xxeDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnXXE, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title: "XML external entity processing", Summary: "An observed XML request body caused the server to resolve an external entity and call the collaborator.",
		EndpointID: ep.ID, EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: xxeEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("xxe: persist finding", "scan", job.ScanID, "err", err)
	}
}

func (c *Controller) enqueueXXEProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableXXE {
		return
	}
	eps, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	for _, ep := range eps {
		if !isXMLBodyEndpoint(ep) {
			continue
		}
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobXXE,
			State: domain.JobQueued, Priority: 47, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 1, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("xxe: enqueue", "scan", scanID, "err", err)
		}
	}
}

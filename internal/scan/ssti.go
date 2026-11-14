package scan

// Server-side template injection (SSTI) engine.
//
// One JobSSTI is enqueued per eligible injection point. The engine sends a
// small set of arithmetic template expressions through the HTTP engine. A
// template expression is harmless: the request contains e.g. "{{7*7}}" while
// a vulnerable server evaluates it and returns "49".
//
// A verdict is CONFIRMED only when two independent expressions produce their
// own computed result and neither the raw payload nor the result was already
// present in the baseline response. Reflection, a single marker, transport
// errors and ordinary pages containing the same numbers are never promoted to
// a finding. No template statement, file access, network access or state change
// is sent.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const sstiEngine = "ssti"

type sstiAttempt struct {
	Payload  string `json:"payload"`
	Expected string `json:"expected"`
	Kind     string `json:"kind,omitempty"`
	Output   bool   `json:"output"`
	Status   int    `json:"status,omitempty"`
}

type sstiDetail struct {
	Engine         string               `json:"engine"`
	Parameter      string               `json:"parameter"`
	Location       domain.ParamLocation `json:"location"`
	BaselineStatus int                  `json:"baseline_status,omitempty"`
	Attempts       []sstiAttempt        `json:"attempts,omitempty"`
	ConfirmedCount int                  `json:"confirmed_count"`
	Verdict        domain.Verdict       `json:"verdict"`
	Reason         string               `json:"reason,omitempty"`
	EvidenceIDs    []domain.ID          `json:"evidence_ids,omitempty"`
}

type sstiExecutor struct {
	*commandInjectionExecutor
}

// NewSSTIExecutorForTest exposes the executor to tests without exporting the
// production constructor.
func NewSSTIExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sstiExecutor {
	return newSSTIExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newSSTIExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sstiExecutor {
	return &sstiExecutor{commandInjectionExecutor: newCommandInjectionExecutor(st, eng, ev, cfg, log, findingsMu)}
}

var _ worker.Handler = (*sstiExecutor)(nil)

type sstiVariant struct {
	prefix   string
	suffix   string
	expr     string
	expected string
}

func sstiVariants() []sstiVariant {
	// Pairs are deliberate: many engines support only one syntax, so a
	// single probe per family would make a real ERB/Jinja/Freemarker target
	// inconclusive. Each pair uses different arithmetic results; reflection
	// alone still cannot produce either computed value.
	return []sstiVariant{
		{prefix: "<%= ", suffix: " %>", expr: "7*7", expected: "49"},
		{prefix: "<%= ", suffix: " %>", expr: "11*13", expected: "143"},
		{prefix: "{{", suffix: "}}", expr: "7*7", expected: "49"},
		{prefix: "{{", suffix: "}}", expr: "11*13", expected: "143"},
		{prefix: "${", suffix: "}", expr: "7*7", expected: "49"},
		{prefix: "${", suffix: "}", expr: "11*13", expected: "143"},
		{prefix: "#{", suffix: "}", expr: "7*7", expected: "49"},
		{prefix: "#{", suffix: "}", expr: "11*13", expected: "143"},
		{prefix: "*{", suffix: "}", expr: "7*7", expected: "49"},
		{prefix: "*{", suffix: "}", expr: "11*13", expected: "143"},
		{prefix: "{", suffix: "}", expr: "7*7", expected: "49"},
		{prefix: "{", suffix: "}", expr: "11*13", expected: "143"},
	}
}

func (e *sstiExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve ssti target: %w", err)
	}
	if focus == nil {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !isSSTILocation(focus.Location) || isDynamicTokenName(focus.Name) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "parameter location is not template-injectable")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}
	if isWriteLikeEndpoint(ep, params) && (!e.cfg.AllowStateChanging || e.cfg.SkipWriteEndpoints) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}

	baseValue := strings.TrimSpace(focus.Example)
	if baseValue == "" {
		baseValue = commandInjectionBaseValue(focus.Name)
	}
	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build ssti baseline: %w", err)
	}
	baseResp, outcome, reqErr := e.do(ctx, base)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishSSTIError(ctx, job, started, ep, focus, outcome, reqErr)
	}

	d := sstiDetail{Engine: sstiEngine, Parameter: focus.Name, Location: focus.Location, BaselineStatus: baseResp.Status}
	baseEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "ssti baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baseEvidence...)
	baseBody := string(baseResp.Body)

	confirmedValues := map[string]bool{}
	for _, v := range sstiVariants() {
		key := v.prefix + v.expected
		if _, already := confirmedValues[key]; already {
			continue
		}
		// A page that already renders this number in its baseline is not
		// evidence of template evaluation for this parameter.
		if strings.Contains(baseBody, v.expected) {
			continue
		}
		payload := v.prefix + v.expr + v.suffix
		attempt := sstiAttempt{Payload: truncate(payload, 200), Expected: v.expected, Kind: "template"}
		params = e.refreshParams(ctx, ep, params, focus)
		req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
		if err != nil {
			attempt.Status = 0
			d.Attempts = append(d.Attempts, attempt)
			continue
		}
		resp, respOutcome, _ := e.do(ctx, req)
		if resp != nil {
			attempt.Status = resp.Status
		}
		if respOutcome == domain.OutcomeSuccess && resp != nil {
			body := string(resp.Body)
			attempt.Output = strings.Contains(body, v.expected) && !strings.Contains(body, payload)
			ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "ssti "+v.expr)
			d.EvidenceIDs = append(d.EvidenceIDs, ev...)
		}
		d.Attempts = append(d.Attempts, attempt)
		if attempt.Output {
			confirmedValues[key] = true
		}
		if len(confirmedValues) >= 2 {
			break
		}
	}

	d.ConfirmedCount = len(confirmedValues)
	if d.ConfirmedCount >= 2 {
		d.Verdict = domain.VerdictConfirmed
		d.Reason = "two independent template expressions were evaluated by the server"
		e.persistSSTICase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed server-side template injection: two independent arithmetic expressions evaluated")
		e.correlateSSTI(ctx, job, ep, focus, d)
		return nil
	}
	note := "no server-side template evaluation observed"
	if d.ConfirmedCount == 1 {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one template marker was evaluated; a second independent marker is required"
		note = "one template marker observed; not enough to confirm"
	} else {
		d.Verdict = domain.VerdictRejected
	}
	e.persistSSTICase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
	return nil
}

func isSSTILocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationPath:
		return true
	default:
		return false
	}
}

func (e *sstiExecutor) persistSSTICase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sstiDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnSSTI,
		Status: status, Outcome: outcome, Method: string(ep.Method), URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("ssti: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *sstiExecutor) finishSSTIUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSSTI, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "ssti skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped ssti case: %w", err)
	}
	return nil
}

func (e *sstiExecutor) finishSSTIError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSSTI, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "ssti baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("ssti baseline failed: %s", msg)
}

func (e *sstiExecutor) correlateSSTI(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sstiDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnSSTI, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "Server-side template injection in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    "Two independent template expressions were evaluated by the server.",
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: sstiEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("ssti: persist finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueSSTIProbes queues one bounded job per eligible injection point.
func (c *Controller) enqueueSSTIProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableSSTI {
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
		if err != nil || ep == nil || !isSSTILocation(ip.Location) {
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
		if focus == nil || isDynamicTokenName(focus.Name) {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"endpoint_id": string(ep.ID), "parameter_id": string(focus.ID)})
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobSSTI,
			State: domain.JobQueued, Priority: 46, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("ssti: enqueue", "scan", scanID, "err", err)
		}
	}
}

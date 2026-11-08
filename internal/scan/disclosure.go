package scan

// Cases 38 and 39: information disclosure, decided from bytes the scan already
// knows about. No mutation, no submission: one GET per candidate, then the pure
// rules in internal/disclosure decide.
//
// The pass is bounded: it queues at most maxDisclosureProbes endpoints per scan,
// preferring the ones whose URL already suggests a debug page or a backup
// artefact, then the remaining discovered pages.

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/disclosure"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"log/slog"
)

const (
	disclosureEngine = "disclosure"
	// disclosureModeErrorProbe marks a job that re-requests one endpoint with a
	// wrong-typed value to make the application print its own stack trace (37).
	disclosureModeErrorProbe = "error_probe"
	// maxErrorProbes bounds the wrong-typed pass per scan.
	maxErrorProbes        = 20
	maxDisclosureProbes   = 40
	disclosurePriority    = 22
	disclosurePriorityHit = 20
)

// disclosureExecutor runs JobDisclosure jobs: one endpoint, one GET, one verdict.
type disclosureExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
}

func newDisclosureExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *disclosureExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &disclosureExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu}
}

// Handle implements worker.Handler.
func (e *disclosureExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnInfoDisclosure, Status: domain.TestCaseRunning, URL: job.Target.URL,
		StartedAt: &started, CreatedAt: started, UpdatedAt: started,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return err
	}

	target := job.Target.URL
	probeParam := ""
	if mode, param := disclosurePayload(job); mode == disclosureModeErrorProbe {
		probeParam = param
		if rewritten := wrongTypedURL(target, param); rewritten != "" {
			target = rewritten
		}
	}

	resp, err := e.fetch(ctx, target)
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	if err != nil {
		tc.Status, tc.Outcome = domain.TestCaseFailed, domain.OutcomeError
		tc.Error = truncate(err.Error(), 1024)
		_ = e.store.TestCases().Update(ctx, tc)
		return nil
	}
	tc.Method, tc.URL = "GET", target
	tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess

	var v disclosure.Verdict
	var ok bool
	if probeParam != "" {
		v, ok = disclosure.ClassifyError(resp.Status, resp.Headers.Get("Content-Type"), resp.Body, resp.Headers)
		if ok {
			v.Reason = "parameter " + probeParam + " with a wrong-typed value: " + v.Reason
		}
	} else {
		v, ok = disclosure.Classify(target, resp.Status, resp.Headers.Get("Content-Type"), resp.Body)
	}
	if ok {
		e.record(ctx, tc, resp, job.Target.URL, v)
	}
	// The crawler ignores commented-out markup and does not descend into an
	// open directory listing; both are exactly where a debug page and a backup
	// artefact live. Follow those links, bounded, and classify each response.
	followed := 0
	for _, href := range disclosure.CandidateLinks(resp.Body) {
		if followed >= maxDisclosureFollow {
			break
		}
		abs := resolveDisclosureLink(job.Target.URL, href)
		if abs == "" || !sameOrigin(job.Target.URL, abs) {
			continue
		}
		if !disclosure.LooksInteresting(abs) && !strings.HasSuffix(strings.ToLower(abs), "~") {
			continue
		}
		followed++
		sub, err := e.fetch(ctx, abs)
		if err != nil {
			continue
		}
		sv, sok := disclosure.Classify(abs, sub.Status, sub.Headers.Get("Content-Type"), sub.Body)
		if !sok {
			continue
		}
		e.record(ctx, tc, sub, abs, sv)
		ok = true
	}
	if !ok {
		tc.Note = "disclosure: nothing disclosed by this response"
	}
	_ = e.store.TestCases().Update(ctx, tc)
	return nil
}

// maxDisclosureFollow bounds the links one page may add.
const maxDisclosureFollow = 4

// record persists the evidence and the finding for one classified response.
func (e *disclosureExecutor) record(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, rawURL string, v disclosure.Verdict) {
	ids, evErr := e.persist(ctx, tc, resp, string(v.Kind))
	if evErr != nil {
		tc.Note = strings.TrimSpace(tc.Note + " | evidence incomplete: " + truncate(evErr.Error(), 200))
	}
	tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
	tc.Note = strings.TrimSpace(tc.Note + " disclosure: " + string(v.Kind) + " at " + rawURL + " (" + truncate(v.Reason, 200) + ")")
	e.correlate(ctx, &domain.TestJob{ScanID: tc.ScanID, Target: domain.JobTarget{URL: rawURL}}, tc, v)
}

// resolveDisclosureLink turns a page-relative href into an absolute URL.
func resolveDisclosureLink(base, href string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	h, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return b.ResolveReference(h).String()
}

// sameOrigin keeps the follow-ups inside the scanned origin.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ua.Scheme == ub.Scheme && ua.Host == ub.Host
}

func (e *disclosureExecutor) fetch(ctx context.Context, rawURL string) (*httpengine.Response, error) {
	req := httpengine.GET(rawURL)
	req.Timeout = e.cfg.RequestTimeout
	return e.engine.Do(ctx, req)
}

func (e *disclosureExecutor) persist(ctx context.Context, tc *domain.TestCase, resp *httpengine.Response, kind string) ([]domain.ID, error) {
	if e.evidence == nil || resp == nil {
		return nil, nil
	}
	var ids []domain.ID
	if resp.Request != nil {
		id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceRequest, ".http", "message/http",
			dumpRequest(resp.Request), "test_case="+string(tc.ID)+" disclosure "+kind+" request")
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	id, err := putEvidenceBlob(ctx, e.store, e.evidence, tc.ScanID, domain.EvidenceResponse, ".http", "message/http",
		dumpResponse(resp), "test_case="+string(tc.ID)+" disclosure "+kind+" response")
	if err != nil {
		return ids, err
	}
	return append(ids, id), nil
}

// correlate upserts one Confirmed finding per (class, URL family).
func (e *disclosureExecutor) correlate(ctx context.Context, job *domain.TestJob, tc *domain.TestCase, v disclosure.Verdict) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("load scan for disclosure finding", "scan", job.ScanID, "err", err)
		return
	}
	key := string(v.Kind) + "\x00" + tc.URL
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("list findings for disclosure correlation", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	severity := domain.SeverityMedium
	if v.Detail != "" {
		severity = domain.SeverityHigh
	}
	for _, f := range existing {
		if f.VulnClass != domain.VulnInfoDisclosure {
			continue
		}
		var fd disclosureDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey != key {
			continue
		}
		fd.Occurrences++
		fd.Reason = v.Reason
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, tc.EvidenceIDs)
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("update disclosure finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnInfoDisclosure,
		Verdict: domain.VerdictConfirmed, Severity: severity, Confidence: domain.ConfidenceHigh,
		Title:       titleForDisclosure(v.Kind),
		Summary:     v.Reason,
		EndpointID:  job.Target.EndpointID,
		EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: disclosureEngine, DiscoverySource: domain.SourceContentDiscovery, DetectedAt: now, AIAssisted: false},
		Detail:      encodeDisclosureDetail(v, tc.URL, key),
		CreatedAt:   now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("create disclosure finding", "scan", job.ScanID, "err", err)
	}
}

type disclosureDetail struct {
	Engine      string          `json:"engine"`
	Kind        disclosure.Kind `json:"kind"`
	URL         string          `json:"url"`
	DedupKey    string          `json:"dedup_key"`
	Occurrences int             `json:"occurrences"`
	Reason      string          `json:"reason"`
	Detail      string          `json:"detail,omitempty"`
}

func encodeDisclosureDetail(v disclosure.Verdict, rawURL, key string) []byte {
	b, _ := json.Marshal(disclosureDetail{Engine: disclosureEngine, Kind: v.Kind, URL: rawURL, DedupKey: key, Occurrences: 1, Reason: v.Reason, Detail: v.Detail})
	return b
}

func titleForDisclosure(k disclosure.Kind) string {
	switch k {
	case disclosure.KindDebugPage:
		return "Information disclosure: debug page exposes runtime configuration"
	case disclosure.KindBackupSource:
		return "Information disclosure: backup file serves source code"
	case disclosure.KindErrorDisclosure:
		return "Information disclosure: error message discloses a stack trace and framework version"
	}
	return "Information disclosure"
}

// enqueueDisclosureProbes queues the bounded passive pass: one job per candidate
// endpoint, name-suggestive URLs first.
func (c *Controller) enqueueDisclosureProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("disclosure probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	queued := 0
	queue := func(ep *domain.Endpoint, priority int) bool {
		if queued >= maxDisclosureProbes {
			return false
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobDisclosure, State: domain.JobQueued,
			Priority: priority, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			return true
		}
		queued++
		return true
	}
	var rest []*domain.Endpoint
	for _, ep := range endpoints {
		if ep.Method != domain.MethodGET {
			continue
		}
		if u, err := url.Parse(ep.URL); err != nil || u.RawQuery != "" {
			continue
		}
		if disclosure.LooksInteresting(ep.URL) {
			queue(ep, disclosurePriorityHit)
			continue
		}
		rest = append(rest, ep)
	}
	for _, ep := range rest {
		if !queue(ep, disclosurePriority) {
			break
		}
	}
	if queued > 0 {
		c.log.Info("disclosure probes: enqueued", "scan", scanID, "jobs", queued)
	}
}

// disclosurePayload reads the job's mode and parameter.
func disclosurePayload(job *domain.TestJob) (mode, param string) {
	var p struct {
		Mode  string `json:"mode"`
		Param string `json:"param"`
	}
	_ = json.Unmarshal(job.Payload, &p)
	return p.Mode, p.Param
}

// wrongTypedURL replaces one query parameter's value with a token of the wrong
// type. A numeric parameter fed a word is exactly what makes a Java/ASP.NET/PHP
// handler throw before it can answer politely.
func wrongTypedURL(rawURL, param string) string {
	if param == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return ""
	}
	q := u.Query()
	if _, ok := q[param]; !ok {
		return ""
	}
	q.Set(param, "indago-not-a-value")
	u.RawQuery = q.Encode()
	return u.String()
}

// enqueueDisclosureErrorProbes queues the wrong-typed pass: one job per GET
// endpoint whose query carries a numeric value, bounded.
func (c *Controller) enqueueDisclosureErrorProbes(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("error probes: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	n := 0
	for _, ep := range endpoints {
		if n >= maxErrorProbes {
			break
		}
		if ep.Method != domain.MethodGET {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || u.RawQuery == "" {
			continue
		}
		param := numericQueryParam(u)
		if param == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"mode": disclosureModeErrorProbe, "param": param})
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobDisclosure, State: domain.JobQueued,
			Priority: disclosurePriorityHit, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("error probes: enqueued", "scan", scanID, "jobs", n)
	}
}

// numericQueryParam returns the first query parameter whose value is a number:
// those are the ones a wrong-typed value crashes.
func numericQueryParam(u *url.URL) string {
	for k, vs := range u.Query() {
		if len(vs) == 0 || vs[0] == "" {
			continue
		}
		if _, err := strconv.Atoi(vs[0]); err == nil {
			return k
		}
	}
	return ""
}

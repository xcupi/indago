package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	maxPrototypePollutionEndpoints = 15
	prototypePollutionEngine       = "prototype_pollution"
	prototypePollutionEvalExpr     = `Boolean(Object.prototype && Object.prototype.indago_pp === "1")`
)

type prototypePollutionJob struct {
	EndpointID domain.ID `json:"endpoint_id"`
}

type prototypePollutionVector struct {
	name  string
	label string
	kind  string // "query" or "fragment"
	param string
}

var prototypePollutionVectors = []prototypePollutionVector{
	{
		name:  "query_proto",
		label: "query __proto__",
		kind:  "query",
		param: "__proto__[indago_pp]=1",
	},
	{
		name:  "query_constructor",
		label: "query constructor.prototype",
		kind:  "query",
		param: "constructor[prototype][indago_pp]=1",
	},
	{
		name:  "fragment_proto",
		label: "fragment __proto__",
		kind:  "fragment",
		param: "__proto__[indago_pp]=1",
	},
}

var prototypePollutionStaticExtensions = map[string]bool{
	".css":   true,
	".eot":   true,
	".gif":   true,
	".ico":   true,
	".jpeg":  true,
	".jpg":   true,
	".js":    true,
	".json":  true,
	".map":   true,
	".mjs":   true,
	".mp3":   true,
	".mp4":   true,
	".png":   true,
	".svg":   true,
	".ttf":   true,
	".txt":   true,
	".wasm":  true,
	".webp":  true,
	".woff":  true,
	".woff2": true,
	".xml":   true,
}

func isPrototypePollutionStaticAsset(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSuffix(u.Path, "/")))
	return prototypePollutionStaticExtensions[ext]
}

func isPrototypePollutionEligibleEndpoint(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	if ep.Method != domain.MethodGET && ep.Method != "" {
		return false
	}
	if !domXSSContentTypeAllowsDOM(ep.ContentType) {
		return false
	}
	if isDownloadLikeEndpoint(ep) || isPrototypePollutionStaticAsset(ep.URL) {
		return false
	}
	return true
}

func selectPrototypePollutionEndpoints(endpoints []*domain.Endpoint, limit int) []*domain.Endpoint {
	seen := make(map[string]bool, len(endpoints))
	var out []*domain.Endpoint
	for _, ep := range endpoints {
		if !isPrototypePollutionEligibleEndpoint(ep) || seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		out = append(out, ep)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func buildPrototypePollutionURL(rawURL string, vec prototypePollutionVector) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	switch vec.kind {
	case "query":
		if u.RawQuery == "" {
			u.RawQuery = vec.param
		} else {
			u.RawQuery += "&" + vec.param
		}
		u.Fragment = ""
	case "fragment":
		u.Fragment = vec.param
	default:
		return "", fmt.Errorf("unknown prototype pollution vector kind %q", vec.kind)
	}
	return u.String(), nil
}

// enqueuePrototypePollutionProbes enqueues one JobPrototypePollution per unique
// GET HTML-like endpoint URL (skipping static assets/downloads), capped at
// maxPrototypePollutionEndpoints.
func (c *Controller) enqueuePrototypePollutionProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		c.log.Warn("prototype_pollution probes: load scan", "scan", scanID, "err", err)
		return
	}
	if sc.Config.SkipPrototypePollution {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("prototype_pollution probes: list endpoints", "scan", scanID, "err", err)
		return
	}

	targets := selectPrototypePollutionEndpoints(endpoints, maxPrototypePollutionEndpoints)
	now := time.Now()
	enqueued := 0
	for _, ep := range targets {
		payload, err := json.Marshal(prototypePollutionJob{EndpointID: ep.ID})
		if err != nil {
			c.log.Warn("prototype_pollution probes: marshal job", "scan", scanID, "err", err)
			continue
		}
		job := &domain.TestJob{
			ID:          domain.NewID(),
			ScanID:      scanID,
			Type:        domain.JobPrototypePollution,
			State:       domain.JobQueued,
			Priority:    50,
			Target:      domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload:     payload,
			MaxAttempts: 2,
			AvailableAt: now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("prototype_pollution probes: enqueue job", "scan", scanID, "err", err)
			continue
		}
		enqueued++
	}
	if enqueued > 0 {
		c.log.Info("prototype_pollution probes: enqueued", "scan", scanID, "jobs", enqueued, "endpoints", len(targets))
	}
}

type prototypePollutionExecutor struct {
	store      store.Store
	browser    *browser.Manager
	evidence   evidence.Store
	wait       time.Duration
	log        *slog.Logger
	findingsMu *sync.Mutex
}

// newPrototypePollutionExecutor creates the worker.Handler for JobPrototypePollution.
func newPrototypePollutionExecutor(st store.Store, bm *browser.Manager, ev evidence.Store, wait time.Duration, log *slog.Logger, findingsMu *sync.Mutex) worker.Handler {
	if log == nil {
		log = slog.Default()
	}
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &prototypePollutionExecutor{
		store:      st,
		browser:    bm,
		evidence:   ev,
		wait:       wait,
		log:        log,
		findingsMu: findingsMu,
	}
}

func parsePrototypePollutionJob(job *domain.TestJob) (prototypePollutionJob, error) {
	if job == nil {
		return prototypePollutionJob{}, errors.New("prototype_pollution job is nil")
	}
	var pj prototypePollutionJob
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &pj); err != nil {
			return pj, fmt.Errorf("decode prototype_pollution job payload: %w", err)
		}
	}
	if pj.EndpointID.Empty() {
		pj.EndpointID = job.Target.EndpointID
	}
	if pj.EndpointID.Empty() {
		return pj, errors.New("prototype_pollution job payload missing endpoint_id")
	}
	return pj, nil
}

func (e *prototypePollutionExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	pj, err := parsePrototypePollutionJob(job)
	if err != nil {
		return fmt.Errorf("%w: %w", worker.ErrPermanent, err)
	}
	ep, err := e.store.Endpoints().Get(ctx, pj.EndpointID)
	if err != nil {
		return fmt.Errorf("%w: resolve endpoint: %w", worker.ErrPermanent, err)
	}
	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return fmt.Errorf("%w: load scan: %w", worker.ErrPermanent, err)
	}
	if sc.Config.SkipPrototypePollution {
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, "prototype_pollution skipped: disabled in scan config")
		return nil
	}
	if !isPrototypePollutionEligibleEndpoint(ep) {
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, "prototype_pollution skipped: endpoint is not a GET HTML-like document")
		return nil
	}
	if e.browser == nil {
		tc := e.newTestCase(ctx, job, ep.URL)
		tc.Status = domain.TestCaseSkipped
		e.finishTestCase(ctx, tc, nil, "prototype_pollution skipped: no browser configured")
		return nil
	}

	var allow func(string) bool
	var allowAuthority func(string) bool
	if scope, err := e.store.Scopes().GetByProject(ctx, sc.ProjectID); err == nil && scope != nil {
		if len(scope.IncludeHosts) > 0 || len(scope.SubdomainOnlyHosts) > 0 {
			allow = func(u string) bool { return scope.Permits(u).Allowed }
			allowAuthority = scope.PermitsHost
			if !allow(ep.URL) {
				return fmt.Errorf("%w: endpoint is out of scope", worker.ErrPermanent)
			}
		}
	}

	bctx, err := e.browser.NewContext(ctx, browser.ContextOptions{
		AllowRequest:      allow,
		AllowAuthority:    allowAuthority,
		StorageStatePath:  e.sessionStatePathFor(ctx, job.ScanID),
		IgnoreHTTPSErrors: sc.Config.AllowInsecureTLS,
	})
	if err != nil {
		return fmt.Errorf("prototype_pollution: create browser context: %w", err)
	}
	defer bctx.Close()

	for _, vec := range prototypePollutionVectors {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := e.probeVector(ctx, bctx, sc, job, ep, vec); err != nil {
			if isBrowserScopeBlocked(err) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (e *prototypePollutionExecutor) probeVector(ctx context.Context, bctx *browser.Context, sc *domain.Scan, job *domain.TestJob, ep *domain.Endpoint, vec prototypePollutionVector) error {
	probeURL, err := buildPrototypePollutionURL(ep.URL, vec)
	if err != nil {
		return fmt.Errorf("%w: build probe URL: %w", worker.ErrPermanent, err)
	}
	tc := e.newTestCase(ctx, job, probeURL)

	page, err := bctx.NewPage(ctx)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return err
	}
	defer page.Close()

	if _, err := page.Navigate(ctx, probeURL, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return err
	}
	if e.wait > 0 {
		if _, err := settleDOMXSSObservation(ctx, page, e.wait); err != nil {
			e.finishTestCase(ctx, tc, err, "")
			return err
		}
	}

	const evalScript = `(() => {
		const polluted = ` + prototypePollutionEvalExpr + `;
		if (Object.prototype && Object.prototype.indago_pp !== undefined) {
			try { delete Object.prototype.indago_pp; } catch (e) {}
		}
		return polluted;
	})()`
	rawRes, err := page.Evaluate(ctx, evalScript)
	if err != nil {
		e.finishTestCase(ctx, tc, err, "")
		return err
	}
	polluted, _ := rawRes.(bool)
	if !polluted {
		e.finishTestCase(ctx, tc, nil, fmt.Sprintf("prototype_pollution (%s): Object.prototype.indago_pp not polluted", vec.name))
		return nil
	}

	evID := e.persistProbeEvidence(ctx, job.ScanID, vec, ep.URL, probeURL, polluted)
	if !evID.Empty() {
		tc.EvidenceIDs = appendUniqueID(tc.EvidenceIDs, evID)
	}
	e.finishTestCase(ctx, tc, nil, fmt.Sprintf("prototype_pollution confirmed (%s): Object.prototype.indago_pp === \"1\"", vec.name))
	e.correlateFinding(ctx, sc, job, ep, tc, vec, probeURL)
	return nil
}

func (e *prototypePollutionExecutor) sessionStatePathFor(ctx context.Context, scanID domain.ID) string {
	sess, err := e.store.Sessions().GetByScan(ctx, scanID)
	if err != nil || sess == nil {
		return ""
	}
	return sess.StatePath
}

type prototypePollutionEvidence struct {
	Vector         string `json:"vector"`
	URL            string `json:"url"`
	ProbeURL       string `json:"probe_url"`
	EvalExpression string `json:"eval_expression"`
	JSEvalResult   bool   `json:"js_eval_result"`
}

func (e *prototypePollutionExecutor) persistProbeEvidence(ctx context.Context, scanID domain.ID, vec prototypePollutionVector, targetURL, probeURL string, result bool) domain.ID {
	if e.evidence == nil {
		return ""
	}
	payload, err := json.Marshal(prototypePollutionEvidence{
		Vector:         vec.name,
		URL:            targetURL,
		ProbeURL:       probeURL,
		EvalExpression: prototypePollutionEvalExpr,
		JSEvalResult:   result,
	})
	if err != nil {
		return ""
	}
	id, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceBrowserLog, ".json", "application/json", payload, fmt.Sprintf("prototype_pollution vector=%s", vec.name))
	if err != nil {
		e.log.Warn("prototype_pollution: persist evidence", "scan", scanID, "err", err)
		return ""
	}
	return id
}

type prototypePollutionDetail struct {
	Engine       string `json:"engine"`
	DedupKey     string `json:"dedup_key"`
	Vector       string `json:"vector"`
	URL          string `json:"url"`
	ProbeURL     string `json:"probe_url"`
	JSEvalResult bool   `json:"js_eval_result"`
	Occurrences  int    `json:"occurrences"`
}

func prototypePollutionDedupKey(endpointURL, vectorName string) string {
	return prototypePollutionEngine + "\x00" + endpointURL + "\x00" + vectorName
}

func (e *prototypePollutionExecutor) correlateFinding(ctx context.Context, sc *domain.Scan, job *domain.TestJob, ep *domain.Endpoint, tc *domain.TestCase, vec prototypePollutionVector, probeURL string) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()

	key := prototypePollutionDedupKey(ep.URL, vec.name)
	existing, err := e.store.Findings().ListByScan(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("prototype_pollution: list findings for correlation", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	for _, f := range existing {
		if f.VulnClass != domain.VulnPrototypePollution {
			continue
		}
		var fd prototypePollutionDetail
		if err := json.Unmarshal(f.Detail, &fd); err != nil || fd.DedupKey != key {
			continue
		}
		fd.Occurrences++
		fd.ProbeURL = probeURL
		if b, err := json.Marshal(fd); err == nil {
			f.Detail = b
		}
		f.EvidenceIDs = appendUniqueIDs(f.EvidenceIDs, tc.EvidenceIDs)
		f.UpdatedAt = now
		if err := e.store.Findings().Update(ctx, f); err != nil {
			e.log.Warn("prototype_pollution: update finding", "scan", job.ScanID, "err", err)
		}
		return
	}

	src := ep.Source
	if !src.IsValid() {
		src = domain.SourceBrowserNetwork
	}
	detail, _ := json.Marshal(prototypePollutionDetail{
		Engine:       prototypePollutionEngine,
		DedupKey:     key,
		Vector:       vec.name,
		URL:          ep.URL,
		ProbeURL:     probeURL,
		JSEvalResult: true,
		Occurrences:  1,
	})
	f := &domain.Finding{
		ID:          domain.NewID(),
		ScanID:      job.ScanID,
		ProjectID:   sc.ProjectID,
		VulnClass:   domain.VulnPrototypePollution,
		Verdict:     domain.VerdictConfirmed,
		Severity:    domain.SeverityHigh,
		Confidence:  domain.ConfidenceHigh,
		Title:       fmt.Sprintf("Client-side Prototype Pollution via %s", vec.label),
		Summary:     fmt.Sprintf("Navigating to %s polluted Object.prototype.indago_pp === \"1\" in the browser JavaScript runtime.", probeURL),
		EndpointID:  ep.ID,
		EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance: domain.Provenance{
			Engine:          prototypePollutionEngine,
			DiscoverySource: src,
			DetectedAt:      now,
			VerifiedAt:      &now,
		},
		Detail:    detail,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("prototype_pollution: create finding", "scan", job.ScanID, "err", err)
	}
}

func (e *prototypePollutionExecutor) newTestCase(ctx context.Context, job *domain.TestJob, rawURL string) *domain.TestCase {
	now := time.Now()
	tc := &domain.TestCase{
		ID:        domain.NewID(),
		ScanID:    job.ScanID,
		JobID:     job.ID,
		Attempt:   job.Attempts,
		VulnClass: domain.VulnPrototypePollution,
		Status:    domain.TestCaseRunning,
		Method:    string(domain.MethodGET),
		URL:       rawURL,
		StartedAt: &now,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("prototype_pollution: persist test case", "job", job.ID, "err", err)
	}
	return tc
}

func (e *prototypePollutionExecutor) finishTestCase(ctx context.Context, tc *domain.TestCase, probeErr error, note string) {
	now := time.Now()
	tc.FinishedAt, tc.UpdatedAt = &now, now
	if note != "" {
		tc.Note = note
	}
	switch {
	case tc.Status == domain.TestCaseSkipped:
	case probeErr == nil:
		tc.Status = domain.TestCaseCompleted
		tc.Outcome = domain.OutcomeSuccess
	case ctx.Err() != nil:
		tc.Status = domain.TestCaseCancelled
		tc.Outcome = domain.OutcomeCancelled
	case browser.IsTimeout(probeErr):
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeTimeout
		tc.Error = truncate(probeErr.Error(), 1024)
	default:
		tc.Status = domain.TestCaseFailed
		tc.Outcome = domain.OutcomeError
		tc.Error = truncate(probeErr.Error(), 1024)
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := e.store.TestCases().Update(wctx, tc); err != nil {
		e.log.Error("prototype_pollution: persist test case result", "test_case", tc.ID, "job", tc.JobID, "err", err)
	}
}

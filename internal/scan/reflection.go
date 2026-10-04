package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// injection selects one parameter to carry a marker value; all other parameters
// keep their observed values.
type injection struct {
	param *domain.Parameter
	value string
}

// maxBaselineBodyKeep caps the baseline body retained for the token-absence
// check, bounding the per-scan baseline cache. Reflection analysis itself uses
// the full mutated response, not this copy.
const maxBaselineBodyKeep = 256 << 10

// runReflection performs the first Reflected XSS detection step for one injection
// point: it reuses the endpoint baseline, sends a mutated request carrying a
// unique marker in the selected parameter only, and records whether — and how —
// the marker is reflected. It makes NO verdict.
func (e *executor) runReflection(ctx context.Context, tc *domain.TestCase, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter) result {
	tc.VulnClass = domain.VulnReflectedXSS
	note := fmt.Sprintf("reflection; parameter %s (%s)", focus.Name, focus.Location)

	// Baseline (shared across this endpoint's injection points).
	baseReq, err := buildRequest(ep, params, nil)
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: note, vulnClass: domain.VulnReflectedXSS}
	}
	bl, outcome, err := e.baseline(ctx, tc.ScanID, baseReq)
	if outcome != domain.OutcomeSuccess {
		// The baseline could not be established: report that execution outcome;
		// reflection was not attempted.
		return result{
			outcome:   outcome,
			permanent: outcome == domain.OutcomeError && isPermanentRequestError(err),
			err:       err,
			note:      note + " (baseline failed)",
			vulnClass: domain.VulnReflectedXSS,
		}
	}

	// Mutated request: the marker goes only into the focused parameter.
	probe := detection.NewProbe(tc.ScanID, tc.InjectionPointID)
	mutReq, err := buildRequest(ep, params, &injection{param: focus, value: probe.Value()})
	if err != nil {
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: note, vulnClass: domain.VulnReflectedXSS, sharedEvidence: bl.evidenceIDs()}
	}
	tc.URL = mutReq.URL

	resp, outcome, err, dur := e.send(ctx, mutReq)
	r := result{
		note:           note,
		duration:       dur,
		vulnClass:      domain.VulnReflectedXSS,
		req:            capturedFrom(mutReq, resp),
		resp:           resp,
		sharedEvidence: bl.evidenceIDs(),
	}
	if outcome != domain.OutcomeSuccess {
		r.outcome = outcome
		r.err = err
		r.permanent = outcome == domain.OutcomeError && isPermanentRequestError(err)
		return r
	}

	// Analyze reflection (pure): baseline body is used only for the token-absence
	// sanity check; the full mutated body is searched for the marker.
	report := detection.AnalyzeReflection(probe, bl.body, resp.Body)
	report.Parameter = focus.Name
	report.Location = focus.Location
	report.Baseline = detection.ResponseSummary{Status: bl.status, BodyLen: bl.bodyLen}
	report.Mutated = detection.ResponseSummary{Status: resp.Status, BodyLen: len(resp.Body)}

	// Context analysis (pure): classify every reflection site against the actual
	// response bytes. Still no verdict.
	detection.ClassifyContexts(&report, resp.Body, detection.ContextOptions{
		ContentType: resp.Headers.Get("Content-Type"),
	})

	// Candidate planning (pure): derive the ordered, deduplicated breakout
	// candidates for each site from its context and observed transformation. This
	// is planning only — nothing is sent here and no verdict is made; candidate
	// execution and verification are later, separately-gated phases.
	detection.PlanCandidates(&report, detection.PlanOptions{
		ScanID:           tc.ScanID,
		InjectionPointID: tc.InjectionPointID,
	})

	r.outcome = domain.OutcomeSuccess
	if report.Reflected {
		r.note = fmt.Sprintf("%s: reflected at %d location(s); %s", note, report.Count, contextSummary(&report))
		if n := len(report.Plan.Candidates); n > 0 {
			r.note += fmt.Sprintf("; planned %d candidate(s)", n)
		}
	} else {
		r.note = note + ": not reflected"
	}
	r.reflection = &report
	r.baselineReq, r.baselineResp = bl.reqEvidence, bl.respEvidence
	return r
}

// contextSummary renders the distinct site contexts, e.g. "context: html_text, js_string".
func contextSummary(rep *detection.ReflectionReport) string {
	var out []string
	seen := map[detection.Context]bool{}
	for _, l := range rep.Locations {
		if l.Context != nil && !seen[l.Context.Context] {
			seen[l.Context.Context] = true
			out = append(out, string(l.Context.Context))
		}
	}
	return "context: " + strings.Join(out, ", ")
}

// finalizeReflection attaches the evidence references to the report — including
// the response body's offset inside the response evidence blob, so every site
// offset maps to an exact byte — and stores it in TestCase.Detail.
//
// own holds this attempt's persisted evidence IDs: [request] or [request, response].
func (e *executor) finalizeReflection(tc *domain.TestCase, r result, own []domain.ID) {
	ev := detection.ReflectionEvidence{BaselineRequest: r.baselineReq, BaselineResponse: r.baselineResp}
	if len(own) >= 1 {
		ev.MutatedRequest = own[0]
	}
	if r.resp != nil {
		if len(own) >= 2 {
			ev.MutatedResponse = own[1]
		}
		// The response blob is "status line + headers + blank line + body", so the
		// body starts where the dump is longer than the body alone.
		ev.MutatedBodyOffset = len(dumpResponse(r.resp)) - len(r.resp.Body)
	}
	r.reflection.Evidence = ev

	detail, err := json.Marshal(r.reflection)
	if err != nil {
		e.log.Warn("marshal reflection report", "job", tc.JobID, "err", err)
		return
	}
	tc.Detail = detail
}

// ---------------------------------------------------------------------------
// baseline cache (reuse one baseline per endpoint across its injection points)
// ---------------------------------------------------------------------------

type baselineEntry struct {
	status       int
	bodyLen      int
	body         []byte    // capped copy for the token-absence check
	reqEvidence  domain.ID // shared baseline request evidence (empty if not stored)
	respEvidence domain.ID // shared baseline response evidence (empty if not stored)
}

// evidenceIDs returns the baseline's stored evidence IDs that exist.
func (b *baselineEntry) evidenceIDs() []domain.ID {
	var ids []domain.ID
	if b.reqEvidence != "" {
		ids = append(ids, b.reqEvidence)
	}
	if b.respEvidence != "" {
		ids = append(ids, b.respEvidence)
	}
	return ids
}

type baselineCache struct {
	mu         sync.Mutex
	entries    map[string]*baselineEntry
	order      []string
	maxEntries int
}

func newBaselineCache() *baselineCache {
	return &baselineCache{entries: make(map[string]*baselineEntry), maxEntries: 2048}
}

func (c *baselineCache) lookup(key string) (*baselineEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

// store records an entry, returning the already-stored winner if one exists (so
// a concurrent duplicate fetch is harmless — callers adopt the shared result).
func (c *baselineCache) store(key string, e *baselineEntry) *baselineEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		return existing
	}
	if len(c.order) >= c.maxEntries {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[key] = e
	c.order = append(c.order, key)
	return e
}

// baseline returns the endpoint's baseline, fetching and caching it on first use.
// A successful baseline is cached (and its evidence persisted once); a failed
// baseline is not cached, so a later injection point may retry.
func (e *executor) baseline(ctx context.Context, scanID domain.ID, req *httpengine.Request) (*baselineEntry, domain.TestOutcome, error) {
	key := baselineKey(req)
	if entry, ok := e.baselines.lookup(key); ok {
		return entry, domain.OutcomeSuccess, nil
	}

	resp, outcome, err, _ := e.send(ctx, req)
	if outcome != domain.OutcomeSuccess {
		return nil, outcome, err
	}

	entry := &baselineEntry{
		status:  resp.Status,
		bodyLen: len(resp.Body),
		body:    capBody(resp.Body, maxBaselineBodyKeep),
	}
	if e.evidence != nil {
		entry.reqEvidence, entry.respEvidence = e.persistBaselineEvidence(ctx, scanID, req, resp)
	}
	return e.baselines.store(key, entry), domain.OutcomeSuccess, nil
}

// persistBaselineEvidence stores the baseline request+response once, scan-scoped
// so it can be shared across the endpoint's injection points. It uses a detached
// context so a single job's cancellation cannot corrupt the shared cache entry.
func (e *executor) persistBaselineEvidence(ctx context.Context, scanID domain.ID, req *httpengine.Request, resp *httpengine.Response) (reqID, respID domain.ID) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	note := "baseline " + req.Method + " " + req.URL
	if id, err := e.putEvidence(wctx, scanID, domain.EvidenceRequest, dumpRequest(capturedFrom(req, resp)), note+" request"); err == nil {
		reqID = id
	} else {
		e.log.Warn("persist baseline request evidence", "err", err)
	}
	respNote := note + " response"
	if resp.Truncated {
		respNote += " (body truncated at the engine's size cap)"
	}
	if id, err := e.putEvidence(wctx, scanID, domain.EvidenceResponse, dumpResponse(resp), respNote); err == nil {
		respID = id
	} else {
		e.log.Warn("persist baseline response evidence", "err", err)
	}
	return reqID, respID
}

func baselineKey(req *httpengine.Request) string {
	sum := sha256.Sum256(req.Body)
	return req.Method + "\x00" + req.URL + "\x00" + req.ContentType + "\x00" + hex.EncodeToString(sum[:])
}

func capBody(b []byte, max int) []byte {
	if len(b) <= max {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	out := make([]byte, max)
	copy(out, b[:max])
	return out
}

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		return result{outcome: domain.OutcomeError, permanent: true, err: err, note: note, vulnClass: domain.VulnReflectedXSS, sharedEvidence: bl.evidence}
	}
	tc.URL = mutReq.URL

	resp, outcome, err, dur := e.send(ctx, mutReq)
	r := result{
		note:           note,
		duration:       dur,
		vulnClass:      domain.VulnReflectedXSS,
		req:            capturedFrom(mutReq, resp),
		resp:           resp,
		sharedEvidence: bl.evidence,
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

	r.outcome = domain.OutcomeSuccess
	if report.Reflected {
		r.note = fmt.Sprintf("%s: reflected at %d location(s)", note, report.Count)
	} else {
		r.note = note + ": not reflected"
	}
	if detail, err := json.Marshal(report); err == nil {
		r.detail = detail
	} else {
		e.log.Warn("marshal reflection report", "job", tc.JobID, "err", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// baseline cache (reuse one baseline per endpoint across its injection points)
// ---------------------------------------------------------------------------

type baselineEntry struct {
	status   int
	bodyLen  int
	body     []byte      // capped copy for the token-absence check
	evidence []domain.ID // shared baseline request+response evidence (may be nil)
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
		entry.evidence = e.persistBaselineEvidence(ctx, scanID, req, resp)
	}
	return e.baselines.store(key, entry), domain.OutcomeSuccess, nil
}

// persistBaselineEvidence stores the baseline request+response once, scan-scoped
// so it can be shared across the endpoint's injection points. It uses a detached
// context so a single job's cancellation cannot corrupt the shared cache entry.
func (e *executor) persistBaselineEvidence(ctx context.Context, scanID domain.ID, req *httpengine.Request, resp *httpengine.Response) []domain.ID {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	note := "baseline " + req.Method + " " + req.URL
	var ids []domain.ID
	if id, err := e.putEvidence(wctx, scanID, domain.EvidenceRequest, dumpRequest(capturedFrom(req, resp)), note+" request"); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("persist baseline request evidence", "err", err)
	}
	respNote := note + " response"
	if resp.Truncated {
		respNote += " (body truncated at the engine's size cap)"
	}
	if id, err := e.putEvidence(wctx, scanID, domain.EvidenceResponse, dumpResponse(resp), respNote); err == nil {
		ids = append(ids, id)
	} else {
		e.log.Warn("persist baseline response evidence", "err", err)
	}
	return ids
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

package scan

// This file implements BOUNDED, deterministic multi-parameter (combined)
// reflected-XSS candidate testing — see docs/reflection-candidates.md
// "Combined (multi-parameter) candidates" for the full design and scope.
//
// It is a FALLBACK probe, never a parallel always-on path: it runs exactly
// ONCE per scan execution, after the scan's ordinary single-parameter
// testing has fully drained (see execution.go's combinedPassDone/evaluate),
// and only at an endpoint where single-parameter testing did NOT already
// produce a Confirmed finding. It considers only PAIRS (never triples+) of
// parameters that (a) both individually reflected during single-parameter
// candidate testing — read directly from the Findings that testing already
// recorded; this never re-detects reflection — and (b) landed in the SAME
// classified context (html_attr_value or js_string — the only two combined
// templates this piece implements; see internal/detection/combined.go). A
// hard, deterministic ceiling (maxCombinedPairsPerEndpoint) bounds how many
// pairs are ever tested per endpoint, mirroring the candidate-profile
// ceiling pattern (minimal/standard/thorough, ceiling 32) as precedent for
// "bounded by design, not unlimited" — this is not an open-ended
// combinatorial fuzzer.

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// maxCombinedPairsPerEndpoint is the hard ceiling on how many combined
// (two-parameter) candidate pairs are ever tested at one endpoint, however
// many same-context parameter pairs are theoretically possible there.
const maxCombinedPairsPerEndpoint = 5

// reflectedSite is one parameter the scan's own single-parameter candidate
// testing already found reflecting into a specific context — derived
// purely from the Findings the scan already recorded (never a fresh
// reflection probe).
type reflectedSite struct {
	injectionPointID domain.ID
	parameterName    string
	location         domain.ParamLocation
	context          detection.Context
	contextSub       string
}

// combinedPair is two reflectedSites sharing the same context, selected to
// be planned as one combined candidate.
type combinedPair struct {
	a, b    reflectedSite
	context detection.Context
}

// enqueueCombinedCandidates is the one-time, scan-wide combined-candidate
// pass (see execution.go's combinedPassDone). Best-effort throughout:
// anything that fails to resolve is logged and skipped, never fatal — this
// is a bounded, optional fallback probe, not a precondition for the scan to
// complete.
func (c *Controller) enqueueCombinedCandidates(ctx context.Context, scanID domain.ID) {
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("combined candidates: list endpoints", "scan", scanID, "err", err)
		return
	}
	findings, err := c.store.Findings().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("combined candidates: list findings", "scan", scanID, "err", err)
		return
	}
	byEndpoint := map[domain.ID][]*domain.Finding{}
	for _, f := range findings {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		byEndpoint[f.EndpointID] = append(byEndpoint[f.EndpointID], f)
	}

	n := 0
	for _, ep := range endpoints {
		epFindings := byEndpoint[ep.ID]
		if len(epFindings) == 0 || endpointHasConfirmed(epFindings) {
			continue // requirement: fallback only where single-param testing did NOT confirm
		}
		pairs := selectCombinedPairs(reflectedSitesFor(epFindings))
		for _, pr := range pairs {
			c.enqueueOneCombinedCandidate(ctx, scanID, ep, pr)
			n++
		}
	}
	if n > 0 {
		c.log.Info("combined candidates: enqueued", "scan", scanID, "pairs", n)
	}
}

// endpointHasConfirmed reports whether any (non-combined or combined)
// Reflected XSS finding at this endpoint is already Confirmed — the
// requirement B gate: combined pairing is a fallback for an endpoint
// single-parameter testing could not crack, never a parallel always-on path.
func endpointHasConfirmed(findings []*domain.Finding) bool {
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			return true
		}
	}
	return false
}

// reflectedSitesFor derives one reflectedSite per ordinary (non-diagnostic,
// non-already-combined) Finding at the endpoint — each such Finding IS
// exactly one parameter reflecting into one context (see findingDedupKey),
// so this is a direct read of what single-parameter testing already
// established, never a fresh reflection probe.
func reflectedSitesFor(findings []*domain.Finding) []reflectedSite {
	var out []reflectedSite
	for _, f := range findings {
		d := decodeFindingDetail(f.Detail)
		if d.BlockSuspected || d.CaptchaSuspected || d.Combined || len(d.Candidates) == 0 {
			continue
		}
		cand := d.Candidates[0]
		if cand.Combined || f.InjectionPointID.Empty() {
			continue
		}
		out = append(out, reflectedSite{
			injectionPointID: f.InjectionPointID,
			parameterName:    d.ParameterName,
			location:         f.Location,
			context:          cand.Context,
			contextSub:       cand.ContextSub,
		})
	}
	return out
}

// selectCombinedPairs groups sites by the two supported combined contexts
// and forms every distinct pair within each group, in a fully deterministic
// order (by parameter name, then injection point ID — not discovery
// timestamps, which this layer never sees), truncated at
// maxCombinedPairsPerEndpoint. Only CtxHTMLAttrValue and CtxJSString are
// considered — every other context is out of scope for this piece.
func selectCombinedPairs(sites []reflectedSite) []combinedPair {
	groups := map[detection.Context][]reflectedSite{}
	for _, s := range sites {
		switch s.context {
		case detection.CtxHTMLAttrValue, detection.CtxJSString:
			groups[s.context] = append(groups[s.context], s)
		}
	}

	var ctxNames []string
	for k := range groups {
		ctxNames = append(ctxNames, string(k))
	}
	sort.Strings(ctxNames)

	var pairs []combinedPair
	for _, cn := range ctxNames {
		grp := groups[detection.Context(cn)]
		sort.Slice(grp, func(i, j int) bool {
			if grp[i].parameterName != grp[j].parameterName {
				return grp[i].parameterName < grp[j].parameterName
			}
			return grp[i].injectionPointID < grp[j].injectionPointID
		})
		for i := 0; i < len(grp); i++ {
			for j := i + 1; j < len(grp); j++ {
				if grp[i].injectionPointID == grp[j].injectionPointID {
					continue // never pair a site with itself
				}
				pairs = append(pairs, combinedPair{a: grp[i], b: grp[j], context: detection.Context(cn)})
			}
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].context != pairs[j].context {
			return pairs[i].context < pairs[j].context
		}
		if pairs[i].a.parameterName != pairs[j].a.parameterName {
			return pairs[i].a.parameterName < pairs[j].a.parameterName
		}
		return pairs[i].b.parameterName < pairs[j].b.parameterName
	})
	if len(pairs) > maxCombinedPairsPerEndpoint {
		pairs = pairs[:maxCombinedPairsPerEndpoint]
	}
	return pairs
}

// enqueueOneCombinedCandidate plans the combined candidate for pr (pure,
// deterministic — see detection.PlanCombinedCandidate) and enqueues it as an
// ordinary JobTest carrying it in the SAME candidateJob payload shape a
// single-parameter candidate already uses: the executor dispatches on
// cand.Combined, so no new job Type or worker wiring is needed.
func (c *Controller) enqueueOneCombinedCandidate(ctx context.Context, scanID domain.ID, ep *domain.Endpoint, pr combinedPair) {
	marker := detection.NewProbe(scanID, pr.a.injectionPointID).Token
	cand, ok := detection.PlanCombinedCandidate(pr.context, pr.a.contextSub, marker)
	if !ok {
		return
	}
	cand.ScanID = scanID
	cand.InjectionPointID = pr.a.injectionPointID
	cand.Parameter = pr.a.parameterName
	cand.Location = pr.a.location
	cand.InjectionPointBID = pr.b.injectionPointID
	cand.ParameterB = pr.b.parameterName
	cand.LocationB = pr.b.location

	payload, err := json.Marshal(candidateJob{Candidate: *cand})
	if err != nil {
		c.log.Warn("combined candidates: marshal job", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	job := &domain.TestJob{
		ID:       domain.NewID(),
		ScanID:   scanID,
		Type:     domain.JobTest,
		State:    domain.JobQueued,
		Priority: cand.Priority,
		Target:   domain.JobTarget{EndpointID: ep.ID, InjectionPointID: pr.a.injectionPointID},
		Payload:  payload, MaxAttempts: 3,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := c.queue.Enqueue(ctx, job); err != nil {
		c.log.Warn("combined candidates: enqueue job", "scan", scanID, "err", err)
	}
}

// findParamByNameLocation finds a combined candidate's SECOND parameter
// within an already-loaded endpoint parameter list, by the name+location
// the candidate itself carries (ParameterB/LocationB) — no extra store
// round trip, since both halves of a combined pair always belong to the
// SAME endpoint (see selectCombinedPairs).
func findParamByNameLocation(params []*domain.Parameter, name string, loc domain.ParamLocation) *domain.Parameter {
	for _, p := range params {
		if p.Name == name && p.Location == loc {
			return p
		}
	}
	return nil
}

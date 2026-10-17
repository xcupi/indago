package detection

import (
	"fmt"
	"sort"
)

// Candidate profiles bound how many of the planner's candidates are actually
// SENT per injection point. They SELECT from what the existing context
// classification and transformation analysis already produced — they never
// add, rewrite, or encode a candidate, and they have no effect on what counts
// as confirmed (that stays the browser verifier's deterministic signal).
//
// Selection is a pure, deterministic function of the plan: the same plan and
// profile always select the same candidates in the same order, so a re-planned
// reflection step (a retry) enqueues the same jobs.

// CandidateProfile names a selection policy.
type CandidateProfile string

const (
	// ProfileMinimal sends only candidates that can fire on page load (the
	// only kind passive verification can confirm), skips ones the site is
	// known to neutralize, and sends at most 3 per injection point.
	ProfileMinimal CandidateProfile = "minimal"
	// ProfileStandard is the default: every built-in candidate, at most 8 per
	// injection point.
	ProfileStandard CandidateProfile = "standard"
	// ProfileThorough is every built-in candidate, at most 16 per injection
	// point.
	ProfileThorough CandidateProfile = "thorough"
)

// MaxCandidatesCeiling is the hard upper bound on any per-injection-point
// candidate count, including an operator override, so a typo cannot turn a
// scan into a high-volume request generator against one parameter (AGENTS.md
// §2.3–2.4).
const MaxCandidatesCeiling = 32

// IsValid reports whether p is a known profile.
func (p CandidateProfile) IsValid() bool {
	switch p {
	case ProfileMinimal, ProfileStandard, ProfileThorough:
		return true
	}
	return false
}

// ProfileSpec is a resolved selection policy. The zero value is "no bound, no
// filtering" — the planner's behaviour before profiles existed — which keeps
// direct PlanCandidates callers unchanged.
type ProfileSpec struct {
	Name CandidateProfile `json:"name,omitempty"`
	// MaxPerInjectionPoint caps the candidates selected across ALL of an
	// injection point's reflection sites (0 = unbounded).
	MaxPerInjectionPoint int `json:"max_per_injection_point,omitempty"`
	// LoadTriggerOnly drops candidates that cannot fire on page load
	// (Trigger != TriggerLoad): they need a user action the verifier never
	// simulates, or carry no executable reference at all.
	LoadTriggerOnly bool `json:"load_trigger_only,omitempty"`
	// SkipNeutralized drops candidates whose required characters the site
	// encodes or strips (Transformation != "raw").
	SkipNeutralized bool `json:"skip_neutralized,omitempty"`
}

// ResolveProfile turns a profile name and optional per-injection-point cap
// into a ProfileSpec. An empty name means ProfileStandard. A positive max
// overrides the profile's cap; it must not exceed MaxCandidatesCeiling.
func ResolveProfile(name string, max int) (ProfileSpec, error) {
	p := CandidateProfile(name)
	if p == "" {
		p = ProfileStandard
	}
	var spec ProfileSpec
	switch p {
	case ProfileMinimal:
		spec = ProfileSpec{Name: p, MaxPerInjectionPoint: 3, LoadTriggerOnly: true, SkipNeutralized: true}
	case ProfileStandard:
		spec = ProfileSpec{Name: p, MaxPerInjectionPoint: 8}
	case ProfileThorough:
		spec = ProfileSpec{Name: p, MaxPerInjectionPoint: 16}
	default:
		return ProfileSpec{}, fmt.Errorf("unknown candidate profile %q (want minimal, standard, or thorough)", name)
	}
	if max < 0 || max > MaxCandidatesCeiling {
		return ProfileSpec{}, fmt.Errorf("max candidates must be between 0 and %d", MaxCandidatesCeiling)
	}
	if max > 0 {
		spec.MaxPerInjectionPoint = max
	}
	return spec, nil
}

// Select applies the profile to a plan's candidates and returns the selected
// ones in the planner's deterministic order, plus how many were dropped.
//
// Order of operations:
//  1. Filters (LoadTriggerOnly, SkipNeutralized). A reflection context left
//     with NO candidate by the filters keeps its single best original
//     candidate: a reflected-but-neutralized or interaction-only site is still
//     tried once, so it ends as a documented, rejected attempt rather than
//     silently vanishing.
//  2. The cap. Candidates are taken in plan order, one per distinct reflection
//     context first (so a cap never starves a second context at the same
//     injection point), then by plan order until the cap is reached.
func (s ProfileSpec) Select(all []Candidate) (selected []Candidate, dropped int) {
	if len(all) == 0 {
		return nil, 0
	}
	ordered := append([]Candidate(nil), all...)
	sort.SliceStable(ordered, func(i, j int) bool { return lessCandidate(ordered[i], ordered[j]) })

	keep := make([]Candidate, 0, len(ordered))
	for _, c := range ordered {
		if s.LoadTriggerOnly && c.Trigger != TriggerLoad {
			continue
		}
		if s.SkipNeutralized && c.Transformation != "raw" {
			continue
		}
		keep = append(keep, c)
	}
	if s.LoadTriggerOnly || s.SkipNeutralized {
		have := map[Context]bool{}
		for _, c := range keep {
			have[c.Context] = true
		}
		for _, c := range ordered { // best-first, so the first per context is its best
			if !have[c.Context] {
				have[c.Context] = true
				keep = append(keep, c)
			}
		}
		sort.SliceStable(keep, func(i, j int) bool { return lessCandidate(keep[i], keep[j]) })
	}

	if s.MaxPerInjectionPoint > 0 && len(keep) > s.MaxPerInjectionPoint {
		chosen := make([]bool, len(keep))
		n := 0
		seenCtx := map[Context]bool{}
		for i, c := range keep { // pass 1: one per context, best first
			if n == s.MaxPerInjectionPoint {
				break
			}
			if !seenCtx[c.Context] {
				seenCtx[c.Context] = true
				chosen[i] = true
				n++
			}
		}
		for i := range keep { // pass 2: fill by plan order
			if n == s.MaxPerInjectionPoint {
				break
			}
			if !chosen[i] {
				chosen[i] = true
				n++
			}
		}
		capped := make([]Candidate, 0, n)
		for i, c := range keep {
			if chosen[i] {
				capped = append(capped, c)
			}
		}
		keep = capped
	}
	return keep, len(all) - len(keep)
}

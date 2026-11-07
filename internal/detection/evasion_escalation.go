package detection

// EvasionEscalationCandidates returns the bounded, deterministic
// filter-bypass fallback candidates for one already-classified reflection.
//
// It is a SECOND pass, never a replacement: a report with no persisted
// canonical plan is ineligible, because nothing established that the canonical
// candidates were planned (and therefore tried) first.
//
// It deliberately plans against a shallow snapshot: callers persist the
// canonical plan in the original report as the evidence for why escalation
// became eligible, and discovering the fallback must never rewrite that
// evidence. Only Candidate.Technique entries are returned. Variation packs are
// separate mechanism coverage, not filter-bypass techniques, and therefore do
// not widen this automatic one-pass escalation.
func EvasionEscalationCandidates(rep *ReflectionReport, opts PlanOptions) []Candidate {
	if rep == nil || !rep.Reflected || rep.Plan == nil {
		return nil
	}

	// Reuse the exact established evasion planner so this path inherits its
	// character-survival checks, transformation-aware priority and profile
	// behavior. PlanCandidates currently co-enables variation packs with
	// EnableEvasion; filter those back out below because the automatic fallback
	// is deliberately the documented Technique set only.
	snapshot := *rep
	if opts.ScanID.Empty() || opts.InjectionPointID.Empty() {
		return nil
	}
	// Candidate execution re-derives its marker from the live scan and
	// injection-point IDs. Do the same here instead of trusting a stale or
	// externally persisted Plan.Marker, otherwise re-analysis could not
	// attribute the fallback response to this exact candidate.
	plannerOpts := opts
	plannerOpts.Marker = NewProbe(opts.ScanID, opts.InjectionPointID).Token
	plannerOpts.EnableEvasion = true
	plannerOpts.EnableVariationPacks = false
	// Enumerate the full fixed technique table first, then apply the automatic
	// path's profile filters below and finally its independent hard cap. Using
	// PlanCandidates with opts.Profile here would cap before filtering, letting
	// interaction-only entries consume slots minimal deliberately rejects.
	plannerOpts.Profile = ProfileSpec{}
	plan := PlanCandidates(&snapshot, plannerOpts)
	if plan == nil {
		return nil
	}

	out := make([]Candidate, 0, MaxEvasionCandidatesPerInjectionPoint)
	for _, cand := range plan.Candidates {
		if cand.Technique == "" || cand.Variation != "" || cand.Combined {
			continue
		}
		// The automatic fallback must preserve the selected scan profile.
		// PlanCandidates' explicit-evasion compatibility path deliberately
		// restores technique candidates beyond a profile cap; doing that here
		// would silently undo minimal's load-only/neutralized filters.
		if opts.Profile.LoadTriggerOnly && cand.Trigger != TriggerLoad {
			continue
		}
		if opts.Profile.SkipNeutralized && cand.Transformation != "raw" {
			continue
		}
		out = append(out, cand)
		if len(out) == MaxEvasionCandidatesPerInjectionPoint {
			break
		}
	}
	return out
}

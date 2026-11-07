package detection_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// Automatic escalation is deliberately a second, evidence-gated pass.  It must
// expose only the existing bounded filter-bypass techniques; canonical output
// remains unchanged until the scan layer has established that the canonical
// attempts did not confirm.
func TestEvasionEscalationCandidatesAreBoundedTechniqueOnlyAndDoNotMutateCanonicalPlan(t *testing.T) {
	const marker = "indagoescalationmarker"
	body := []byte("<p>indago-probe-" + marker + "</p>")

	// Use the real probe format so context analysis sees an actual reflection.
	probe := detection.NewProbe(domain.ID("escalation-scan"), domain.ID("escalation-ip"))
	body = []byte("<p>" + probe.Value() + "</p>")
	rep := detection.AnalyzeReflection(probe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	opts := detection.PlanOptions{
		ScanID:           domain.ID("escalation-scan"),
		InjectionPointID: domain.ID("escalation-ip"),
		Profile:          detection.ProfileSpec{Name: detection.ProfileStandard, MaxPerInjectionPoint: 8},
	}
	canonical := detection.PlanCandidates(&rep, opts)
	canonicalBefore := append([]detection.Candidate(nil), canonical.Candidates...)

	got := detection.EvasionEscalationCandidates(&rep, opts)
	if len(got) == 0 {
		t.Fatal("automatic escalation returned no bypass candidates for an HTML-text reflection")
	}
	if len(got) > detection.MaxEvasionCandidatesPerInjectionPoint {
		t.Fatalf("automatic escalation planned %d candidates, ceiling is %d", len(got), detection.MaxEvasionCandidatesPerInjectionPoint)
	}
	for _, cand := range got {
		if cand.Technique == "" {
			t.Fatalf("automatic escalation emitted non-evasion candidate: %+v", cand)
		}
		if cand.Variation != "" {
			t.Fatalf("automatic escalation emitted variation-pack candidate %q; this pass is limited to documented evasion techniques", cand.Variation)
		}
		// Boundary that must not move: every extra shape is still only the
		// injection point's own benign marker, never an exploit payload.
		if !strings.Contains(cand.Value, probe.Token) {
			t.Fatalf("automatic escalation candidate %q does not carry the benign probe marker %q", cand.Value, probe.Token)
		}
	}

	// Labs 8–11 each need one of these documented bypass families. The fallback
	// ceiling cannot silently trim any of them.
	wantTechniques := map[string]bool{
		"allowlisted_tag_event": false,
		"custom_element_focus":  false,
		"svg_smil_begin":        false,
		"smil_href_animation":   false,
	}
	for _, cand := range got {
		if _, ok := wantTechniques[cand.Technique]; ok {
			wantTechniques[cand.Technique] = true
		}
	}
	for technique, found := range wantTechniques {
		if !found {
			t.Fatalf("automatic escalation omitted %q, required by the corresponding allow-list lab", technique)
		}
	}

	again := detection.EvasionEscalationCandidates(&rep, opts)
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("automatic escalation is not deterministic:\nfirst=%+v\nagain=%+v", got, again)
	}
	if !reflect.DeepEqual(rep.Plan.Candidates, canonicalBefore) {
		t.Fatalf("automatic escalation mutated the persisted canonical plan:\ngot=%+v\nwant=%+v", rep.Plan.Candidates, canonicalBefore)
	}
}

// The automatic fallback is evidence-gated: without a persisted reflection
// there is no reason to plan bypass shapes at all.
func TestEvasionEscalationCandidatesRequiresAReflection(t *testing.T) {
	opts := detection.PlanOptions{ScanID: "s", InjectionPointID: "ip"}
	if got := detection.EvasionEscalationCandidates(nil, opts); got != nil {
		t.Fatalf("nil report produced candidates: %+v", got)
	}
	probe := detection.NewProbe(domain.ID("s"), domain.ID("ip"))
	rep := detection.AnalyzeReflection(probe, nil, []byte("<p>no marker here</p>"))
	if got := detection.EvasionEscalationCandidates(&rep, opts); got != nil {
		t.Fatalf("non-reflected report produced candidates: %+v", got)
	}
	// A reflection whose canonical plan was never persisted has no evidence
	// that the canonical pass ran, so it is not eligible either.
	reflected := detection.AnalyzeReflection(probe, nil, []byte("<p>"+probe.Value()+"</p>"))
	if !reflected.Reflected {
		t.Fatal("setup: expected a reflected report")
	}
	if reflected.Plan != nil {
		t.Fatal("setup: AnalyzeReflection must not plan by itself")
	}
	if got := detection.EvasionEscalationCandidates(&reflected, opts); got != nil {
		t.Fatalf("unplanned reflection produced candidates: %+v", got)
	}
}

func TestEvasionEscalationCandidatesRespectMinimalProfileFilters(t *testing.T) {
	probe := detection.NewProbe(domain.ID("minimal-scan"), domain.ID("minimal-ip"))
	body := []byte("<p>" + probe.Value() + "</p>")
	rep := detection.AnalyzeReflection(probe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	opts := detection.PlanOptions{
		ScanID:           domain.ID("minimal-scan"),
		InjectionPointID: domain.ID("minimal-ip"),
		Profile:          detection.ProfileSpec{Name: detection.ProfileMinimal, MaxPerInjectionPoint: 3, LoadTriggerOnly: true, SkipNeutralized: true},
	}
	detection.PlanCandidates(&rep, opts)

	got := detection.EvasionEscalationCandidates(&rep, opts)
	if len(got) == 0 {
		t.Fatal("setup: minimal profile should retain at least one load-trigger evasion candidate")
	}
	if len(got) != detection.MaxEvasionCandidatesPerInjectionPoint {
		t.Fatalf("profile filtering must happen before the independent cap: got %d, want %d", len(got), detection.MaxEvasionCandidatesPerInjectionPoint)
	}
	techniques := map[string]bool{}
	for _, cand := range got {
		techniques[cand.Technique] = true
		if cand.Trigger != detection.TriggerLoad {
			t.Fatalf("minimal automatic escalation reintroduced an interaction candidate: %+v", cand)
		}
		if cand.Transformation != "raw" {
			t.Fatalf("minimal automatic escalation reintroduced a neutralized candidate: %+v", cand)
		}
	}
	if !techniques["double_url_encoding"] || !techniques["unicode_fullwidth"] {
		t.Fatalf("the cap was spent before profile filtering: techniques=%v", techniques)
	}
}

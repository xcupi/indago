package detection_test

import (
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestEvasionURLSchemesAreInteractionOnlyAndMinimalFallbackSkipsThem(t *testing.T) {
	scanID, ipID := domain.ID("url-evasion-scan"), domain.ID("url-evasion-ip")
	probe := detection.NewProbe(scanID, ipID)
	body := []byte(`<a href="` + probe.Value() + `">go</a>`)
	rep := detection.AnalyzeReflection(probe, nil, body)
	rep.Parameter = "returnUrl"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	minimal := detection.PlanOptions{
		ScanID:           scanID,
		InjectionPointID: ipID,
		Profile: detection.ProfileSpec{
			Name: detection.ProfileMinimal, MaxPerInjectionPoint: 3,
			LoadTriggerOnly: true, SkipNeutralized: true,
		},
	}
	detection.PlanCandidates(&rep, minimal)

	if got := detection.EvasionEscalationCandidates(&rep, minimal); len(got) != 0 {
		t.Fatalf("minimal automatic fallback must not send click-required URL bypasses: %+v", got)
	}

	eagerRep := rep
	eager := detection.PlanCandidates(&eagerRep, detection.PlanOptions{
		ScanID: scanID, InjectionPointID: ipID, EnableEvasion: true,
	})
	seen := 0
	for _, cand := range eager.Candidates {
		if cand.Technique == "" {
			continue
		}
		seen++
		if cand.Trigger != detection.TriggerInteraction {
			t.Fatalf("URL scheme bypass %q trigger=%q, want interaction so one declared click can run", cand.Value, cand.Trigger)
		}
	}
	if seen == 0 {
		t.Fatal("setup: eager URL plan contained no technique candidates")
	}
}

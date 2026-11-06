package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// Measured on PortSwigger lab 11: every on* handler and every href attribute is
// rejected (400), while SMIL is admitted — <svg><a><animate
// attributeName=href values=javascript:…> survives with the URL written into
// the anchor after parsing. No canonical shape can break that filter, so the
// bypass pack has to carry the SMIL construct or the class is unreachable.
func TestPlanCarriesTheSMILHrefAnimationShape(t *testing.T) {
	m := tok()
	body := []byte("<h1>0 search results for '" + candProbe.Value() + "'</h1>")
	rep := detection.AnalyzeReflection(candProbe, nil, body)
	rep.Parameter = "search"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: candHTML})
	spec, err := detection.ResolveProfile("standard", 0)
	if err != nil {
		t.Fatal(err)
	}
	detection.PlanCandidates(&rep, detection.PlanOptions{
		ScanID:           candScan,
		InjectionPointID: candIP,
		EnableEvasion:    true,
		Profile:          spec,
	})

	for _, c := range rep.Plan.Candidates {
		if !strings.Contains(c.Value, "attributeName=href") {
			continue
		}
		if c.Technique != "smil_href_animation" {
			t.Fatalf("technique = %q, want smil_href_animation", c.Technique)
		}
		if c.Trigger != detection.TriggerInteraction {
			t.Fatalf("trigger = %q, want interaction (the link has to be clicked)", c.Trigger)
		}
		if !strings.Contains(c.Value, "javascript:"+m) {
			t.Fatalf("the animated URL does not carry the marker: %q", c.Value)
		}
		// The marker must also be the anchor's text: the verifier clicks the
		// smallest marker-carrying element, and a click on that text is what
		// follows the animated href.
		if strings.Count(c.Value, m) < 2 {
			t.Fatalf("the marker should appear in the URL and in the link text: %q", c.Value)
		}
		return
	}
	var got []string
	for _, c := range rep.Plan.Candidates {
		got = append(got, c.Value)
	}
	t.Fatalf("no SMIL href-animation candidate was planned; got %v", got)
}

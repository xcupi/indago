package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// Measured on PortSwigger lab 8 (search box): the filter 400s every canonical
// mechanism — <script>, <img onerror>, <svg onload>, <details ontoggle>,
// <body onpageshow>, <svg><animate> — and admits only <body onresize=…>,
// <math> and <xss>. With -enable-evasion the operator explicitly asked for the
// bypass pack, and the pack does carry `body/onresize`… but the plan never
// contained it: the eight canonical candidates filled the profile's eight
// slots first, and every evasion shape (priority ≤ 45) was dropped by the cap.
//
// The documented contract is that evasion is ADDITIONAL TO the canonical set,
// never instead of it, so a cap sized for the canonical set must not be the
// thing that decides the bypass pack never runs.
func TestPlanEvasionPackSurvivesTheCanonicalProfileCap(t *testing.T) {
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

	want := "<body onresize=" + m + ">"
	for _, c := range rep.Plan.Candidates {
		if c.Value == want {
			if c.Technique == "" {
				t.Fatalf("candidate %q carries no technique tag; an evasion shape must name the bypass it is", want)
			}
			return
		}
	}
	var got []string
	for _, c := range rep.Plan.Candidates {
		got = append(got, strings.TrimSpace(c.Value))
	}
	t.Fatalf("the evasion pack never reached the plan: %q absent from %d candidates (%v)", want, len(got), got)
}

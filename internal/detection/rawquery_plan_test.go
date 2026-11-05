package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// canonicalLinkReport is one reflection site inside <link rel="canonical"
// href="...">, the canonical-link class: the innermost context is a URL inside
// a quoted HTML attribute.
func canonicalLinkReport(loc domain.ParamLocation, marker string) *detection.ReflectionReport {
	return &detection.ReflectionReport{
		Engine: "reflected-xss", Probe: detection.Probe{Token: marker},
		Parameter: "q", Location: loc, Reflected: true, Count: 1,
		Locations: []detection.ReflectionLocation{{
			Context: &detection.ContextAnalysis{
				Context: detection.CtxURL, Sub: "query",
				Chain:     []detection.Context{detection.CtxHTMLAttrValue, detection.CtxURL},
				Element:   "link",
				Attribute: "href",
				Quote:     "double",
			},
		}},
	}
}

// A raw-query injection point reflecting into a canonical-link href must plan a
// LOAD-triggered attribute breakout. Without it, the only URL-context shapes are
// interaction-only (javascript:/accesskey+onclick), which the passive verifier
// can never confirm — so the new capability would detect but never verify.
func TestPlanCandidates_RawQueryURLPlansLoadAttributeBreakout(t *testing.T) {
	const marker = "indrawmarker"
	rep := canonicalLinkReport(domain.LocationRawQuery, marker)
	plan := detection.PlanCandidates(rep, detection.PlanOptions{Marker: marker})
	if plan == nil {
		t.Fatal("no plan")
	}
	want := `"><svg onload=` + marker + `>`
	for _, c := range plan.Candidates {
		if c.Value == want {
			if c.Trigger != detection.TriggerLoad {
				t.Fatalf("breakout candidate trigger = %q, want %q", c.Trigger, detection.TriggerLoad)
			}
			if c.Category != detection.CatURL {
				t.Fatalf("breakout candidate category = %q, want %q", c.Category, detection.CatURL)
			}
			return
		}
	}
	t.Fatalf("raw-query URL plan has no %q candidate: %+v", want, plan.Candidates)
}

// The same site under a NAMED parameter must plan exactly what it planned
// before this capability: no attribute-breakout candidate is added. This is the
// byte-identical-plan regression at the planner layer.
func TestPlanCandidates_NamedParameterURLPlanUnchanged(t *testing.T) {
	const marker = "indnamedmarker"
	rep := canonicalLinkReport(domain.LocationQuery, marker)
	plan := detection.PlanCandidates(rep, detection.PlanOptions{Marker: marker})
	if plan == nil {
		t.Fatal("no plan")
	}
	for _, c := range plan.Candidates {
		if strings.Contains(c.Value, `<svg onload=`) {
			t.Fatalf("named-parameter URL plan gained a load-triggered attribute breakout: %+v", c)
		}
	}
}

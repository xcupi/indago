package detection_test

// The canonical-link position: a reflected value inside the single-quoted href
// of a <link rel="canonical"> in the head, with < and > HTML-encoded.
//
// The analyzer's innermost context there is the URL component (chain
// [html_attr_value, url]) and urlTemplates deliberately plans nothing for a
// query component — right for an <a href> the page navigates itself, wrong for
// link metadata, which has no rendered box and whose href the page never
// navigates. These tests pin the attribute-only candidate that position needs,
// and the element gate that keeps the addition scoped to <link>.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// canonicalLinkBody serves body for a <link rel="canonical"> whose href is a
// URL containing token. Angle brackets are HTML-encoded, quotes stay raw —
// the documented lab escaping.
func canonicalLinkBody(body, element, token string) []byte {
	return []byte(`<!doctype html><html><head><` + element + ` rel="canonical" href='https://lab.example/?search=` +
		token + `'/></head><body><p>canonical link</p></body></html>`)
}

// planFor classifies body and plans candidates from the real probe, exactly as
// the pipeline does.
func planFor(t *testing.T, body []byte) (*detection.ReflectionReport, *detection.CandidatePlan) {
	t.Helper()
	p := detection.NewProbe(domain.ID("link-attr-test"), domain.ID("ip"))
	rep := detection.AnalyzeReflection(p, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	if !rep.Reflected || len(rep.Locations) != 1 || rep.Locations[0].Context == nil {
		t.Fatalf("fixture must reflect exactly once with a classified site; reflected=%v sites=%d", rep.Reflected, len(rep.Locations))
	}
	return &rep, detection.PlanCandidates(&rep, detection.PlanOptions{})
}

func TestCanonicalLinkPlansAttributeOnlyVector(t *testing.T) {
	body := canonicalLinkBody("", "link", detection.NewProbe(domain.ID("link-attr-test"), domain.ID("ip")).Value())
	loc := func() *detection.ContextAnalysis {
		rep, _ := planFor(t, body)
		return rep.Locations[0].Context
	}()
	if loc.Context != detection.CtxURL || loc.Sub != "query" || loc.Element != "link" || loc.Quote != "single" {
		t.Fatalf("measured context = %s:%s element=%q quote=%q; this test pins the position it was measured for",
			loc.Context, loc.Sub, loc.Element, loc.Quote)
	}

	rep, plan := planFor(t, body)
	marker := rep.Probe.Token
	if plan == nil || len(plan.Candidates) == 0 {
		t.Fatal("canonical-link position must plan at least one candidate (an empty plan leaves a reflecting site unreported)")
	}
	var attributeOnly []detection.Candidate
	for _, c := range plan.Candidates {
		// Attribute-only: no < or >, because the fixture encodes both.
		if !strings.ContainsAny(c.Value, "<>") {
			attributeOnly = append(attributeOnly, c)
		}
	}
	if len(attributeOnly) == 0 {
		t.Fatalf("no attribute-only candidate planned for the canonical link: %+v", plan.Candidates)
	}
	got := attributeOnly[0]
	if !strings.Contains(got.Value, "accesskey=") || !strings.Contains(got.Value, "onclick="+marker) {
		t.Fatalf("the link vector must add accesskey + onclick attributes (the reported lab vector), got %q", got.Value)
	}
	if !strings.HasPrefix(got.Value, `'`) {
		t.Fatalf("the single-quoted href must be closed by the injected quote, got %q", got.Value)
	}
	if got.Trigger != detection.TriggerInteraction {
		t.Fatalf("the vector needs an operator activation, so it must be an interaction candidate, got %q", got.Trigger)
	}
	if !strings.Contains(got.Rationale, "bounded access-key activation") || !strings.Contains(got.Rationale, "marker-specific") {
		t.Fatalf("rationale must describe bounded activation plus marker-only confirmation, got %q", got.Rationale)
	}
	for i := range plan.Candidates {
		for j := i + 1; j < len(plan.Candidates); j++ {
			if plan.Candidates[i].DedupKey == plan.Candidates[j].DedupKey {
				t.Fatalf("duplicate dedup key in plan: %q", plan.Candidates[i].DedupKey)
			}
		}
	}
}

// TestCanonicalLinkVectorStaysScopedToLinkElements pins the element gate: the
// same URL-in-attribute position on an <a> the page itself navigates keeps the
// existing behaviour (no planned candidate), so this slice adds nothing that
// would send new requests at every anchor with a reflected query parameter.
func TestCanonicalLinkVectorStaysScopedToLinkElements(t *testing.T) {
	p := detection.NewProbe(domain.ID("anchor-attr-test"), domain.ID("ip"))
	body := canonicalLinkBody("", "a", p.Value())
	rep := detection.AnalyzeReflection(p, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	if !rep.Reflected || len(rep.Locations) != 1 || rep.Locations[0].Context == nil {
		t.Fatalf("anchor fixture must reflect exactly once; reflected=%v sites=%d", rep.Reflected, len(rep.Locations))
	}
	if el := rep.Locations[0].Context.Element; el != "a" {
		t.Fatalf("anchor fixture must classify as element %q, got %q", "a", el)
	}
	plan := detection.PlanCandidates(&rep, detection.PlanOptions{})
	if plan == nil {
		return
	}
	for _, c := range plan.Candidates {
		if strings.Contains(c.Value, "accesskey=") {
			t.Fatalf("link-only vector leaked onto an anchor element: %+v", c)
		}
	}
}

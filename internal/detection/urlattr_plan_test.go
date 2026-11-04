package detection_test

// The URL/href attribute-breakout shape. A raw-query injection point that lands
// inside <link rel="canonical" href="…"> needs a shape that closes the
// attribute VALUE and adds an event-handler attribute the verifier's single
// click activation can fire — otherwise the position is detectable but can
// never execute. These tests pin:
//
//   - the exact bytes, for BOTH quote styles the analyser can report;
//   - that the shape carries nothing but the benign marker and declares the
//     interaction trigger the verifier activates;
//   - that a site which provably encodes its delimiter does NOT get the shape
//     planned at all (a closing quote must arrive raw; an entity-encoded quote
//     is decoded into the attribute value, never into a delimiter);
//   - that the default (named-parameter) candidate set is byte-identical.
//
// The real-browser confirmation/rejection pair lives in urlattr_browser_test.go.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// urlAttrProbe is one deterministic probe shared by every fixture here.
var urlAttrProbe = detection.NewProbe(domain.ID("url-attr-shape"), domain.ID("ip"))

// hrefFixture serves a canonical-link page with the probe value inside the
// href of a <link rel="canonical"> (the measured lab position). quote selects
// the attribute delimiter and encoded controls whether the page HTML-encodes
// the reflected value, exactly as the escaping controls do elsewhere.
func hrefFixture(element, quote string, encoded bool, value string) []byte {
	if encoded {
		value = strings.NewReplacer(
			"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
		).Replace(value)
	}
	return []byte(`<!doctype html><html><head><` + element + ` rel="canonical" href=` + quote +
		`https://lab.example/post?search=` + value + quote + `><title>Post</title></head>` +
		`<body><h1>Post</h1></body></html>`)
}

// urlAttrPlan analyses served bytes exactly as the reflection step does, then
// labels the injection point the way the scan does for a raw-query job.
func urlAttrPlan(t *testing.T, body []byte, loc domain.ParamLocation) (*detection.ReflectionReport, *detection.CandidatePlan) {
	t.Helper()
	rep := detection.AnalyzeReflection(urlAttrProbe, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	if !rep.Reflected || len(rep.Locations) == 0 || rep.Locations[0].Context == nil {
		t.Fatalf("fixture must reflect at least once with a classified site; reflected=%v sites=%d", rep.Reflected, len(rep.Locations))
	}
	rep.Location = loc // set from the injection point, as internal/scan/reflection.go does
	return &rep, detection.PlanCandidates(&rep, detection.PlanOptions{Marker: urlAttrProbe.Token})
}

// findCandidate returns the candidate whose value is exactly want.
func findCandidate(plan *detection.CandidatePlan, want string) *detection.Candidate {
	for i := range plan.Candidates {
		if plan.Candidates[i].Value == want {
			return &plan.Candidates[i]
		}
	}
	return nil
}

// TestPlanRawQueryURLHrefBreakoutShapeDoubleQuote pins the exact shape for the
// measured double-quoted position: it closes the href value with the site's own
// delimiter and adds accesskey/onclick carrying only the marker.
func TestPlanRawQueryURLHrefBreakoutShapeDoubleQuote(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `"`, false, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Context != detection.CtxURL || loc.Sub != "query" || loc.Element != "link" || loc.Attribute != "href" || loc.Quote != "double" {
		t.Fatalf("measured context = %s:%s element=%q attr=%q quote=%q; this test pins the position it was measured for",
			loc.Context, loc.Sub, loc.Element, loc.Attribute, loc.Quote)
	}

	want := `"accesskey='x' onclick=` + m + ` x="`
	got := findCandidate(plan, want)
	if got == nil {
		t.Fatalf("raw-query URL plan has no href attribute breakout %q: %+v", want, plan.Candidates)
	}
	if got.Trigger != detection.TriggerInteraction {
		t.Fatalf("trigger = %q, want %q (the verifier must activate it)", got.Trigger, detection.TriggerInteraction)
	}
	if got.Category != detection.CatURL {
		t.Fatalf("category = %q, want %q", got.Category, detection.CatURL)
	}
	if got.Transformation != "raw" {
		t.Fatalf("transformation = %q, want raw (the delimiter survived, so the shape is plannable)", got.Transformation)
	}
	// Benign-marker only: the handler body is the bare marker and nothing else,
	// exactly like every other built-in candidate.
	if strings.Contains(strings.ToLower(got.Value), "alert") || strings.Contains(got.Value, "cookie") || strings.Contains(got.Value, "http") {
		t.Fatalf("candidate must carry only the benign marker, got %q", got.Value)
	}
	if !strings.Contains(got.Rationale, "click activation") {
		t.Fatalf("rationale must declare the activation the shape needs, got %q", got.Rationale)
	}
}

// TestPlanRawQueryURLHrefBreakoutShapeSingleQuote proves the shape follows the
// delimiter the analyser reports instead of assuming a double quote.
func TestPlanRawQueryURLHrefBreakoutShapeSingleQuote(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `'`, false, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Quote != "single" || loc.Context != detection.CtxURL {
		t.Fatalf("measured context = %s quote=%q; this test pins the single-quoted position", loc.Context, loc.Quote)
	}
	want := `'accesskey='x' onclick=` + m + ` x='`
	if got := findCandidate(plan, want); got == nil {
		t.Fatalf("single-quoted href plan has no %q candidate: %+v", want, plan.Candidates)
	}
	if got := findCandidate(plan, `"accesskey='x' onclick=`+m+` x="`); got != nil {
		t.Fatalf("single-quoted site was planned a double-quote breakout: %+v", got)
	}
}

// TestPlanRawQueryURLHrefBreakoutDroppedWhenDelimiterEncoded is the strict-needs
// guard: when the site provably HTML-encodes the quote, an injected quote can
// never terminate the attribute, so the shape is NOT planned (not merely
// deprioritized). Sending it would only produce a request that cannot break out.
func TestPlanRawQueryURLHrefBreakoutDroppedWhenDelimiterEncoded(t *testing.T) {
	body := hrefFixture("link", `"`, true, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Context != detection.CtxURL {
		t.Fatalf("encoded fixture must still classify as a URL site, got %s", loc.Context)
	}
	if rep.Locations[0].PerChar[`"`] != detection.EncHTML {
		t.Fatalf("fixture must prove the quote is HTML-encoded, per-char form = %q", rep.Locations[0].PerChar[`"`])
	}
	for _, c := range plan.Candidates {
		if strings.Contains(c.Value, "accesskey='x'") {
			t.Fatalf("href attribute breakout planned against an encoded delimiter: %+v", c)
		}
	}
}

// TestURLAttributeBreakoutDefaultCandidateSetUnchanged freezes, byte for byte,
// what the canonical-link position planned before this shape existed — for a
// NAMED parameter (the default scan) — and proves the raw-query plan is that
// same frozen set plus exactly ONE added shape, with nothing else reordered,
// re-prioritized or removed.
func TestURLAttributeBreakoutDefaultCandidateSetUnchanged(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `"`, false, urlAttrProbe.Value())

	type frozen struct{ named, rawQuery []string }
	want := frozen{
		named: []string{
			`url|" accesskey=x onclick=` + m + ` y="|60|interaction`,
		},
		rawQuery: []string{
			`url|"><svg onload=` + m + `>|90|load`,
			`url|" autofocus onfocus=` + m + ` x="|87|load`,
			`url|" onmouseover=` + m + ` x="|85|interaction`,
			`url|"accesskey='x' onclick=` + m + ` x="|78|interaction`,
			`url|" accesskey=x onclick=` + m + ` y="|60|interaction`,
		},
	}
	render := func(plan *detection.CandidatePlan) []string {
		out := make([]string, 0, len(plan.Candidates))
		for _, c := range plan.Candidates {
			out = append(out, strings.Join([]string{string(c.Category), c.Value, itoa(c.Priority), c.Trigger}, "|"))
		}
		return out
	}

	_, named := urlAttrPlan(t, body, domain.LocationQuery)
	if got := render(named); strings.Join(got, "\n") != strings.Join(want.named, "\n") {
		t.Fatalf("default (named-parameter) candidate set changed:\n got:\n%s\nwant:\n%s",
			strings.Join(got, "\n"), strings.Join(want.named, "\n"))
	}
	for _, c := range named.Candidates {
		if strings.Contains(c.Value, "accesskey='x'") {
			t.Fatalf("default plan gained the raw-query href breakout: %+v", c)
		}
	}

	_, raw := urlAttrPlan(t, body, domain.LocationRawQuery)
	if raw.Generated != len(raw.Candidates) {
		t.Fatalf("raw-query plan generated %d candidates but kept %d", raw.Generated, len(raw.Candidates))
	}
	if got := render(raw); strings.Join(got, "\n") != strings.Join(want.rawQuery, "\n") {
		t.Fatalf("raw-query candidate set is not the frozen set + one shape:\n got:\n%s\nwant:\n%s",
			strings.Join(got, "\n"), strings.Join(want.rawQuery, "\n"))
	}
}

// TestPlanURLHrefBreakoutOnlyForHrefAttributes keeps the addition scoped: a URL
// reflected in another URL-bearing attribute (src) does not get this shape.
func TestPlanURLHrefBreakoutOnlyForHrefAttributes(t *testing.T) {
	body := []byte(`<!doctype html><html><head><title>t</title></head><body><img src="https://lab.example/a?search=` +
		urlAttrProbe.Value() + `"></body></html>`)
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)
	if el, attr := rep.Locations[0].Context.Element, rep.Locations[0].Context.Attribute; el != "img" || attr != "src" {
		t.Fatalf("fixture classified element=%q attr=%q, want img/src", el, attr)
	}
	for _, c := range plan.Candidates {
		if strings.Contains(c.Value, "accesskey='x'") {
			t.Fatalf("href breakout leaked onto a non-href attribute: %+v", c)
		}
	}
}

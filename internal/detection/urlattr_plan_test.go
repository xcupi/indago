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

// hrefAccesskeyBreakout reports whether c belongs to the href
// attribute-breakout family (urlHrefBreakoutTemplates): an accesskey/onclick
// pair that closes a quoted attribute value. The link-attribute shape also
// carries accesskey/onclick, but it does not close a quote of its own
// (Candidate.Delimiter is empty), so the delimiter label separates the two
// families without depending on the exact bytes of either.
func hrefAccesskeyBreakout(c detection.Candidate) bool {
	return c.Delimiter != "" && strings.Contains(c.Value, "accesskey=") && strings.Contains(c.Value, "onclick=")
}

// hrefScriptBreakout reports whether c is the LOAD-class href breakout: it
// closes a quoted attribute value and ends the tag with '>', then opens a
// <script> block. It needs no activation at all.
func hrefScriptBreakout(c detection.Candidate) bool {
	return c.Delimiter != "" && strings.Contains(c.Value, "><script>")
}

func hrefScriptBreakouts(plan *detection.CandidatePlan) []detection.Candidate {
	var out []detection.Candidate
	for _, c := range plan.Candidates {
		if hrefScriptBreakout(c) {
			out = append(out, c)
		}
	}
	return out
}

// hrefScriptBreakoutValue is the exact load-class shape for one quote style:
// the site's delimiter closes the attribute, '>' ends the element's tag, and a
// <script> block whose entire body is the bare marker executes during parse.
func hrefScriptBreakoutValue(style, marker string) string {
	q := dq
	if style == "single" {
		q = sq
	}
	return q + "><script>" + marker + "</script>"
}

// hrefBreakoutValue is the exact shape the href family plans for one quote
// style: the site's delimiter closes the value, the accesskey VALUE is the bare
// character x with no quote of its own (so no reader can mistake a delimiter
// byte for the declared key), the handler body is the bare marker, and an inert
// trailing attribute swallows the site's closing quote. The single-quote
// variant keeps its historical trailing name (x); the double-quote mirror uses
// y.
func hrefBreakoutValue(style, marker string) string {
	q := dq
	filler := "y"
	if style == "single" {
		q, filler = sq, "x"
	}
	return q + "accesskey=x onclick=" + marker + " " + filler + "=" + q
}

// TestPlanRawQueryURLHrefBreakoutShapeDoubleQuote pins the exact shape for the
// measured double-quoted position: it closes the href value with the site's own
// delimiter and adds accesskey/onclick carrying only the marker. The accesskey
// VALUE is double-quoted too, so the shape needs no single quote at all.
func TestPlanRawQueryURLHrefBreakoutShapeDoubleQuote(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `"`, false, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Context != detection.CtxURL || loc.Sub != "query" || loc.Element != "link" || loc.Attribute != "href" || loc.Quote != "double" {
		t.Fatalf("measured context = %s:%s element=%q attr=%q quote=%q; this test pins the position it was measured for",
			loc.Context, loc.Sub, loc.Element, loc.Attribute, loc.Quote)
	}

	want := hrefBreakoutValue("double", m)
	got := findCandidate(plan, want)
	if got == nil {
		t.Fatalf("raw-query URL plan has no href attribute breakout %q: %+v", want, plan.Candidates)
	}
	if got.Delimiter != "double" {
		t.Fatalf("delimiter = %q, want double", got.Delimiter)
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
	// The mirror must depend on exactly ONE quote byte (the site's delimiter):
	// a single-quote site encodes or filters ' as a matter of course, and a
	// hardcoded accesskey='x' would lose the keybinding there.
	if strings.Contains(got.Value, "'") {
		t.Fatalf("double-quote mirror carries a single quote, so it depends on a second quote arriving raw: %q", got.Value)
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
// delimiter the analyser reports instead of assuming a double quote, and that
// the single-quote variant is byte-identical to what it was before the mirror
// existed.
func TestPlanRawQueryURLHrefBreakoutShapeSingleQuote(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `'`, false, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Quote != "single" || loc.Context != detection.CtxURL {
		t.Fatalf("measured context = %s quote=%q; this test pins the single-quoted position", loc.Context, loc.Quote)
	}
	want := `'accesskey=x onclick=` + m + ` x='`
	if got := findCandidate(plan, want); got == nil {
		t.Fatalf("single-quoted href plan has no %q candidate: %+v", want, plan.Candidates)
	}
	if got := findCandidate(plan, hrefBreakoutValue("double", m)); got != nil {
		t.Fatalf("single-quoted site was planned a double-quote breakout: %+v", got)
	}
}

// TestDoubleQuoteBreakoutNeedsOnlyTheDoubleQuote is the measured-gap
// regression: a double-quoted href that HTML-encodes the single quote (but
// leaves its own double quote raw) still gets a click-class breakout, and that
// breakout contains no single quote to be rewritten. The planner must not
// substitute a single-quoted accesskey VALUE here: the attribute would close
// fine, but the keybinding would be rewritten in place.
func TestDoubleQuoteBreakoutNeedsOnlyTheDoubleQuote(t *testing.T) {
	m := urlAttrProbe.Token
	value := strings.ReplaceAll(urlAttrProbe.Value(), "'", "&#39;")
	body := []byte(`<!doctype html><html><head><link rel="canonical" href="https://lab.example/post?search=` +
		value + `"><title>Post</title></head><body><h1>Post</h1></body></html>`)
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Quote != "double" {
		t.Fatalf("delimiter = %q, want double", loc.Quote)
	}
	if rep.Locations[0].PerChar["'"] != detection.EncHTML {
		t.Fatalf("fixture must HTML-encode the single quote, per-char form = %q", rep.Locations[0].PerChar["'"])
	}
	want := hrefBreakoutValue("double", m)
	got := findCandidate(plan, want)
	if got == nil {
		t.Fatalf("double-quoted href with an encoded single quote has no click-class breakout %q: %+v", want, plan.Candidates)
	}
	if got.Transformation != "raw" {
		t.Fatalf("transformation = %q, want raw (the shape needs only the double quote, which survived)", got.Transformation)
	}
	for _, c := range plan.Candidates {
		if hrefAccesskeyBreakout(c) && strings.Contains(c.Value, "'") {
			t.Fatalf("href breakout depends on the encoded single quote: %+v", c)
		}
	}
}

// TestPlanRawQueryURLHrefBreakoutDroppedWhenDelimiterEncoded is the strict-needs
// guard: when the site provably HTML-encodes the quote, an injected quote can
// never terminate the attribute, so the shape is NOT planned (not merely
// deprioritized). Sending it would only produce a request that cannot break out.
// It holds for both quote families.
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
		if hrefAccesskeyBreakout(c) {
			t.Fatalf("href attribute breakout planned against an encoded delimiter: %+v", c)
		}
		if hrefScriptBreakout(c) {
			t.Fatalf("href script breakout planned against an encoded delimiter: %+v", c)
		}
	}
}

// TestURLAttributeBreakoutDefaultCandidateSetUnchanged freezes, byte for byte,
// what the canonical-link position planned before these shapes existed — for a
// NAMED parameter (the default scan) — and proves the raw-query plan is that
// same frozen set plus the href-breakout shapes and their TAB-separated
// siblings only, with nothing else reordered, re-prioritized or removed.
func TestURLAttributeBreakoutDefaultCandidateSetUnchanged(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", `"`, false, urlAttrProbe.Value())

	type frozen struct{ named, rawQuery []string }
	want := frozen{
		named: []string{
			`url|" accesskey=x onclick=` + m + ` y="|60|interaction`,
		},
		// The canonical (space-separated) shapes, each followed by its
		// TAB-separated sibling one priority point lower. The siblings are
		// additive: every frozen shape above keeps its bytes and its priority.
		rawQuery: []string{
			`url|"><svg onload=` + m + `>|90|load`,
			`url|"><script>` + m + `</script>|89|load`,
			`url|" autofocus onfocus=` + m + ` x="|87|load`,
			`url|"	autofocus	onfocus=` + m + `	x="|86|load`,
			`url|" onmouseover=` + m + ` x="|85|interaction`,
			`url|"	onmouseover=` + m + `	x="|84|interaction`,
			`url|"accesskey=x onclick=` + m + ` y="|78|interaction`,
			`url|"accesskey=x	onclick=` + m + `	y="|77|interaction`,
			`url|" accesskey=x onclick=` + m + ` y="|60|interaction`,
			`url|"	accesskey=x	onclick=` + m + `	y="|59|interaction`,
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
		if hrefAccesskeyBreakout(c) {
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
		if hrefAccesskeyBreakout(c) {
			t.Fatalf("href breakout leaked onto a non-href attribute: %+v", c)
		}
		if hrefScriptBreakout(c) {
			t.Fatalf("href script breakout leaked onto a non-href attribute: %+v", c)
		}
	}
}

// TestPlanURLHrefScriptBreakoutExecutesOnLoad pins the load-class shape against
// a page that echoes the value raw: the site's own delimiter closes the href
// value, '>' ends the element's tag, and a <script> block carrying nothing but
// the bare marker executes while the page is parsed. It needs NO activation,
// which is what makes it confirmable on a <link> (no rendered box, never
// clicked). Both quote families are pinned, each against its own proven
// delimiter.
func TestPlanURLHrefScriptBreakoutExecutesOnLoad(t *testing.T) {
	m := urlAttrProbe.Token
	for _, tc := range []struct{ quote, style string }{
		{dq, "double"},
		{sq, "single"},
	} {
		body := hrefFixture("link", tc.quote, false, urlAttrProbe.Value())
		rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

		ctx := rep.Locations[0].Context
		if ctx.Context != detection.CtxURL || ctx.Element != "link" || ctx.Attribute != "href" || ctx.Quote != tc.style || !ctx.QuoteProven {
			t.Fatalf("%s fixture measured %s element=%q attr=%q quote=%q proven=%v", tc.style, ctx.Context, ctx.Element, ctx.Attribute, ctx.Quote, ctx.QuoteProven)
		}

		want := hrefScriptBreakoutValue(tc.style, m)
		got := findCandidate(plan, want)
		if got == nil {
			t.Fatalf("%s fixture has no load-class href breakout %q: %+v", tc.style, want, plan.Candidates)
		}
		if got.Trigger != detection.TriggerLoad {
			t.Fatalf("%s shape trigger = %q, want %q (verified during the page's own load, with no activation)", tc.style, got.Trigger, detection.TriggerLoad)
		}
		if got.Delimiter != tc.style {
			t.Fatalf("%s shape delimiter = %q", tc.style, got.Delimiter)
		}
		if got.Category != detection.CatURL {
			t.Fatalf("%s shape category = %q, want url", tc.style, got.Category)
		}
		if got.Transformation != "raw" || got.Priority != 89 {
			t.Fatalf("%s shape transformation/priority = %q/%d, want raw/89", tc.style, got.Transformation, got.Priority)
		}
		// Nothing but the benign marker may be carried: the script body is
		// exactly the marker token, so a browser that executes it raises a
		// marker-specific ReferenceError and nothing else happens.
		if !strings.HasSuffix(got.Value, "<script>"+m+"</script>") {
			t.Fatalf("%s shape script body is not exactly the marker: %q", tc.style, got.Value)
		}
		lower := strings.ToLower(got.Value)
		if strings.Contains(lower, "alert") || strings.Contains(lower, "cookie") || strings.Contains(lower, "http") || strings.Contains(lower, "src=") {
			t.Fatalf("%s shape carries more than the benign marker: %q", tc.style, got.Value)
		}
		if !strings.Contains(got.Rationale, "no click") || !strings.Contains(got.Rationale, tc.style+"-quoted") {
			t.Fatalf("%s shape rationale must state the load execution and name its delimiter, got %q", tc.style, got.Rationale)
		}
	}
}

// TestPlanURLHrefScriptBreakoutMirrorsBothQuoteStyles covers the unproven
// delimiter: when the target rewrote the value, both quote families are planned
// (exactly like the accesskey sibling), each closing its own delimiter, and
// each is DEPRIORITIZED rather than dropped when the site provably encodes the
// '<' and '>' the tag breakout needs — the needs analysis records the form.
func TestPlanURLHrefScriptBreakoutMirrorsBothQuoteStyles(t *testing.T) {
	m := urlAttrProbe.Token
	body := quoteFixture(dq, "angles", urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	ctx := rep.Locations[0].Context
	if ctx.QuoteProven {
		t.Fatalf("an angle-encoded reflection must not prove the delimiter")
	}
	got := hrefScriptBreakouts(plan)
	if len(got) != 2 {
		t.Fatalf("unproven delimiter must plan exactly 2 load-class href breakouts, got %d: %+v", len(got), got)
	}
	styles := map[string]detection.Candidate{}
	for _, c := range got {
		if c.Delimiter != "double" && c.Delimiter != "single" {
			t.Fatalf("load breakout %q has delimiter %q", c.Value, c.Delimiter)
		}
		if _, dup := styles[c.Delimiter]; dup {
			t.Fatalf("two load variants assume the same delimiter %q", c.Delimiter)
		}
		styles[c.Delimiter] = c
		if c.Value != hrefScriptBreakoutValue(c.Delimiter, m) {
			t.Fatalf("%s variant = %q", c.Delimiter, c.Value)
		}
		if c.Trigger != detection.TriggerLoad {
			t.Fatalf("%s variant trigger = %q, want load", c.Delimiter, c.Trigger)
		}
		if c.Transformation != detection.EncHTML || c.Priority >= 89 {
			t.Fatalf("%s variant transformation/priority = %q/%d, want the encoded angle brackets recorded and deprioritized", c.Delimiter, c.Transformation, c.Priority)
		}
		if !strings.Contains(c.Rationale, "encodes/strips the characters this breakout needs") {
			t.Fatalf("%s variant rationale must record the neutralized angle brackets, got %q", c.Delimiter, c.Rationale)
		}
	}
	if _, ok := styles["double"]; !ok {
		t.Fatalf("unproven delimiter did not plan the double-quote load variant: %+v", got)
	}
	if _, ok := styles["single"]; !ok {
		t.Fatalf("unproven delimiter did not plan the single-quote load variant: %+v", got)
	}
	if v := styles["double"].Value; strings.Contains(v, "'") {
		t.Fatalf("double variant depends on a raw single quote: %q", v)
	}
	if v := styles["single"].Value; strings.Contains(v, dq) {
		t.Fatalf("single variant depends on a raw double quote: %q", v)
	}
}

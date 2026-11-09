package detection_test

// TAB-separated attribute variants for the raw-query location.
//
// Measured on the canonical-link lab: the page reflects the whole query blob
// into a single-quoted href and PERCENT-ENCODES a space. The space-separated
// shape therefore arrives as `accesskey=x%20onclick=MARKER%20x=` inside the
// href VALUE — `%20` is literal text to the HTML parser, so exactly one
// attribute exists and there is no handler to activate. The same TAB is
// reflected RAW, so `accesskey=x<TAB>onclick=MARKER<TAB>x=` parses as three
// separate attributes.
//
// These tests pin the planner half: the raw-query family offers the TAB
// siblings alongside the unchanged space shapes, they are distinguishable in
// provenance, the separator survives url.QueryEscape as %09 (never a space or
// `+`), and every planner gate that applies to the canonical shape (the
// delimiter `needs`, the strict encoded-delimiter drop) applies to its sibling.
// The real-browser confirmation/rejection pair lives in
// urlattr_tabsep_browser_test.go.

import (
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// TestRawQueryPlansTabSeparatedAttributeVariants is the planning regression: for
// the measured double-quoted canonical-link position, every attribute pair that
// the canonical plan joins with a space also has a TAB twin, one priority point
// lower, carrying the same trigger and delimiter label.
func TestRawQueryPlansTabSeparatedAttributeVariants(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", dq, false, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Context != detection.CtxURL || loc.Quote != "double" || !loc.QuoteProven {
		t.Fatalf("measured context = %s quote=%q proven=%v; this test pins the measured position", loc.Context, loc.Quote, loc.QuoteProven)
	}

	pairs := []struct {
		name      string
		space     string
		tab       string
		trigger   string
		delimiter string
		priority  int // the TAB sibling's priority
	}{
		{
			name:      "href accesskey/onclick",
			space:     `"accesskey=x onclick=` + m + ` y="`,
			tab:       `"accesskey=x` + "	" + `onclick=` + m + "	" + `y="`,
			trigger:   detection.TriggerInteraction,
			delimiter: "double",
			priority:  77,
		},
		{
			name:      "link accesskey/onclick",
			space:     `" accesskey=x onclick=` + m + ` y="`,
			tab:       `"` + "	" + `accesskey=x` + "	" + `onclick=` + m + "	" + `y="`,
			trigger:   detection.TriggerInteraction,
			delimiter: "", // the link family carries no delimiter label (see hrefAccesskeyBreakout)
			priority:  59,
		},
		{
			name:      "autofocus/onfocus pair",
			space:     `" autofocus onfocus=` + m + ` x="`,
			tab:       `"` + "	" + `autofocus` + "	" + `onfocus=` + m + "	" + `x="`,
			trigger:   detection.TriggerLoad,
			delimiter: "double",
			priority:  86,
		},
		{
			name:      "onmouseover handler",
			space:     `" onmouseover=` + m + ` x="`,
			tab:       `"` + "	" + `onmouseover=` + m + "	" + `x="`,
			trigger:   detection.TriggerInteraction,
			delimiter: "double",
			priority:  84,
		},
	}

	for _, tc := range pairs {
		spaceCand := findCandidate(plan, tc.space)
		if spaceCand == nil {
			t.Fatalf("%s: the space-separated shape must stay planned, got %+v", tc.name, plan.Candidates)
		}
		if spaceCand.Priority != tc.priority+1 {
			t.Fatalf("%s: space shape priority = %d, want its unchanged %d", tc.name, spaceCand.Priority, tc.priority+1)
		}

		tabCand := findCandidate(plan, tc.tab)
		if tabCand == nil {
			t.Fatalf("%s: raw-query plan has no TAB variant %q: %+v", tc.name, tc.tab, plan.Candidates)
		}
		if tabCand.Trigger != tc.trigger {
			t.Fatalf("%s: TAB variant trigger = %q, want %q", tc.name, tabCand.Trigger, tc.trigger)
		}
		if tabCand.Priority != tc.priority {
			t.Fatalf("%s: TAB variant priority = %d, want %d (one point below its space sibling)", tc.name, tabCand.Priority, tc.priority)
		}
		if tabCand.Category != detection.CatURL {
			t.Fatalf("%s: TAB variant category = %q, want url", tc.name, tabCand.Category)
		}
		if tabCand.Delimiter != tc.delimiter {
			t.Fatalf("%s: TAB variant delimiter = %q, want %q", tc.name, tabCand.Delimiter, tc.delimiter)
		}
		if tabCand.Transformation != "raw" {
			t.Fatalf("%s: TAB variant transformation = %q, want raw (the delimiter survived)", tc.name, tabCand.Transformation)
		}
		// Provenance: the variant says which separator it uses, so a report can
		// tell it from its space sibling without diffing the bytes.
		if !strings.Contains(tabCand.Rationale, "TAB") {
			t.Fatalf("%s: TAB variant rationale must name its separator, got %q", tc.name, tabCand.Rationale)
		}
		if tabCand.DedupKey == spaceCand.DedupKey {
			t.Fatalf("%s: the TAB variant collides with its space sibling in dedup", tc.name)
		}
		if strings.Contains(tabCand.Value, " ") {
			t.Fatalf("%s: TAB variant still separates attributes with a space: %q", tc.name, tabCand.Value)
		}
		// Benign marker only, exactly like the canonical shape.
		lower := strings.ToLower(tabCand.Value)
		if strings.Contains(lower, "alert") || strings.Contains(lower, "cookie") || strings.Contains(lower, "http") || strings.Contains(lower, "src=") {
			t.Fatalf("%s: TAB variant carries more than the benign marker: %q", tc.name, tabCand.Value)
		}
	}

	// The plan is additive and dedup-free for this fixture: the six frozen
	// shapes plus four TAB siblings. (The named-link TAB sibling dedupes
	// against the raw-query one, so it adds no eleventh candidate.)
	if plan.Generated != 11 || len(plan.Candidates) != 10 {
		t.Fatalf("raw-query plan = %d generated / %d kept, want 11/10", plan.Generated, len(plan.Candidates))
	}
}

// TestRawQueryTabSeparatorSurvivesURLEncoding is the wire-shape half: the
// separator must reach the server as a real tab. The raw-query request builder
// encodes the payload with url.QueryEscape (internal/discovery), so a literal
// TAB in the value must become %09 — never `+` or %20, which is exactly the
// bytes that turned the space shape into one attribute value on the lab.
func TestRawQueryTabSeparatorSurvivesURLEncoding(t *testing.T) {
	body := hrefFixture("link", sq, false, urlAttrProbe.Value())
	_, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	tabs := hrefTabBreakouts(plan)
	if len(tabs) == 0 {
		t.Fatalf("no TAB href breakouts planned: %+v", plan.Candidates)
	}
	for _, c := range tabs {
		if !strings.Contains(c.Value, "\t") {
			t.Fatalf("candidate %q carries no raw TAB", c.Value)
		}
		encoded := url.QueryEscape(c.Value)
		if !strings.Contains(encoded, "%09") {
			t.Fatalf("candidate %q encodes to %q, want a %%09 for its separator", c.Value, encoded)
		}
		if strings.Contains(encoded, "+") || strings.Contains(encoded, "%20") {
			t.Fatalf("candidate %q encodes a space (%q); the separator must be a tab", c.Value, encoded)
		}
		decoded, err := url.QueryUnescape(encoded)
		if err != nil {
			t.Fatalf("decode %q: %v", encoded, err)
		}
		if decoded != c.Value {
			t.Fatalf("encoded form %q round-trips to %q, want the exact candidate bytes %q", encoded, decoded, c.Value)
		}
	}
}

// TestRawQueryTabVariantsRespectEncodedDelimiterGuard keeps the planner gates in
// force for the new variants: a site that provably encodes the closing quote
// cannot be broken out of, so the strict href siblings (space AND tab) are not
// planned at all — the same drop the canonical shape already gets.
func TestRawQueryTabVariantsRespectEncodedDelimiterGuard(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", dq, true, urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	if rep.Locations[0].PerChar[dq] != detection.EncHTML {
		t.Fatalf("fixture must prove the double quote is encoded, per-char = %q", rep.Locations[0].PerChar[dq])
	}
	forbidden := []string{
		`"accesskey=x onclick=` + m + ` y="`,
		`"accesskey=x` + "\t" + `onclick=` + m + "\t" + `y="`,
		`"><script>` + m + `</script>`,
	}
	for _, v := range forbidden {
		if c := findCandidate(plan, v); c != nil {
			t.Fatalf("strict shape planned against an encoded delimiter: %+v", c)
		}
	}
	if got := hrefTabBreakouts(plan); len(got) != 0 {
		t.Fatalf("TAB href breakouts planned against an encoded delimiter: %+v", got)
	}
}

// TestRawQueryTabVariantsCoverTheUnquotedPosition applies the same treatment to
// the unquoted attribute value, where whitespace (not a quote) ends the value:
// the TAB sibling terminates the injected attribute exactly like a space does.
func TestRawQueryTabVariantsCoverTheUnquotedPosition(t *testing.T) {
	m := urlAttrProbe.Token
	body := []byte(`<!doctype html><html><head><link rel=canonical href=https://lab.example/post?search=` +
		urlAttrProbe.Value() + `><title>Post</title></head><body><h1>Post</h1></body></html>`)
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	loc := rep.Locations[0].Context
	if loc.Quote != "unquoted" || loc.Attribute != "href" {
		t.Fatalf("measured context = %s attr=%q quote=%q, want the unquoted href position", loc.Context, loc.Attribute, loc.Quote)
	}
	for _, want := range []string{
		"\tautofocus\tonfocus=" + m + "\t",
		"\tonmouseover=" + m + "\t",
	} {
		c := findCandidate(plan, want)
		if c == nil {
			t.Fatalf("unquoted raw-query position has no TAB variant %q: %+v", want, plan.Candidates)
		}
		if !strings.Contains(c.Rationale, "TAB") {
			t.Fatalf("unquoted TAB variant rationale must name its separator, got %q", c.Rationale)
		}
	}
}

// TestNamedParameterPlanHasNoTabVariants is the default-plan guard at the
// planner layer: the in-tag/href TAB family is reachable only from the
// raw-query branch. The ONE exception is the link-element accesskey sibling,
// which the canonical-link position needs on a named parameter too (the lab
// reflects the space percent-encoded but passes a raw TAB through).
func TestNamedParameterPlanHasNoTabVariants(t *testing.T) {
	for _, loc := range []domain.ParamLocation{domain.LocationQuery, domain.LocationForm} {
		_, plan := urlAttrPlan(t, hrefFixture("link", dq, false, urlAttrProbe.Value()), loc)
		for _, c := range plan.Candidates {
			if !strings.Contains(c.Value, "	") {
				continue
			}
			if hrefAccesskeyBreakout(c) || !strings.Contains(c.Value, "accesskey=x	") {
				t.Fatalf("%s plan gained a non-link TAB-separated variant: %+v", loc, c)
			}
		}
	}
}

// TestTabVariantIsSentByTheStandardProfile proves the fix is not merely planned
// but SELECTED: the profile cap is unchanged (8 for standard), and the
// accesskey TAB variant still falls inside it, so the shape that works on the
// measured page is actually executed. The two link-element shapes are what the
// unchanged cap leaves out.
func TestTabVariantIsSentByTheStandardProfile(t *testing.T) {
	m := urlAttrProbe.Token
	body := hrefFixture("link", dq, false, urlAttrProbe.Value())

	rep := detection.AnalyzeReflection(urlAttrProbe, nil, body)
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	rep.Location = domain.LocationRawQuery
	spec, err := detection.ResolveProfile(string(detection.ProfileStandard), 0)
	if err != nil {
		t.Fatalf("resolve standard profile: %v", err)
	}
	plan := detection.PlanCandidates(&rep, detection.PlanOptions{Marker: m, Profile: spec})

	if plan.Limit != 8 {
		t.Fatalf("standard profile cap = %d, want the unchanged 8", plan.Limit)
	}
	if len(plan.Candidates) != 8 || plan.Dropped != 2 {
		t.Fatalf("standard selection = %d kept / %d dropped, want 8/2", len(plan.Candidates), plan.Dropped)
	}
	tab := findCandidate(plan, `"accesskey=x`+"	"+`onclick=`+m+"	"+`y="`)
	if tab == nil {
		t.Fatalf("the standard profile dropped the accesskey TAB variant: %+v", plan.Candidates)
	}
	for _, dropped := range []string{
		`" accesskey=x onclick=` + m + ` y="`,
		`"` + "	" + `accesskey=x` + "	" + `onclick=` + m + "	" + `y="`,
	} {
		if c := findCandidate(plan, dropped); c != nil {
			t.Fatalf("expected the unchanged cap to leave the link-element shape out, got %+v", c)
		}
	}
}

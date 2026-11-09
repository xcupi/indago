package detection_test

// Quote selection for attribute-closing breakouts.
//
// The analyser reports the delimiter it saw while the probe was parsed, but
// that is only PROOF of the site's delimiter when the reflection came back raw:
// the target echoed the value verbatim, so the quote bytes around the site are
// the template's own. When the target rewrote the value (HTML/URL encoding,
// transformation) the delimiter in force belongs to that rewrite of OUR payload,
// and a single-style breakout is a guess — the measured live-lab failure. In
// that case both quote styles are planned, each labelled with the style it
// assumes (Candidate.Delimiter), so a report can say which one fired.
//
// These tests pin every branch of that rule against served bytes, plus the
// default (named-parameter) plan staying byte-identical.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

const (
	dq = `"`
	sq = `'`
)

// quoteFixture serves a canonical-link page with the probe value inside the
// href. quote picks the delimiter. escaping selects what the target does to the
// value: "none" (raw echo — the delimiter is PROVEN), "angles" (only < and >
// HTML-encoded, quotes stay raw — the documented lab escaping) or "all" (every
// breakout character encoded, the encoded-delimiter control).
func quoteFixture(quote, escaping, value string) []byte {
	switch escaping {
	case "all":
		value = strings.NewReplacer(
			"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
		).Replace(value)
	case "angles":
		value = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(value)
	}
	return []byte(`<!doctype html><html><head><link rel="canonical" href=` + quote +
		`https://lab.example/post?search=` + value + quote + `><title>Post</title></head>` +
		`<body><h1>Post</h1></body></html>`)
}

// urlEncodedQuoteFixture serves the live-lab shape: the target URL-encodes the
// syntax characters (including the double quote) but leaves the single quote
// raw, inside a single-quoted href.
func urlEncodedQuoteFixture(value string) []byte {
	value = strings.NewReplacer("<", "%3c", ">", "%3e", `"`, "%22").Replace(value)
	return []byte(`<!doctype html><html><head><link rel="canonical" href='` +
		`https://lab.example/post?search=` + value + `'><title>Post</title></head>` +
		`<body><h1>Post</h1></body></html>`)
}

// hrefBreakouts returns the planned canonical (SPACE-separated) href
// attribute-breakout candidates. The TAB-separated siblings are a separate
// family (hrefTabBreakouts), so counting the canonical mechanism stays
// meaningful.
func hrefBreakouts(plan *detection.CandidatePlan) []detection.Candidate {
	var out []detection.Candidate
	for _, c := range plan.Candidates {
		if hrefAccesskeyBreakout(c) && !strings.Contains(c.Value, "	") {
			out = append(out, c)
		}
	}
	return out
}

// hrefTabBreakouts returns the planned TAB-separated siblings of the href
// accesskey breakout: same mechanism and quote style, attributes joined by a
// raw TAB instead of a space.
func hrefTabBreakouts(plan *detection.CandidatePlan) []detection.Candidate {
	var out []detection.Candidate
	for _, c := range plan.Candidates {
		if hrefAccesskeyBreakout(c) && strings.Contains(c.Value, "	") {
			out = append(out, c)
		}
	}
	return out
}

// TestUnprovenDelimiterPlansBothQuoteStyles is the core case: the site's value
// was rewritten on the way back (angles encoded), so the delimiter observed at
// the probe is not proof for another payload — both styles are planned, same
// mechanism, each labelled.
func TestUnprovenDelimiterPlansBothQuoteStyles(t *testing.T) {
	m := urlAttrProbe.Token
	body := quoteFixture(dq, "angles", urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	ctx := rep.Locations[0].Context
	if ctx.Quote != "double" || ctx.QuoteProven {
		t.Fatalf("delimiter = %q proven=%v, want an analysed but UNPROVEN double quote", ctx.Quote, ctx.QuoteProven)
	}
	if rep.Locations[0].Encoding == detection.EncNone {
		t.Fatalf("fixture must rewrite the value (encoding %q), otherwise the delimiter would be proven", rep.Locations[0].Encoding)
	}

	got := hrefBreakouts(plan)
	if len(got) != 2 {
		t.Fatalf("unproven delimiter must plan exactly 2 href breakouts, got %d: %+v", len(got), got)
	}
	styles := map[string]string{}
	for _, c := range got {
		if c.Delimiter != "double" && c.Delimiter != "single" {
			t.Fatalf("breakout %q has delimiter %q, want double or single", c.Value, c.Delimiter)
		}
		if _, dup := styles[c.Delimiter]; dup {
			t.Fatalf("two variants assume the same delimiter %q", c.Delimiter)
		}
		styles[c.Delimiter] = c.Value
		if c.Trigger != detection.TriggerInteraction || c.Category != detection.CatURL || c.Priority != 78 {
			t.Fatalf("variant %q = trigger %q category %q priority %d, want the same mechanism as before", c.Value, c.Trigger, c.Category, c.Priority)
		}
		if c.Transformation != "raw" {
			t.Fatalf("variant %q transformation = %q, want raw (both quotes survived)", c.Value, c.Transformation)
		}
		if !strings.Contains(c.Rationale, c.Delimiter+"-quoted") {
			t.Fatalf("rationale must name the delimiter the variant assumes, got %q", c.Rationale)
		}
	}
	if styles["double"] != hrefBreakoutValue("double", m) {
		t.Fatalf("double variant = %q", styles["double"])
	}
	if strings.Contains(styles["double"], "'") {
		t.Fatalf("double variant depends on a raw single quote: %q", styles["double"])
	}
	if styles["single"] != "'accesskey=x onclick="+m+" x='" {
		t.Fatalf("single variant = %q", styles["single"])
	}
}

// TestProvenDelimiterPlansOnlyThatStyle pins the unchanged behaviour: a raw
// echo proves the delimiter, so only the site's own style is planned.
func TestProvenDelimiterPlansOnlyThatStyle(t *testing.T) {
	for _, tc := range []struct{ quote, style string }{
		{dq, "double"},
		{sq, "single"},
	} {
		m := urlAttrProbe.Token
		body := quoteFixture(tc.quote, "none", urlAttrProbe.Value())
		rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

		ctx := rep.Locations[0].Context
		if ctx.Quote != tc.style || !ctx.QuoteProven {
			t.Fatalf("%s fixture: delimiter = %q proven=%v, want a PROVEN %s", tc.style, ctx.Quote, ctx.QuoteProven, tc.style)
		}
		got := hrefBreakouts(plan)
		if len(got) != 1 {
			t.Fatalf("%s fixture: %d href breakouts planned, want exactly 1: %+v", tc.style, len(got), got)
		}
		if got[0].Delimiter != tc.style {
			t.Fatalf("%s fixture: planned delimiter = %q", tc.style, got[0].Delimiter)
		}
		want := hrefBreakoutValue(tc.style, m)
		if got[0].Value != want {
			t.Fatalf("%s fixture: value = %q, want %q", tc.style, got[0].Value, want)
		}
	}
}

// TestEncodedDelimiterPlansNeitherQuoteStyle is the existing strict guard over
// the new expansion: when the site encodes the quotes, no style can close the
// attribute, so neither variant is sent.
func TestEncodedDelimiterPlansNeitherQuoteStyle(t *testing.T) {
	body := quoteFixture(dq, "all", urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	ctx := rep.Locations[0].Context
	if ctx.QuoteProven {
		t.Fatalf("an encoded delimiter must not be reported proven")
	}
	if got := hrefBreakouts(plan); len(got) != 0 {
		t.Fatalf("encoded delimiter planned %d href breakouts, want none: %+v", len(got), got)
	}
}

// TestUnprovenDelimiterDropsOnlyTheEncodedStyle covers the live-lab shape: the
// value is URL-encoded (so the double quote can never arrive raw) but the single
// quote does, inside a single-quoted href. Both styles are considered, and the
// per-variant strict guard keeps only the one whose delimiter survives.
func TestUnprovenDelimiterDropsOnlyTheEncodedStyle(t *testing.T) {
	body := urlEncodedQuoteFixture(urlAttrProbe.Value())
	rep, plan := urlAttrPlan(t, body, domain.LocationRawQuery)

	ctx := rep.Locations[0].Context
	if ctx.Quote != "single" || ctx.QuoteProven {
		t.Fatalf("delimiter = %q proven=%v, want an unproven single quote", ctx.Quote, ctx.QuoteProven)
	}
	if rep.Locations[0].PerChar[dq] == detection.EncNone || rep.Locations[0].PerChar[sq] != detection.EncNone {
		t.Fatalf("fixture must URL-encode the double quote and keep the single quote raw, per-char = %v", rep.Locations[0].PerChar)
	}
	got := hrefBreakouts(plan)
	if len(got) != 1 || got[0].Delimiter != "single" {
		t.Fatalf("want exactly the single-quote variant (the double quote is encoded), got %+v", got)
	}
	// The TAB sibling obeys the same per-variant strict guard: the encoded
	// double quote cannot close the attribute, so only the single-quote TAB
	// sibling may be planned.
	tabs := hrefTabBreakouts(plan)
	if len(tabs) != 1 || tabs[0].Delimiter != "single" {
		t.Fatalf("want exactly the single-quote TAB sibling (the double quote is encoded), got %+v", tabs)
	}
}

// TestUnprovenDelimiterKeepsDefaultPlanUnchanged proves the named-parameter
// (default) plan is byte-identical: the both-styles expansion is reached only
// from the raw-query branch, and the link vector is untouched.
func TestUnprovenDelimiterKeepsDefaultPlanUnchanged(t *testing.T) {
	m := urlAttrProbe.Token
	body := quoteFixture(dq, "angles", urlAttrProbe.Value())

	_, named := urlAttrPlan(t, body, domain.LocationQuery)
	var rendered []string
	for _, c := range named.Candidates {
		rendered = append(rendered, string(c.Category)+"|"+c.Value)
	}
	want := []string{
		"url|" + dq + " accesskey=x onclick=" + m + " y=" + dq,
		"url|" + dq + "	accesskey=x	onclick=" + m + "	y=" + dq,
	}
	if strings.Join(rendered, "\n") != strings.Join(want, "\n") {
		t.Fatalf("default plan changed:\n got: %v\nwant: %v", rendered, want)
	}
	if got := hrefBreakouts(named); len(got) != 0 {
		t.Fatalf("default plan gained a raw-query href breakout: %+v", got)
	}
}

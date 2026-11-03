package detection_test

// The PortSwigger "Reflected XSS into a template literal with angle brackets,
// single, double quotes, backslash and backticks Unicode-escaped" shape,
// reproduced byte for byte on a loopback fixture.
//
// The reader reflects the value inside a JS TEMPLATE LITERAL and \uXXXX-escapes
// every character that could end or alter it — angle brackets, both quotes, the
// backslash and the backtick. Consequences, in order:
//
//   - the literal cannot be CLOSED (the backtick comes back as \u0060), so a
//     closing-quote/backtick breakout is impossible;
//   - the script element cannot be ended either (< and > come back escaped), so
//     the </script><script>M</script> shape is impossible;
//   - the only remaining route to execution is ${...} substitution, which the
//     reader leaves alone.
//
// The planner's ${MARKER} candidate is therefore the single route for this
// reader, and this file pins (a) the exact served bytes, (b) the classification
// and (c) the plan — including the neutralised control, where '$', '{' and '}'
// are escaped too and the same candidate must stay inert TEXT.
//
// Note on the control: HTML-escaping does NOT neutralise ${MARKER} — none of
// '$', '{' or '}' is HTML-special, and character references are not decoded
// inside a <script> element anyway. A reader only neutralises the shape by
// escaping those characters (or the whole opener as \${) before serving it, so
// the control implements that, not html.EscapeString.

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// tplProbe is a fixed probe so the expected bytes below can be written out
// literally instead of re-derived from the fixture's own helpers.
var tplProbe = detection.NewProbe(domain.ID("ps-template-fixture"), domain.ID("ip"))

// tplEscape applies the lab's reader rule: <, >, ', ", \ and the backtick are
// \uXXXX-escaped. When interp is set the interpolation characters are escaped
// too — the neutralised control.
func tplEscape(v string, interp bool) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '<', '>', '\'', '"', '\\', '`':
			fmt.Fprintf(&b, `\u%04x`, r)
		case '$', '{', '}':
			if interp {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// tplPage is the lab's document shape: the value inside the template literal,
// with the page's own document.write line after it (so the site is not the last
// thing in the script body).
func tplPage(v string, interp bool) string {
	return "<!doctype html>\n<html>\n<head><title>Search results</title></head>\n<body>\n<h1>Search results</h1>\n" +
		"<script>\n    var searchTerms = `" + tplEscape(v, interp) + "`;\n" +
		"    document.write('<p>Your search for <b>' + searchTerms + '</b> returned no results.</p>');\n" +
		"</script>\n</body>\n</html>"
}

// newTemplateLab serves /lab (the reader that leaves ${} alone) and /control
// (the reader that escapes it too).
func newTemplateLab(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(interp bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, tplPage(r.URL.Query().Get("search"), interp))
		}
	}
	mux.HandleFunc("/lab", serve(false))
	mux.HandleFunc("/control", serve(true))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// tplGet returns the served body for one request, failing the test on error.
func tplGet(t *testing.T, rawurl string) string {
	t.Helper()
	resp, err := http.Get(rawurl)
	if err != nil {
		t.Fatalf("GET %s: %v", rawurl, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", rawurl, err)
	}
	return string(body)
}

// tplInjected returns the bytes the reader actually served between the opening
// backtick and the literal's terminator — the injected region, isolated from
// the page's own markup.
func tplInjected(t *testing.T, body string) string {
	t.Helper()
	const open = "var searchTerms = `"
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("served body has no template literal assignment at all:\n%q", body)
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, "`;")
	if j < 0 {
		t.Fatalf("served template literal is unterminated (the reader did not serve a closing backtick):\n%q", rest)
	}
	return rest[:j]
}

// TestTemplateLiteralFixtureServesExactEscapedBytes asserts the served bytes
// themselves: the escapes ARE the subject, so nothing else may run before them.
func TestTemplateLiteralFixtureServesExactEscapedBytes(t *testing.T) {
	lab := newTemplateLab(t)

	// The probe value is token + <>"' + tail. The reader must return exactly
	// \u003c\u003e\u0022\u0027 in place of the canary. Written out literally.
	want := "<!doctype html>\n<html>\n<head><title>Search results</title></head>\n<body>\n<h1>Search results</h1>\n" +
		"<script>\n    var searchTerms = `" + tplProbe.Token + `\u003c\u003e\u0022\u0027` + tplProbe.Tail + "`;\n" +
		"    document.write('<p>Your search for <b>' + searchTerms + '</b> returned no results.</p>');\n" +
		"</script>\n</body>\n</html>"

	got := tplGet(t, lab.URL+"/lab?search="+tplProbe.Value())
	if got != want {
		t.Fatalf("served bytes:\n got %q\nwant %q", got, want)
	}
	// A second request proves the fixture also escapes the backslash and the
	// backtick — the two characters that make closing the literal impossible.
	got = tplGet(t, lab.URL+"/lab?search="+"a%5C%60b")
	if want := "a\\u005c\\u0060b"; tplInjected(t, got) != want {
		t.Fatalf("backslash/backtick escaping: injected region = %q, want %q", tplInjected(t, got), want)
	}
}

// TestTemplateLiteralInterpolationIsTheOnlyPlannedRoute runs the real
// reflection → context → planning pipeline over the served bytes and pins what
// the planner can do at this site: exactly one candidate, and it is ${MARKER}.
// No quote, angle bracket or backtick appears in it, because the reader escapes
// all of them; the quote-breaking shapes stay in the planner for the readers
// that need them (candidate_jsstring_test.go), they are simply unusable here.
func TestTemplateLiteralInterpolationIsTheOnlyPlannedRoute(t *testing.T) {
	lab := newTemplateLab(t)
	body := []byte(tplGet(t, lab.URL+"/lab?search="+tplProbe.Value()))

	rep := detection.AnalyzeReflection(tplProbe, nil, body)
	rep.Parameter, rep.Location = "search", domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html; charset=utf-8"})
	if !rep.Reflected || len(rep.Locations) != 1 {
		t.Fatalf("reflection = %v (%d sites), want exactly 1", rep.Reflected, len(rep.Locations))
	}
	ctx := rep.Locations[0].Context
	if ctx == nil || ctx.Context != detection.CtxJSString || ctx.Sub != "template_literal" {
		t.Fatalf("context = %+v, want js_string:template_literal", ctx)
	}
	for _, ch := range []string{"<", ">", `"`, "'"} {
		if got := rep.Locations[0].PerChar[ch]; got != detection.EncJS {
			t.Errorf("per-char %q = %q, want js (the reader Unicode-escapes it)", ch, got)
		}
	}

	plan := detection.PlanCandidates(&rep, detection.PlanOptions{ScanID: domain.ID("s"), InjectionPointID: domain.ID("i")})
	want := "${" + tplProbe.Token + "}"
	if len(plan.Candidates) != 1 || plan.Candidates[0].Value != want {
		t.Fatalf("plan = %v, want exactly [%q]: interpolation is this reader's only route", tplValues(plan), want)
	}
	c := plan.Candidates[0]
	if c.Category != detection.CatJS || c.Trigger != detection.TriggerLoad {
		t.Fatalf("candidate = %s/%s, want a load-trigger javascript candidate", c.Category, c.Trigger)
	}
	// The shape depends on characters the probe canary does not contain ('$',
	// '{', '}'), so the planner cannot observe whether the reader preserves
	// them; it must not claim they were neutralised either. It is planned at
	// full priority and sent regardless — it is the only executable route.
	if c.Transformation != "raw" || c.Priority < 80 {
		t.Fatalf("transformation=%q priority=%d, want raw and a high priority", c.Transformation, c.Priority)
	}
	// Interpolation needs no quote, angle bracket or backtick: if one appeared
	// the candidate would be broken for exactly this reader.
	for _, ch := range []string{"<", ">", `"`, "'", "`", "\\"} {
		if strings.Contains(c.Value, ch) {
			t.Errorf("candidate %q contains %q, but the reader escapes it", c.Value, ch)
		}
	}
	// The rationale must record WHY this is the only route (it is evidence an
	// operator reads on the finding), not just restate the value.
	for _, want := range []string{"template literal", "only route", "${MARKER}", "probe canary"} {
		if !strings.Contains(c.Rationale, want) {
			t.Errorf("rationale %q does not explain the escaping rule (missing %q)", c.Rationale, want)
		}
	}
	spec, err := detection.ResolveProfile("standard", 0)
	if err != nil {
		t.Fatal(err)
	}
	sel, dropped := spec.Select(plan.Candidates)
	if len(sel) != 1 || dropped != 0 || sel[0].Value != want {
		t.Fatalf("standard selection = %v (dropped %d), want the interpolation candidate", tplValuesOf(sel), dropped)
	}
}

// TestTemplateLiteralNeutralisedControlServesInertBytes is the control: the
// same reader, but '$', '{' and '}' are escaped too, so ${MARKER} is served as
// inert template TEXT (\u0024\u007bMARKER\u007d) instead of an interpolation.
//
// This is a byte-level assertion on purpose. Whether such a page yields a
// REFLECTED-BUT-NOT-EXECUTED (Rejected) verdict is the browser verifier's call
// and is already covered end to end by the /safe-template control in
// internal/scan/jsstring_fixture_test.go, a required root of
// scripts/ci-browser-check.py. The planner still plans the candidate here
// because '$', '{', '}' are outside the probe canary: it cannot see the
// neutralisation, and a shape it cannot see is never dropped.
func TestTemplateLiteralNeutralisedControlServesInertBytes(t *testing.T) {
	lab := newTemplateLab(t)
	value := "${" + tplProbe.Token + "}"

	positive := tplInjected(t, tplGet(t, lab.URL+"/lab?search="+value))
	if positive != value {
		t.Fatalf("positive reader served %q, want the interpolation intact (%q)", positive, value)
	}
	control := tplInjected(t, tplGet(t, lab.URL+"/control?search="+value))
	want := `\u0024\u007b` + tplProbe.Token + `\u007d`
	if control != want {
		t.Fatalf("control reader served %q, want %q (the interpolation opener escaped)", control, want)
	}
	if strings.Contains(control, "${") {
		t.Fatalf("control served a live interpolation opener: %q", control)
	}

	// The control still reflects (so a finding exists and the attempt is
	// recorded); it is the execution signal that must be absent.
	body := []byte(tplGet(t, lab.URL+"/control?search="+value))
	if !strings.Contains(string(body), tplProbe.Token) {
		t.Fatal("control does not reflect the marker at all; it would produce no finding and prove nothing")
	}
}

func tplValues(p *detection.CandidatePlan) []string {
	if p == nil {
		return nil
	}
	return tplValuesOf(p.Candidates)
}

func tplValuesOf(cs []detection.Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Value)
	}
	return out
}

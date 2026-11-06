package detection_test

import (
	"html"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

// A single-quoted JavaScript string whose reader backslash-escapes the quote
// cannot be closed by a quote at all: the injected quote comes back as \', so
// the string stays open. Two shapes still reach an executable position without
// needing a raw quote:
//
//   - a literal </script> ends the SCRIPT ELEMENT from the HTML tokenizer's
//     point of view (the HTML tokenizer does not track JS string state), and a
//     fresh <script> block whose entire body is the marker then runs;
//   - a leading backslash consumes the escaping backslash the reader inserts,
//     leaving the quote that follows it raw.
//
// Both are canonical, unobfuscated, benign-marker detection probes; neither
// needs a character the reader escapes in its own right.
func TestPlanJSStringEscapeBreakingShapes(t *testing.T) {
	m := tok()

	// Lab 1's reader: backslash doubled, then single quote escaped.
	quoteAndBackslash := func(v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		return strings.ReplaceAll(v, `'`, `\'`)
	}
	// Lab 2's reader: angle brackets and double quotes HTML-encoded, single
	// quote escaped, backslash NOT escaped.
	angleQuotes := func(v string) string {
		v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		return strings.ReplaceAll(v, `'`, `\'`)
	}

	t.Run("quote-and-backslash-escaped string gets the script-close shape", func(t *testing.T) {
		rep := planDoc(t, `<script>var searchTerms = '{{M}}';</script>`, candHTML, quoteAndBackslash)
		want := "</script><script>" + m + "</script>"
		c := mustFind(t, rep.Plan, want)
		if c.Context != detection.CtxJSString || c.ContextSub != "single_quoted" {
			t.Fatalf("context = %s:%s, want js_string:single_quoted", c.Context, c.ContextSub)
		}
		if c.Trigger != detection.TriggerLoad {
			t.Fatalf("trigger = %q, want load (the fresh script block runs on parse)", c.Trigger)
		}
		// < and > survive this reader, so the shape is not deprioritized.
		if c.Transformation != "raw" || c.Priority < 50 {
			t.Fatalf("transformation=%q priority=%d, want raw and a high priority", c.Transformation, c.Priority)
		}
	})

	t.Run("html-encoded angle brackets still get the backslash break", func(t *testing.T) {
		rep := planDoc(t, `<script>var searchTerms = '{{M}}';</script>`, candHTML, angleQuotes)
		c := mustFind(t, rep.Plan, `\';`+m+`//`)
		if c.Context != detection.CtxJSString || c.ContextSub != "single_quoted" {
			t.Fatalf("context = %s:%s, want js_string:single_quoted", c.Context, c.ContextSub)
		}
		if c.Trigger != detection.TriggerLoad {
			t.Fatalf("trigger = %q, want load", c.Trigger)
		}
		// The probe can only observe that the quote came back escaped; it has no
		// backslash in its canary, so it cannot tell whether backslash is
		// escaped too. The shape must still be planned (deprioritized, never
		// dropped): this is exactly the reader it exists for.
		found := false
		for _, cand := range rep.Plan.Candidates {
			if cand.Value == c.Value {
				found = true
			}
		}
		if !found {
			t.Fatalf("the backslash break must survive planning, got %v", valuesOf(rep.Plan))
		}
	})

	t.Run("plain single-quoted string keeps the canonical quote escape first", func(t *testing.T) {
		rep := planDoc(t, `<script>var searchTerms = '{{M}}';</script>`, candHTML, raw)
		if len(rep.Plan.Candidates) == 0 {
			t.Fatal("expected candidates")
		}
		first := rep.Plan.Candidates[0]
		if first.Value != "';"+m+"//" {
			t.Fatalf("top candidate = %q, want the canonical quote escape", first.Value)
		}
	})
}

// The same new shape must not be planned for a double-quoted string: that
// context keeps its own quote-aware breakout, and this slice adds no
// candidate class beyond the three measured labs.
func TestPlanJSStringEscapeBreakingShapesAreSingleQuotedOnly(t *testing.T) {
	rep := planDoc(t, `<script>var searchTerms = "{{M}}";</script>`, candHTML, html.EscapeString)
	for _, c := range rep.Plan.Candidates {
		if strings.Contains(c.Value, "</script>") || strings.HasPrefix(c.Value, `\';`) {
			t.Fatalf("double-quoted site got a single-quoted-only shape: %q", c.Value)
		}
	}
}

// The `minimal` profile keeps one candidate per context. For a reader that
// escapes the quote but leaves backslash alone, the only route that works is
// the backslash break, so that is the one the single js_string slot must hold —
// even though the probe cannot prove the backslash arrives raw (the canary has
// none). It ranks above provably-neutralized shapes and below proven-raw ones,
// so a reader that also escapes backslash still prefers its raw route.
func TestPlanMinimalProfileKeepsTheOnlyWorkableRouteForTheReader(t *testing.T) {
	m := tok()
	angleQuotes := func(v string) string {
		v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		return strings.ReplaceAll(v, `'`, `\'`)
	}
	quoteAndBackslash := func(v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		return strings.ReplaceAll(v, `'`, `\'`)
	}
	spec, err := detection.ResolveProfile("minimal", 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("quote-escaping reader keeps the backslash break", func(t *testing.T) {
		rep := planDoc(t, `<script>var searchTerms = '{{M}}';</script>`, candHTML, angleQuotes)
		selected, dropped := spec.Select(rep.Plan.Candidates)
		if len(selected) != 1 || selected[0].Value != `\';`+m+`//` {
			var got []string
			for _, c := range selected {
				got = append(got, c.Value)
			}
			t.Fatalf("minimal selection = %v, want only the backslash break", got)
		}
		if dropped == 0 {
			t.Fatal("expected the other shapes to be reported as dropped, not silently missing")
		}
	})

	t.Run("quote-and-backslash reader keeps the raw script close", func(t *testing.T) {
		rep := planDoc(t, `<script>var searchTerms = '{{M}}';</script>`, candHTML, quoteAndBackslash)
		selected, _ := spec.Select(rep.Plan.Candidates)
		if len(selected) == 0 || selected[0].Value != "</script><script>"+m+"</script>" {
			var got []string
			for _, c := range selected {
				got = append(got, c.Value)
			}
			t.Fatalf("minimal selection = %v, want the raw script close", got)
		}
	})
}

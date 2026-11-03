package detection_test

// Coverage for the angular_expression sink category (AngularJS text-node
// interpolation):
//   - exactly one interpolation candidate per (source, sink);
//   - the candidate never contains the contiguous marker, which is what makes
//     an observed marker in rendered text a compilation signal rather than a
//     reflection match;
//   - every pre-existing sink's planned value AND dedup key is byte-identical
//     (the regression the slice requires), with angular_expression the only
//     addition.
// Pure: no browser, no network. The executing behaviour is covered by the
// browser_integration tests in internal/scan.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func TestDOMXSSAngularInterpolationCandidate(t *testing.T) {
	const marker = "ANGULARMARKER42"
	for _, source := range detection.DOMXSSSources {
		shapes := detection.DOMXSSPayloadsFor(source, detection.DOMSinkAngularExpression, marker)
		if len(shapes) != 1 {
			t.Fatalf("%s: angular_expression must plan exactly one shape, got %d: %+v", source, len(shapes), shapes)
		}
		cand := shapes[0]
		wantValue := "{{'" + marker[:len(marker)/2] + "' + '" + marker[len(marker)/2:] + "' + ($id ? '' : '')}}"
		if cand.Value != wantValue {
			t.Fatalf("%s: want %q, got %q", source, wantValue, cand.Value)
		}
		if strings.Contains(cand.Value, marker) {
			t.Fatalf("%s: candidate %q must never contain the contiguous marker, or a page that merely echoes it could match", source, cand.Value)
		}
		if !strings.Contains(cand.Value, "{{") || !strings.Contains(cand.Value, "}}") {
			t.Fatalf("%s: candidate must be a double-brace interpolation, got %q", source, cand.Value)
		}
		if strings.ContainsAny(cand.Value, "<>") {
			t.Fatalf("%s: candidate must not carry markup, got %q", source, cand.Value)
		}
		if cand.Category != detection.CatDOMXSS || cand.Source != detection.SourceBuiltin ||
			string(cand.Context) != "angular_expression" || cand.ContextSub != string(source) || cand.Trigger != detection.TriggerLoad {
			t.Fatalf("%s: wrong provenance/field repurposing: %+v", source, cand)
		}
		if !strings.Contains(cand.Rationale, "interpolation") || !strings.Contains(cand.Rationale, "never contain the marker contiguously") {
			t.Fatalf("%s: rationale must state the text-node mechanism and the split-marker specificity, got %q", source, cand.Rationale)
		}
		if !strings.Contains(cand.Rationale, "csp_blocked") {
			t.Fatalf("%s: rationale must name the distinct CSP outcome, got %q", source, cand.Rationale)
		}
		if again := detection.DOMXSSPayloadsFor(source, detection.DOMSinkAngularExpression, marker); len(again) != 1 || again[0] != cand {
			t.Fatalf("%s: planner is not deterministic", source)
		}
	}
}

func TestDOMXSSAngularRejectsUnusableMarkers(t *testing.T) {
	for _, marker := range []string{"", "a", "abc", "1bad", "x;y", "x y", "x\ny", "true", "undefined"} {
		if got := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMSinkAngularExpression, marker); len(got) != 0 {
			t.Fatalf("marker %q must not produce an interpolation candidate: %+v", marker, got)
		}
	}
	if !detection.DOMSinkAngularExpression.IsValid() {
		t.Fatal("angular_expression must be a valid sink")
	}
	if got := detection.DOMXSSPayloadsFor("eval", detection.DOMSinkAngularExpression, "MARKER42"); len(got) != 0 {
		t.Fatalf("unknown source must produce nothing: %+v", got)
	}
}

// TestDOMXSSExistingSinkPlansAreByteIdentical is the regression gate: the exact
// value AND dedup key of every pre-existing sink plan, including the new sink's
// neighbours, must not have moved. angular_expression is additive only.
func TestDOMXSSExistingSinkPlansAreByteIdentical(t *testing.T) {
	const marker = "GOLDENMARKER42"
	type shape struct{ name, value string }
	markup := "<img src=x onerror=" + marker + ">"
	breakout := `"><img src=y onerror=` + marker + ">"

	golden := []struct {
		sink   detection.DOMXSSSink
		source detection.DOMXSSSource
		shapes []shape
	}{
		{detection.DOMSinkInnerHTML, detection.DOMSourceHash, []shape{{"markup", markup}, {"attr_breakout", breakout}}},
		{detection.DOMSinkOuterHTML, detection.DOMSourceHash, []shape{{"markup", markup}, {"attr_breakout", breakout}}},
		{detection.DOMSinkInsertAdjacentHTML, detection.DOMSourceHash, []shape{{"markup", markup}, {"attr_breakout", breakout}}},
		{detection.DOMSinkCreateContextualFragment, detection.DOMSourceHash, []shape{{"markup", markup}, {"attr_breakout", breakout}}},
		{detection.DOMSinkDocumentWrite, detection.DOMSourceHash, []shape{{"markup", markup}, {"attr_breakout", breakout}}},
		{detection.DOMSinkDocumentWrite, detection.DOMSourceQuery, []shape{{"markup", "<script>" + marker + "</script>"}, {"attr_breakout", breakout}}},
		{detection.DOMSinkSetTimeout, detection.DOMSourceHash, []shape{{"timer_expression", marker}}},
		{detection.DOMSinkSetInterval, detection.DOMSourceHash, []shape{{"timer_expression", marker}}},
		{detection.DOMSinkJQueryAttr, detection.DOMSourceHash, []shape{{"jquery_javascript_url", "javascript:" + marker}}},
		{detection.DOMSinkJQuerySelector, detection.DOMSourceHash, []shape{{"markup", markup}}},
	}
	for _, tc := range golden {
		got := detection.DOMXSSPayloadsFor(tc.source, tc.sink, marker)
		if len(got) != len(tc.shapes) {
			t.Fatalf("%s/%s: want %d shape(s), got %d: %+v", tc.source, tc.sink, len(tc.shapes), len(got), got)
		}
		for i, want := range tc.shapes {
			if got[i].Value != want.value {
				t.Fatalf("%s/%s shape %d: value changed: want %q, got %q", tc.source, tc.sink, i, want.value, got[i].Value)
			}
			wantKey := "dom_xss\x00" + string(tc.source) + "\x00" + string(tc.sink) + "\x00" + want.name + "\x00" + want.value
			if got[i].DedupKey != wantKey {
				t.Fatalf("%s/%s shape %d: dedup key changed: want %q, got %q", tc.source, tc.sink, i, wantKey, got[i].DedupKey)
			}
		}
		// The primary candidate view must agree with the first shape.
		primary, ok := detection.DOMXSSPayloadFor(tc.source, tc.sink, marker)
		if !ok || primary != got[0] {
			t.Fatalf("%s/%s: primary candidate changed: %+v", tc.source, tc.sink, primary)
		}
	}

	// Every existing sink still plans for every source, so the new category
	// did not accidentally narrow the planner.
	for _, sink := range []detection.DOMXSSSink{
		detection.DOMSinkInnerHTML, detection.DOMSinkOuterHTML, detection.DOMSinkDocumentWrite,
		detection.DOMSinkInsertAdjacentHTML, detection.DOMSinkCreateContextualFragment,
		detection.DOMSinkSetTimeout, detection.DOMSinkSetInterval,
		detection.DOMSinkJQueryAttr, detection.DOMSinkJQuerySelector,
	} {
		for _, source := range detection.DOMXSSSources {
			if got := detection.DOMXSSPayloadsFor(source, sink, marker); len(got) == 0 {
				t.Fatalf("%s/%s: existing sink lost its plan", source, sink)
			}
		}
	}
}

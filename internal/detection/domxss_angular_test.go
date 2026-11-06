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
	"fmt"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

// angularShape returns the candidate with the given shape, or fails.
func angularShape(t *testing.T, cands []detection.Candidate, shape string) detection.Candidate {
	t.Helper()
	for _, c := range cands {
		if c.Shape == shape {
			return c
		}
	}
	t.Fatalf("no %s candidate among %d: %+v", shape, len(cands), cands)
	return detection.Candidate{}
}

func TestDOMXSSAngularInterpolationCandidate(t *testing.T) {
	const marker = "angularmarker42"
	for _, source := range detection.DOMXSSSources {
		shapes := detection.DOMXSSPayloadsFor(source, detection.DOMSinkAngularExpression, marker)
		// The query source also plans the two parameter-NAME shapes (below);
		// every other source has no parameter name to deliver, so it plans
		// exactly the interpolation.
		wantShapes := 1
		if source == detection.DOMSourceQuery {
			wantShapes = 3
		}
		if len(shapes) != wantShapes {
			t.Fatalf("%s: angular_expression must plan %d shape(s), got %d: %+v", source, wantShapes, len(shapes), shapes)
		}
		if source == detection.DOMSourceQuery && shapes[0].Shape != "angular_sandbox_escape" {
			t.Fatalf("%s: the execution shape must be tried before the compilation shapes, got %q first", source, shapes[0].Shape)
		}
		cand := angularShape(t, shapes, "angular_interpolation")
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
		if cand.Shape != "angular_interpolation" || detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
			t.Fatalf("%s: the interpolation shape must be value-delivered, got shape %q", source, cand.Shape)
		}
		if !strings.Contains(cand.Rationale, "interpolation") || !strings.Contains(cand.Rationale, "never contain the marker contiguously") {
			t.Fatalf("%s: rationale must state the text-node mechanism and the split-marker specificity, got %q", source, cand.Rationale)
		}
		if !strings.Contains(cand.Rationale, "csp_blocked") {
			t.Fatalf("%s: rationale must name the distinct CSP outcome, got %q", source, cand.Rationale)
		}
		again := detection.DOMXSSPayloadsFor(source, detection.DOMSinkAngularExpression, marker)
		if len(again) != wantShapes {
			t.Fatalf("%s: planner is not deterministic (len %d vs %d)", source, len(again), wantShapes)
		}
		for i := range again {
			if again[i] != shapes[i] {
				t.Fatalf("%s: planner is not deterministic at %d: %q vs %q", source, i, again[i].Shape, shapes[i].Shape)
			}
		}
	}
}

// TestDOMXSSAngularParseExpressionShape covers the second, query-only shape:
// the same sink reached through a page that hands each parameter NAME to
// AngularJS's $parse. It must be a quote-free expression that rebuilds the
// marker from number-to-string terms, must be delivered as a parameter NAME,
// and must never carry the contiguous marker.
func TestDOMXSSAngularParseExpressionShape(t *testing.T) {
	const marker = "inddd525eb0320dca43"
	got := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkAngularExpression, marker)
	if len(got) != 3 {
		t.Fatalf("query source must plan the interpolation, the parameter-name and the sandbox-escape shapes, got %d: %+v", len(got), got)
	}
	cand := angularShape(t, got, "angular_parse_expression")
	if !detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
		t.Fatal("the executor must be told this shape needs parameter-name delivery")
	}
	// A page that rewrites both quote styles into character references inside
	// its inline <script> leaves no usable string literal, so the expression
	// must contain none — and it must not smuggle in an escape either.
	for _, forbidden := range []string{"'", `"`, "`", "{{", "}}", "<", ">", "&", "$", "constructor", "prototype", "__proto__", "eval", "window", "document", "alert", "cookie"} {
		if strings.Contains(cand.Value, forbidden) {
			t.Fatalf("candidate must not contain %q: %q", forbidden, cand.Value)
		}
	}
	if strings.Contains(cand.Value, marker) {
		t.Fatalf("candidate must never contain the contiguous marker: %q", cand.Value)
	}
	// The terms must actually rebuild the marker: decode every term the same
	// way Angular does (a number literal, rendered in base 36) and join them.
	body := strings.TrimSuffix(strings.TrimPrefix(cand.Value, "["), "].join([])")
	var built strings.Builder
	for _, term := range strings.Split(body, ",") {
		var digit int
		if _, err := fmt.Sscanf(term, "(%d).toString(36)", &digit); err != nil || digit < 0 || digit >= 36 {
			t.Fatalf("term %q is not a base-36 number-to-string term: %v", term, err)
		}
		if digit < 10 {
			built.WriteByte(byte('0' + digit))
		} else {
			built.WriteByte(byte('a' + digit - 10))
		}
	}
	if built.String() != marker {
		t.Fatalf("expression rebuilds %q, want the marker %q", built.String(), marker)
	}
	if cand.Category != detection.CatDOMXSS || cand.ContextSub != string(detection.DOMSourceQuery) ||
		string(cand.Context) != "angular_expression" || cand.Trigger != detection.TriggerLoad {
		t.Fatalf("wrong provenance: %+v", cand)
	}
	if !strings.Contains(cand.Rationale, "query parameter NAME") || !strings.Contains(cand.Rationale, "never contain the marker contiguously") {
		t.Fatalf("rationale must state the delivery channel and the marker specificity: %q", cand.Rationale)
	}
	if !strings.Contains(cand.Rationale, "csp_blocked") {
		t.Fatalf("rationale must name the distinct CSP outcome: %q", cand.Rationale)
	}
	if cand.DedupKey == got[0].DedupKey {
		t.Fatal("the two shapes must not share a dedup key")
	}
	// A marker the base-36 construction cannot represent must not produce a
	// dead candidate: the interpolation shape is still planned, and so is the
	// sandbox escape (it carries the marker as character codes, so it is
	// representable for ANY marker). The parameter-name expression is the one
	// shape that is dropped. (A marker that is not a valid DOM-XSS marker at all
	// plans nothing, which the existing rejects-unusable-markers test pins.)
	for _, m := range []string{"UPPERmarker42", "mark_er42"} {
		shapes := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkAngularExpression, m)
		if len(shapes) != 2 || shapes[0].Shape != "angular_sandbox_escape" || shapes[1].Shape != "angular_interpolation" {
			t.Fatalf("marker %q must plan sandbox escape + interpolation only, got %+v", m, shapes)
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

// TestDOMXSSAngularSandboxEscapeShape covers the third, query-only shape: the
// same parameter-NAME binding, but an expression that ESCAPES the AngularJS
// sandbox and evaluates code, so execution (not just compilation) can be
// observed. It must follow the published technique — overwhelm charAt through
// the String prototype, then build x=alert('<marker>') from character codes —
// carry the marker only inside those codes, and be delivered as a param NAME.
func TestDOMXSSAngularSandboxEscapeShape(t *testing.T) {
	const marker = "inddd525eb0320dca43"
	got := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkAngularExpression, marker)
	cand := angularShape(t, got, "angular_sandbox_escape")
	if !detection.DOMXSSShapeNeedsParameterName(cand.Shape) {
		t.Fatal("the executor must be told this shape needs parameter-name delivery")
	}
	for _, want := range []string{"constructor.prototype.charAt", "[].join", "|orderBy:", "fromCharCode("} {
		if !strings.Contains(cand.Value, want) {
			t.Fatalf("escape shape must contain %q: %q", want, cand.Value)
		}
	}
	// The marker must travel ONLY as character codes: the contiguous marker in
	// the candidate bytes would let a page that merely echoes the parameter name
	// fake the dialog check.
	if strings.Contains(cand.Value, marker) {
		t.Fatalf("candidate must never contain the contiguous marker: %q", cand.Value)
	}
	// Decode the fromCharCode argument list the way JavaScript does and require
	// the exact alert statement it is supposed to build.
	body := cand.Value[strings.Index(cand.Value, "fromCharCode(")+len("fromCharCode("):]
	body = strings.TrimSuffix(body, ")")
	var built strings.Builder
	for _, part := range strings.Split(body, ",") {
		var code int
		if _, err := fmt.Sscanf(part, "%d", &code); err != nil || code < 32 || code > 126 {
			t.Fatalf("fromCharCode argument %q is not a printable ASCII code: %v", part, err)
		}
		built.WriteByte(byte(code))
	}
	if want := "x=alert('" + marker + "')"; built.String() != want {
		t.Fatalf("escape builds %q, want %q", built.String(), want)
	}
	if !strings.Contains(cand.Rationale, "DIALOG") {
		t.Fatalf("rationale must say the confirmation is a dialog, got %q", cand.Rationale)
	}
}

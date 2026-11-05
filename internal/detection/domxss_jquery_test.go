package detection_test

// jQuery sink coverage: the two PortSwigger jQuery sinks must be first-class
// DOM sinks with their own deterministic, bounded candidate shapes. The
// attribute write needs a javascript: URL that only executes on activation;
// the selector call needs markup that jQuery parses as HTML. Both stay
// benign-marker probes and confirmation still requires the engine-attributed
// marker execution, never a reflection.
//
// Written with string literals first so the RED run fails on behavior
// (IsValid false / no candidate) instead of on a missing Go symbol.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

var (
	jqueryAttrSink     = detection.DOMXSSSink("jQuery.attr")
	jquerySelectorSink = detection.DOMXSSSink("jQuery.selector")
)

func TestDOMXSSJQuerySinksAreFirstClass(t *testing.T) {
	for _, sink := range []detection.DOMXSSSink{jqueryAttrSink, jquerySelectorSink} {
		if !sink.IsValid() {
			t.Fatalf("%q must be a valid DOM sink", sink)
		}
	}
	// The seven existing sinks stay valid; the new ones are additive.
	for _, sink := range []detection.DOMXSSSink{
		detection.DOMSinkInnerHTML, detection.DOMSinkOuterHTML, detection.DOMSinkDocumentWrite,
		detection.DOMSinkInsertAdjacentHTML, detection.DOMSinkCreateContextualFragment,
		detection.DOMSinkSetTimeout, detection.DOMSinkSetInterval,
	} {
		if !sink.IsValid() {
			t.Fatalf("existing sink %q must stay valid", sink)
		}
	}
	if detection.DOMXSSSink("jQuery.html").IsValid() {
		t.Fatal("unimplemented jQuery sink must stay invalid")
	}
	if s, a := jqueryAttrSink, jquerySelectorSink; s == a {
		t.Fatal("the two jQuery sinks must be distinguishable by name")
	}
}

func TestDOMXSSJQueryAttrPayloadIsAnActivatableJavascriptURL(t *testing.T) {
	const marker = "JQUERYATTRMARKER"
	for _, source := range detection.DOMXSSSources {
		shapes := detection.DOMXSSPayloadsFor(source, jqueryAttrSink, marker)
		if len(shapes) != 1 {
			t.Fatalf("%s/jQuery.attr: want exactly the javascript: URL shape, got %d: %+v", source, len(shapes), shapes)
		}
		got := shapes[0]
		if got.Value != "javascript:"+marker {
			t.Fatalf("%s/jQuery.attr: got %q, want the bare javascript: marker expression", source, got.Value)
		}
		if strings.ContainsAny(got.Value, "<>\"'") {
			t.Fatalf("%s/jQuery.attr: shape must carry no markup or quotes: %q", source, got.Value)
		}
		if got.Category != detection.CatDOMXSS || string(got.Context) != "jQuery.attr" || got.ContextSub != string(source) {
			t.Fatalf("%s/jQuery.attr: candidate field repurposing changed: %+v", source, got)
		}
		if !strings.Contains(got.Rationale, "activation") || !strings.Contains(got.Rationale, "marker-specific") {
			t.Fatalf("%s/jQuery.attr: rationale must state the activation step and the marker-specific signal, got %q", source, got.Rationale)
		}
	}
}

func TestDOMXSSJQuerySelectorPayloadIsMarkupThatjQueryParses(t *testing.T) {
	const marker = "JQUERYSELECTORMARKER"
	for _, source := range detection.DOMXSSSources {
		shapes := detection.DOMXSSPayloadsFor(source, jquerySelectorSink, marker)
		if len(shapes) != 1 {
			t.Fatalf("%s/jQuery.selector: want exactly the markup shape, got %d: %+v", source, len(shapes), shapes)
		}
		got := shapes[0]
		if got.Value != "<img src=x onerror="+marker+">" {
			t.Fatalf("%s/jQuery.selector: got %q, want the benign marker image", source, got.Value)
		}
		if !strings.Contains(got.Rationale, "jQuery") || !strings.Contains(got.Rationale, "marker-specific") {
			t.Fatalf("%s/jQuery.selector: rationale must name the sink and the marker-specific signal, got %q", source, got.Rationale)
		}
	}
}

func TestDOMXSSJQuerySinkIdentitiesAreDistinctAndDeterministic(t *testing.T) {
	const marker = "JQUERYIDENTITYMARKER"
	attr := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, jqueryAttrSink, marker)
	sel := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, jquerySelectorSink, marker)
	if len(attr) != 1 || len(sel) != 1 {
		t.Fatalf("want one candidate each, got %d/%d", len(attr), len(sel))
	}
	if attr[0].DedupKey == sel[0].DedupKey {
		t.Fatalf("jQuery.attr and jQuery.selector must not share a dedup key: %q", attr[0].DedupKey)
	}
	html := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkInnerHTML, marker)
	for _, other := range html {
		if other.DedupKey == attr[0].DedupKey {
			t.Fatalf("jQuery.attr must not collide with an HTML sink: %q", other.DedupKey)
		}
	}
	for i := 0; i < 10; i++ {
		if again := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, jqueryAttrSink, marker); len(again) != 1 || again[0] != attr[0] {
			t.Fatalf("run %d: jQuery.attr candidate is not deterministic", i)
		}
	}
	if got := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, jqueryAttrSink, "not-an-identifier"); got != nil {
		t.Fatalf("non-identifier marker must produce no candidate: %+v", got)
	}
}

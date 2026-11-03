package detection_test

// Coverage-gap regressions for the DOM-XSS candidate planner:
//   - an attribute-context injection needs a breakout SHAPE, without losing
//     the original wholesale-markup shape or the one-shape-per-(source, sink,
//     shape) identity;
//   - primitive-string timers must keep exactly one expression shape.
// Pure: no browser, no network — the executing behaviour is covered by the
// browser_integration tests in internal/scan.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func TestDOMXSSPayloadsForAddsAttributeBreakoutToEveryHTMLSink(t *testing.T) {
	const marker = "ATTRBREAKOUTMARKER"
	for _, sink := range []detection.DOMXSSSink{
		detection.DOMSinkInnerHTML,
		detection.DOMSinkOuterHTML,
		detection.DOMSinkDocumentWrite,
		detection.DOMSinkInsertAdjacentHTML,
		detection.DOMSinkCreateContextualFragment,
	} {
		for _, source := range detection.DOMXSSSources {
			shapes := detection.DOMXSSPayloadsFor(source, sink, marker)
			if len(shapes) != 2 {
				t.Fatalf("%s/%s: want the markup shape plus one attribute-breakout shape, got %d: %+v", source, sink, len(shapes), shapes)
			}
			primary, ok := detection.DOMXSSPayloadFor(source, sink, marker)
			if !ok {
				t.Fatalf("%s/%s: primary candidate must still exist", source, sink)
			}
			if shapes[0].Value != primary.Value || shapes[0].DedupKey != primary.DedupKey {
				t.Fatalf("%s/%s: first shape must stay the existing one, got %q vs %q", source, sink, shapes[0].Value, primary.Value)
			}
			seen := map[string]bool{}
			for _, cand := range shapes {
				if cand.Category != detection.CatDOMXSS || string(cand.Context) != string(sink) || cand.ContextSub != string(source) {
					t.Fatalf("%s/%s: candidate field repurposing changed: %+v", source, sink, cand)
				}
				if seen[cand.DedupKey] {
					t.Fatalf("%s/%s: shapes must have distinct dedup keys: %q", source, sink, cand.DedupKey)
				}
				seen[cand.DedupKey] = true
			}
			breakout := shapes[1]
			if !strings.Contains(breakout.Value, `"><img`) || !strings.Contains(breakout.Value, "onerror="+marker) {
				t.Fatalf("%s/%s: breakout shape must close the quoted attribute and fire onerror with the bare marker, got %q", source, sink, breakout.Value)
			}
			if breakout.Value == shapes[0].Value {
				t.Fatalf("%s/%s: breakout shape must differ from the markup shape", source, sink)
			}
			if !strings.Contains(breakout.Rationale, "attribute") || !strings.Contains(breakout.Rationale, "marker-specific execution signal") {
				t.Fatalf("%s/%s: breakout rationale must state the attribute context and the execution requirement, got %q", source, sink, breakout.Rationale)
			}
		}
	}
}

func TestDOMXSSPayloadsForKeepsQueryDocumentWriteScriptShapeFirst(t *testing.T) {
	const marker = "QUERYWRITEMARKER"
	shapes := detection.DOMXSSPayloadsFor(detection.DOMSourceQuery, detection.DOMSinkDocumentWrite, marker)
	if len(shapes) != 2 {
		t.Fatalf("want markup+breakout, got %d", len(shapes))
	}
	// The decodeURI-friendly script body stays the FIRST attempt: a target that
	// reads location.href through decodeURI keeps reserved '=' and '+' encoded,
	// so the breakout shape cannot work there and must not displace it.
	if shapes[0].Value != "<script>"+marker+"</script>" {
		t.Fatalf("query/document.write must keep its script body first, got %q", shapes[0].Value)
	}
	if !strings.Contains(shapes[1].Value, `"><img`) {
		t.Fatalf("query/document.write still needs the breakout shape, got %q", shapes[1].Value)
	}
}

func TestDOMXSSPayloadsForTimersKeepExactlyOneExpressionShape(t *testing.T) {
	const marker = "TIMERSHAPEMARKER"
	for _, sink := range []detection.DOMXSSSink{detection.DOMSinkSetTimeout, detection.DOMSinkSetInterval} {
		for _, source := range detection.DOMXSSSources {
			shapes := detection.DOMXSSPayloadsFor(source, sink, marker)
			if len(shapes) != 1 || shapes[0].Value != marker {
				t.Fatalf("%s/%s: a timer evaluates JavaScript only; want exactly the bare marker, got %+v", source, sink, shapes)
			}
			if strings.Contains(shapes[0].Value, "<") || strings.Contains(shapes[0].Value, `"`) {
				t.Fatalf("%s/%s: timer shape must not carry HTML/markup breakout, got %q", source, sink, shapes[0].Value)
			}
		}
	}
}

func TestDOMXSSPayloadsForIsDeterministicAndRejectsInvalidInput(t *testing.T) {
	first := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, "DETERMINISMMARKER")
	for i := 0; i < 20; i++ {
		again := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, "DETERMINISMMARKER")
		if len(again) != len(first) {
			t.Fatalf("run %d: shape count changed", i)
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d: shape %d is not deterministic: %+v vs %+v", i, j, again[j], first[j])
			}
		}
	}
	if got := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMXSSSink("eval"), "X"); got != nil {
		t.Fatalf("unknown sink must produce no shape: %+v", got)
	}
	if got := detection.DOMXSSPayloadsFor(detection.DOMXSSSource("eval"), detection.DOMSinkInnerHTML, "X"); got != nil {
		t.Fatalf("unknown source must produce no shape: %+v", got)
	}
	if got := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, ""); got != nil {
		t.Fatalf("empty marker must produce no shape: %+v", got)
	}
	if got := detection.DOMXSSPayloadsFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, "alert(1)"); got != nil {
		t.Fatalf("non-identifier marker must produce no shape: %+v", got)
	}
}

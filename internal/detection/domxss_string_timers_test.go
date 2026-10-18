package detection

import (
	"strings"
	"testing"
)

func TestDOMSetTimeoutPlan(t *testing.T) { testDOMStringTimerPlan(t, "setTimeout") }

func TestDOMSetIntervalPlan(t *testing.T) { testDOMStringTimerPlan(t, "setInterval") }

func testDOMStringTimerPlan(t *testing.T, name string) {
	t.Helper()
	sink := DOMXSSSink(name)
	for _, source := range DOMXSSSources {
		const marker = "TIMER_MARKER_123"
		got, ok := DOMXSSPayloadFor(source, sink, marker)
		if !ok {
			t.Fatalf("%s must plan a primitive-string timer candidate", name)
		}
		if got.Value != marker || got.Category != CatDOMXSS || got.Source != SourceBuiltin || got.Context != Context(sink) || got.ContextSub != string(source) || got.Trigger != TriggerLoad {
			t.Fatalf("wrong bare expression or provenance: %+v", got)
		}
		if !strings.Contains(got.Rationale, name) || !strings.Contains(got.Rationale, "native") || strings.Contains(got.Rationale, "<img>") {
			t.Fatalf("HTML rationale used for a timer: %s", got.Rationale)
		}
		again, ok := DOMXSSPayloadFor(source, sink, marker)
		if !ok || again != got {
			t.Fatal("planner mutated its output or inputs")
		}
		html, _ := DOMXSSPayloadFor(source, DOMSinkInnerHTML, marker)
		if html.Value != "<img src=x onerror="+marker+">" || html.DedupKey == got.DedupKey {
			t.Fatal("existing HTML payload or disjoint identity changed")
		}
	}
	for _, marker := range []string{"", "1bad", "x;y", "x y", "<img>", "x\n", "true", "undefined", "this"} {
		if got, ok := DOMXSSPayloadFor(DOMSourceHash, sink, marker); ok || got != (Candidate{}) {
			t.Fatalf("unsafe/non-marker expression accepted: %q", marker)
		}
	}
	for _, pair := range []struct {
		source DOMXSSSource
		sink   DOMXSSSink
	}{{"bad-source", sink}, {DOMSourceHash, "eval"}, {DOMSourceHash, ""}} {
		if got, ok := DOMXSSPayloadFor(pair.source, pair.sink, "TIMER_MARKER_123"); ok || got != (Candidate{}) {
			t.Fatal("invalid pair accepted")
		}
	}
}

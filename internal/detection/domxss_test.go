package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

func TestDOMXSSSinkIsValid(t *testing.T) {
	valid := []detection.DOMXSSSink{detection.DOMSinkInnerHTML, detection.DOMSinkOuterHTML, detection.DOMSinkDocumentWrite}
	for _, s := range valid {
		if !s.IsValid() {
			t.Fatalf("%s should be valid", s)
		}
	}
	if detection.DOMXSSSink("eval").IsValid() {
		t.Fatal("eval is out of scope for this slice and must not be a valid sink")
	}
	if detection.DOMXSSSink("").IsValid() {
		t.Fatal("empty sink must not be valid")
	}
}

func TestDOMXSSCanaryContainsMarker(t *testing.T) {
	marker := "indabc123"
	canary := detection.DOMXSSCanary(marker)
	if !strings.Contains(canary, marker) {
		t.Fatalf("canary %q does not contain marker %q", canary, marker)
	}
	// The canary must not itself be a markup breakout (AGENTS.md §2.2 —
	// a reachability probe is never a payload): no "<" or ">" at all.
	if strings.ContainsAny(canary, "<>") {
		t.Fatalf("canary %q must be inert, not a markup breakout", canary)
	}
}

func TestDOMXSSPayloadForEachSink(t *testing.T) {
	marker := "indxyz789"
	for _, sink := range []detection.DOMXSSSink{detection.DOMSinkInnerHTML, detection.DOMSinkOuterHTML, detection.DOMSinkDocumentWrite} {
		cand, ok := detection.DOMXSSPayloadFor(sink, marker)
		if !ok {
			t.Fatalf("DOMXSSPayloadFor(%s): expected ok=true", sink)
		}
		if !strings.Contains(cand.Value, marker) {
			t.Fatalf("candidate value %q does not embed marker %q", cand.Value, marker)
		}
		if cand.Category != detection.CatDOMXSS {
			t.Fatalf("category = %s, want %s", cand.Category, detection.CatDOMXSS)
		}
		if string(cand.Context) != string(sink) {
			t.Fatalf("context = %s, want sink name %s", cand.Context, sink)
		}
		if cand.ContextSub != string(detection.DOMSourceHash) {
			t.Fatalf("context_sub = %s, want %s", cand.ContextSub, detection.DOMSourceHash)
		}
		if cand.Trigger != detection.TriggerLoad {
			t.Fatalf("trigger = %s, want load (passively observable, like the reachability-only canary is NOT)", cand.Trigger)
		}
		// Benign-marker-only, same guarantee candidate.go's canonical
		// templates carry (TestPlanCandidatesAreBenignMarkers): never an
		// exfiltration/weaponized construct.
		for _, bad := range []string{"alert(", "document.cookie", "fetch("} {
			if strings.Contains(cand.Value, bad) {
				t.Fatalf("candidate value %q contains a weaponized construct %q", cand.Value, bad)
			}
		}
	}
}

func TestDOMXSSPayloadForRejectsUnknownSinkOrEmptyMarker(t *testing.T) {
	if _, ok := detection.DOMXSSPayloadFor(detection.DOMXSSSink("eval"), "indabc"); ok {
		t.Fatal("an out-of-scope sink must not produce a candidate")
	}
	if _, ok := detection.DOMXSSPayloadFor(detection.DOMSinkInnerHTML, ""); ok {
		t.Fatal("an empty marker must not produce a candidate")
	}
}

func TestDOMXSSPayloadForDeterministic(t *testing.T) {
	marker := "indrepeat1"
	first, _ := detection.DOMXSSPayloadFor(detection.DOMSinkInnerHTML, marker)
	for i := 0; i < 20; i++ {
		got, ok := detection.DOMXSSPayloadFor(detection.DOMSinkInnerHTML, marker)
		if !ok || got != first {
			t.Fatalf("run %d: DOMXSSPayloadFor is not deterministic: %+v vs %+v", i, got, first)
		}
	}
}

func TestDOMXSSPayloadForDistinctSinksDontCollide(t *testing.T) {
	marker := "inddistinct1"
	a, _ := detection.DOMXSSPayloadFor(detection.DOMSinkInnerHTML, marker)
	b, _ := detection.DOMXSSPayloadFor(detection.DOMSinkOuterHTML, marker)
	if a.DedupKey == b.DedupKey {
		t.Fatalf("different sinks must not share a dedup key: %q", a.DedupKey)
	}
}

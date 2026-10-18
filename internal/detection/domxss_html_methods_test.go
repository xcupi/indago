package detection

import "testing"

func TestDOMHTMLMethodSinkCandidates(t *testing.T) {
	for _, sink := range []DOMXSSSink{DOMSinkInsertAdjacentHTML, DOMSinkCreateContextualFragment} {
		for _, source := range []DOMXSSSource{DOMSourceHash, DOMSourceQuery} {
			candidate, ok := DOMXSSPayloadFor(source, sink, "HTML_METHOD_MARKER")
			if !ok || !sink.IsValid() || candidate.Value != "<img src=x onerror=HTML_METHOD_MARKER>" || string(candidate.Context) != string(sink) || candidate.ContextSub != string(source) || candidate.Category != CatDOMXSS {
				t.Fatalf("missing source-generic candidate mapping for %s -> %s: %+v (%v)", source, sink, candidate, ok)
			}
		}
	}
	for _, sink := range []DOMXSSSink{"eval", "Function", "location", "src"} {
		if sink.IsValid() {
			t.Fatalf("out-of-scope sink accepted: %s", sink)
		}
		if _, ok := DOMXSSPayloadFor(DOMSourceHash, sink, "HTML_METHOD_MARKER"); ok {
			t.Fatalf("out-of-scope candidate generated: %s", sink)
		}
	}
}

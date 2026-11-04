package detection

// Source-spelling and URLSearchParams-form coverage for the bounded static
// taint pass.
//
// The measured live lab serves this page (verbatim) at /search-results:
//
//	function trackSearch(query) {
//	    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
//	}
//	var query = (new URLSearchParams(window.location.search)).get('search');
//	if (query) { trackSearch(query); }
//
// The first fixture below is that page byte-for-byte. It is deliberately kept
// first: it records what the pass does with the measured page, and at the base
// revision it already reports the document.write sink (the window/ prefix was
// accepted before this slice). The spellings the pass genuinely missed —
// `self.location.…` — are what the matrix test below pins, so the regression
// this file locks is the real one rather than a hypothesis.

import (
	"strings"
	"testing"
)

// labTrackSearchScript is the measured lab script, byte-for-byte, including
// the four-space indentation.
const labTrackSearchScript = `function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }`

// TestDOMXSSStaticMeasuredLabPage is the measured-page fixture: the value is
// read through window.location.search into a local variable, crosses exactly
// one function argument, and reaches document.write inside a concatenation.
func TestDOMXSSStaticMeasuredLabPage(t *testing.T) {
	res := DOMXSSStaticReachability(taintPage(labTrackSearchScript), DOMSourceQuery, "search")
	if res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("the measured lab page must report a tainted path, got %s (unresolved=%+v notes=%v)", res.Outcome, res.Unresolved, res.Notes)
	}
	if !hasSink(res, DOMSinkDocumentWrite) {
		t.Fatalf("want document.write reachable, got %v", taintSinks(res))
	}
	site := res.Sites[0]
	if site.Hops != 1 {
		t.Fatalf("the value crosses exactly one user-defined function boundary, got hops=%d chain=%v", site.Hops, site.Chain)
	}
	chain := strings.Join(site.Chain, " -> ")
	for _, want := range []string{"window.location.search", "URLSearchParams.get(search)", "query", "trackSearch", "document.write"} {
		if !strings.Contains(chain, want) {
			t.Fatalf("flow chain %q is missing %q", chain, want)
		}
	}
}

// labTrackSearchWith builds the measured page around one source expression, so
// every spelling is measured in exactly the position the lab uses it.
func labTrackSearchWith(sourceExpr string) string {
	return `function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var query = (new URLSearchParams(` + sourceExpr + `)).get('search');
if (query) { trackSearch(query); }`
}

// TestDOMXSSStaticLocationSourceSpellings is the equivalence matrix: a page
// reaches the SAME Location object through the bare global and through the
// window/self/document aliases, so all four spellings must carry the source.
func TestDOMXSSStaticLocationSourceSpellings(t *testing.T) {
	for _, spelling := range []string{
		"location.search",
		"window.location.search",
		"document.location.search",
		"self.location.search",
	} {
		t.Run(spelling, func(t *testing.T) {
			res := DOMXSSStaticReachability(taintPage(labTrackSearchWith(spelling)), DOMSourceQuery, "search")
			if res.Outcome != DOMXSSFlowTainted || !hasSink(res, DOMSinkDocumentWrite) {
				t.Fatalf("%s must reach document.write, got %s sites=%v unresolved=%+v", spelling, res.Outcome, taintSinks(res), res.Unresolved)
			}
			if got := strings.Join(res.Sites[0].Chain, " -> "); !strings.Contains(got, spelling) {
				t.Fatalf("the flow chain must name the spelling the page used (%s), got %q", spelling, got)
			}
		})
	}
}

// TestDOMXSSStaticHashAndHrefSpellings covers the other two location members
// the brief names: the fragment and the full URL.
func TestDOMXSSStaticHashAndHrefSpellings(t *testing.T) {
	for _, spelling := range []string{
		"location.hash",
		"window.location.hash",
		"document.location.hash",
		"self.location.hash",
	} {
		t.Run(spelling, func(t *testing.T) {
			page := taintPage(`var q = decodeURIComponent(` + spelling + `.slice(1));` + "\n" +
				`document.write('<img src="/t.gif?q=' + q + '">');`)
			res := DOMXSSStaticReachability(page, DOMSourceHash, "")
			if res.Outcome != DOMXSSFlowTainted || !hasSink(res, DOMSinkDocumentWrite) {
				t.Fatalf("%s must reach document.write for the hash source, got %s sites=%v", spelling, res.Outcome, taintSinks(res))
			}
		})
	}

	for _, spelling := range []string{
		"location.href",
		"window.location.href",
		"document.location.href",
		"self.location.href",
	} {
		t.Run(spelling, func(t *testing.T) {
			page := taintPage(`var q = ` + spelling + `;` + "\n" +
				`document.write('<img src="/t.gif?q=' + q + '">');`)
			// A full-URL read carries the query string AND the fragment; the
			// pass credits it for both URL sources, as it already did for the
			// bare and window-prefixed spellings.
			for _, source := range []DOMXSSSource{DOMSourceQuery, DOMSourceHash} {
				res := DOMXSSStaticReachability(page, source, "")
				if res.Outcome != DOMXSSFlowTainted || !hasSink(res, DOMSinkDocumentWrite) {
					t.Fatalf("%s must reach document.write for %s, got %s sites=%v", spelling, source, res.Outcome, taintSinks(res))
				}
			}
		})
	}
}

// TestDOMXSSStaticLocationSpellingsKeepSourceIsolation proves the new
// spellings did not make the sources interchangeable: a query probe must not
// be credited by a fragment read, and a hash probe must not be credited by a
// query read, whichever alias the page used.
func TestDOMXSSStaticLocationSpellingsKeepSourceIsolation(t *testing.T) {
	hashRead := taintPage(`var q = decodeURIComponent(self.location.hash.slice(1));
document.write('<img src="/t.gif?q=' + q + '">');`)
	if res := DOMXSSStaticReachability(hashRead, DOMSourceQuery, ""); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a self.location.hash read must not be credited to the query source, got %s sites=%v", res.Outcome, taintSinks(res))
	}

	queryRead := taintPage(`var q = (new URLSearchParams(self.location.search)).get('q');
document.write('<img src="/t.gif?q=' + q + '">');`)
	if res := DOMXSSStaticReachability(queryRead, DOMSourceHash, "q"); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a self.location.search read must not be credited to the hash source, got %s sites=%v", res.Outcome, taintSinks(res))
	}
}

// TestDOMXSSStaticURLSearchParamsGetForms pins every accepted spelling of the
// URLSearchParams -> .get() chain: with or without `new`, with or without
// wrapping parentheses, with a qualified constructor, and with the object
// assigned to a variable before .get() is called.
func TestDOMXSSStaticURLSearchParamsGetForms(t *testing.T) {
	cases := map[string]struct {
		script string
		source DOMXSSSource
	}{
		"new + parens (measured form)": {
			script: labTrackSearchWith("window.location.search"),
			source: DOMSourceQuery,
		},
		"new, no parens": {
			script: `var query = new URLSearchParams(location.search).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"no new, parens": {
			script: `var query = (URLSearchParams(location.search)).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"no new, no parens": {
			script: `var query = URLSearchParams(location.search).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"doubled parens": {
			script: `var query = ((new URLSearchParams(location.search))).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"assigned then .get() later": {
			script: `var params = new URLSearchParams(window.location.search);
var query = params.get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"assigned (no new) then .get() later": {
			script: `var params = URLSearchParams(window.location.search);
var query = params.get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"qualified new window.URLSearchParams": {
			script: `var query = new window.URLSearchParams(window.location.search).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"qualified window.URLSearchParams call": {
			script: `var query = window.URLSearchParams(window.location.search).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceQuery,
		},
		"hash-fed params": {
			script: `var query = (new URLSearchParams(self.location.hash.slice(1))).get('search');
document.write('<img src="/t.gif?q=' + query + '">');`,
			source: DOMSourceHash,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := DOMXSSStaticReachability(taintPage(tc.script), tc.source, "search")
			if res.Outcome != DOMXSSFlowTainted || !hasSink(res, DOMSinkDocumentWrite) {
				t.Fatalf("%s must reach document.write, got %s sites=%v unresolved=%+v", name, res.Outcome, taintSinks(res), res.Unresolved)
			}
		})
	}
}

// TestDOMXSSStaticLocationSpellingsKeepDepthBound proves the new spellings
// cannot be used to slip past the one-function-hop bound.
func TestDOMXSSStaticLocationSpellingsKeepDepthBound(t *testing.T) {
	page := taintPage(`function inner(v) { document.write('<img src="/t.gif?q=' + v + '">'); }
function outer(v) { inner(v); }
var q = (new URLSearchParams(self.location.search)).get('q');
outer(q);`)
	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowUnresolved || !hasUnresolved(res, "flow depth") {
		t.Fatalf("two function boundaries must stay unresolved for the self. spelling too, got %s sites=%v unresolved=%+v", res.Outcome, taintSinks(res), res.Unresolved)
	}
	if len(res.Sites) != 0 {
		t.Fatalf("an unresolved flow must not claim a reachable sink, got %v", taintSinks(res))
	}
}

// TestDOMXSSStaticLocationSpellingsKeepNegativesNegative re-runs the
// anti-false-positive fixtures with the newly accepted spellings: a constant
// sink, an unrelated variable, and a source read that never reaches the sink
// must all stay negative.
func TestDOMXSSStaticLocationSpellingsKeepNegativesNegative(t *testing.T) {
	cases := map[string]string{
		"constant sink, source unused": `function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + '"static"' + '" />');
}
var query = (new URLSearchParams(self.location.search)).get('search');
if (query) { trackSearch('static'); }`,
		"unrelated variable reaches the sink": `var query = (new URLSearchParams(self.location.search)).get('search');
var safe = 'static-value';
document.write('<img src="/t.gif?q=' + safe + '">');`,
		"source read but never used": `var query = (new URLSearchParams(self.location.search)).get('search');
document.write('<img src="/t.gif">');`,
		"different selector": `var query = (new URLSearchParams(self.location.search)).get('other');
document.write('<img src="/t.gif?q=' + query + '">');`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			res := DOMXSSStaticReachability(taintPage(script), DOMSourceQuery, "search")
			if res.Outcome != DOMXSSFlowNoTaintedPath {
				t.Fatalf("%s must stay negative, got %s sites=%v unresolved=%+v", name, res.Outcome, taintSinks(res), res.Unresolved)
			}
			if len(res.Sites) != 0 {
				t.Fatalf("%s must report no site, got %v", name, taintSinks(res))
			}
		})
	}
}

// TestDOMXSSPayloadGoldensUnchanged freezes the planner's output for the
// shapes this pass feeds. Source spelling is a taint-pass concern only: the
// candidates a reachable (source, sink) pair produces must not move.
func TestDOMXSSPayloadGoldensUnchanged(t *testing.T) {
	const m = "GOLDENMARKER"
	htmlSinks := []DOMXSSSink{
		DOMSinkInnerHTML,
		DOMSinkOuterHTML,
		DOMSinkInsertAdjacentHTML,
		DOMSinkCreateContextualFragment,
	}
	wantHTML := []string{
		"<img src=x onerror=" + m + ">",
		`"><img src=y onerror=` + m + ">",
	}
	wantWrite := map[DOMXSSSource][]string{
		DOMSourceQuery: {"<script>" + m + "</script>", `"><img src=y onerror=` + m + ">"},
	}
	for _, source := range DOMXSSSources {
		want, ok := wantWrite[source]
		if !ok {
			want = wantHTML
		}
		if got := payloadValues(DOMXSSPayloadsFor(source, DOMSinkDocumentWrite, m)); !equalStrings(got, want) {
			t.Fatalf("%s/document.write plan moved: got %v want %v", source, got, want)
		}
		for _, sink := range htmlSinks {
			if got := payloadValues(DOMXSSPayloadsFor(source, sink, m)); !equalStrings(got, wantHTML) {
				t.Fatalf("%s/%s plan moved: got %v want %v", source, sink, got, wantHTML)
			}
		}
		if got := payloadValues(DOMXSSPayloadsFor(source, DOMSinkJQuerySelector, m)); !equalStrings(got, []string{"<img src=x onerror=" + m + ">"}) {
			t.Fatalf("%s/jQuery.selector plan moved: got %v", source, got)
		}
		if got := payloadValues(DOMXSSPayloadsFor(source, DOMSinkJQueryAttr, m)); !equalStrings(got, []string{"javascript:" + m}) {
			t.Fatalf("%s/jQuery.attr plan moved: got %v", source, got)
		}
		wantTimer := []string{m}
		if source == DOMSourceQuery {
			wantTimer = []string{m, `";` + m + ";//", `';` + m + ";//", `"};` + m + ";//", `\"};` + m + ";//"}
		}
		if got := payloadValues(DOMXSSPayloadsFor(source, DOMSinkSetTimeout, m)); !equalStrings(got, wantTimer) {
			t.Fatalf("%s/setTimeout plan moved: got %v", source, got)
		}
	}
}

func payloadValues(cands []Candidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.Value)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

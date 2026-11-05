package detection

import (
	"strings"
	"testing"
)

// page wraps a script body in a minimal HTML document.
func taintPage(script string) string {
	return "<!doctype html><html><body><p>lab</p><script>\n" + script + "\n</script></body></html>"
}

func taintSinks(res DOMXSSStaticResult) []string {
	out := make([]string, 0, len(res.Sites))
	for _, site := range res.Sites {
		out = append(out, string(site.Sink))
	}
	return out
}

func hasSink(res DOMXSSStaticResult, sink DOMXSSSink) bool {
	for _, site := range res.Sites {
		if site.Sink == sink {
			return true
		}
	}
	return false
}

func hasUnresolved(res DOMXSSStaticResult, reasonFragment string) bool {
	for _, u := range res.Unresolved {
		if strings.Contains(u.Reason, reasonFragment) || strings.Contains(u.Detail, reasonFragment) {
			return true
		}
	}
	return false
}

// TestDOMXSSStaticTrackSearchShape is the measured lab shape: the query value
// is read into a local variable and handed to a function, whose parameter
// reaches document.write inside a string concatenation.
func TestDOMXSSStaticTrackSearchShape(t *testing.T) {
	page := taintPage(`
function trackSearch(query) {
  document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '" />');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "search")
	if res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("variable + one function hop must produce a tainted path, got %s (unresolved=%+v notes=%v)", res.Outcome, res.Unresolved, res.Notes)
	}
	if !hasSink(res, DOMSinkDocumentWrite) {
		t.Fatalf("want document.write reachable, got %v", taintSinks(res))
	}
	site := res.Sites[0]
	if site.Hops != 1 {
		t.Fatalf("the value crosses exactly one user-defined function boundary, got hops=%d chain=%v", site.Hops, site.Chain)
	}
	chain := strings.Join(site.Chain, " -> ")
	for _, want := range []string{"location.search", "URLSearchParams.get(search)", "query", "trackSearch", "document.write"} {
		if !strings.Contains(chain, want) {
			t.Fatalf("flow chain %q is missing %q", chain, want)
		}
	}
	if site.Line <= 0 {
		t.Fatalf("site must carry a page line number, got %d", site.Line)
	}
}

// TestDOMXSSStaticConstantSinkStaysNegative proves the negative side: the same
// page shape with a constant written to the sink, and the source variable
// unused, must never be reported as tainted.
func TestDOMXSSStaticConstantSinkStaysNegative(t *testing.T) {
	page := taintPage(`
function trackSearch(query) {
  document.write('<img src="/resources/images/tracker.gif" />');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "search")
	if res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a constant sink with an unused source variable must stay negative, got %s sites=%v unresolved=%+v", res.Outcome, taintSinks(res), res.Unresolved)
	}
	if len(res.Sites) != 0 {
		t.Fatalf("no site may be reported, got %v", taintSinks(res))
	}
}

// TestDOMXSSStaticUnrelatedSinkStaysNegative: the source reaches a variable, but
// the variable is only used in assignments that are not implemented sinks.
func TestDOMXSSStaticUnrelatedSinkStaysNegative(t *testing.T) {
	page := taintPage(`
var q = (new URLSearchParams(location.search)).get('q');
document.title = 'Results for ' + q;
document.getElementById('out').textContent = q;
document.write('<img src="/tracker.gif" />');`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("an unrelated sink must stay negative, got %s sites=%v unresolved=%+v", res.Outcome, taintSinks(res), res.Unresolved)
	}
}

// TestDOMXSSStaticUnrelatedVariableStaysNegative: a tainted and an unrelated
// variable coexist; only the unrelated one reaches the sink.
func TestDOMXSSStaticUnrelatedVariableStaysNegative(t *testing.T) {
	page := taintPage(`
var q = (new URLSearchParams(location.search)).get('q');
var safe = 'static-value';
document.write('<img src="/tracker.gif?q=' + safe + '" />');`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a sink fed by an unrelated variable must stay negative, got %s sites=%v", res.Outcome, taintSinks(res))
	}
}

// TestDOMXSSStaticDynamicCalleeIsUnresolved is the required unresolved fixture:
// window['docu'+'ment']['write'](x) cannot be named statically, so the honest
// outcome is unresolved — never a silent negative.
func TestDOMXSSStaticDynamicCalleeIsUnresolved(t *testing.T) {
	page := taintPage(`
var x = (new URLSearchParams(location.search)).get('q');
window['docu'+'ment']['write'](x);`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowUnresolved {
		t.Fatalf("a computed callee carrying taint must be unresolved, got %s sites=%v", res.Outcome, taintSinks(res))
	}
	if len(res.Sites) != 0 {
		t.Fatalf("unresolved flow must not claim a reachable sink, got %v", taintSinks(res))
	}
	if !hasUnresolved(res, "dynamic property access") {
		t.Fatalf("unresolved entry must name the dynamic property access, got %+v", res.Unresolved)
	}
}

// TestDOMXSSStaticExistingInlineFixturesUnchanged re-runs the inline shapes the
// real-browser fixtures already confirm, so the static pass agrees with them.
func TestDOMXSSStaticExistingInlineFixturesUnchanged(t *testing.T) {
	cases := []struct {
		name   string
		script string
		sink   DOMXSSSink
	}{
		{
			name:   "document.write quoted attribute",
			script: `const q=new URLSearchParams(location.search).get('q')||'';document.write('<img src="/resources/images/tracker.gif?searchTerms='+q+'">');`,
			sink:   DOMSinkDocumentWrite,
		},
		{
			name:   "innerHTML quoted attribute",
			script: `const q=new URLSearchParams(location.search).get('q')||'';document.getElementById('sink').innerHTML='<img src="/resources/images/tracker.gif?searchTerms='+q+'">';`,
			sink:   DOMSinkInnerHTML,
		},
		{
			name:   "jQuery selector",
			script: `const q=new URLSearchParams(location.search).get('q')||'';$('<img src=x onerror='+q+'>');`,
			sink:   DOMSinkJQuerySelector,
		},
		{
			name:   "jQuery href attribute",
			script: `const q=new URLSearchParams(location.search).get('q')||'';$('#link').attr('href','javascript:'+q);`,
			sink:   DOMSinkJQueryAttr,
		},
		{
			name:   "insertAdjacentHTML",
			script: `const q=new URLSearchParams(location.search).get('q')||'';document.getElementById('sink').insertAdjacentHTML('beforeend','<img src=x onerror='+q+'>');`,
			sink:   DOMSinkInsertAdjacentHTML,
		},
		{
			name:   "Range.createContextualFragment",
			script: `const q=new URLSearchParams(location.search).get('q')||'';document.createRange().createContextualFragment('<img src=x onerror='+q+'>');`,
			sink:   DOMSinkCreateContextualFragment,
		},
		{
			name:   "primitive-string timer",
			script: `const q=new URLSearchParams(location.search).get('q')||'';setTimeout('<img src=x onerror='+q+'>', 0);`,
			sink:   DOMSinkSetTimeout,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := DOMXSSStaticReachability(taintPage(tc.script), DOMSourceQuery, "q")
			if res.Outcome != DOMXSSFlowTainted || !hasSink(res, tc.sink) {
				t.Fatalf("existing inline fixture must stay reachable through %s, got %s sites=%v unresolved=%+v", tc.sink, res.Outcome, taintSinks(res), res.Unresolved)
			}
		})
	}
}

// TestDOMXSSStaticSelectorAndSourceIsolation keeps the pass honest about WHICH
// source and selector were probed.
func TestDOMXSSStaticSelectorAndSourceIsolation(t *testing.T) {
	queryPage := taintPage(`var q = new URLSearchParams(location.search).get('search');
document.write('<img src="/t.gif?q=' + q + '">');`)

	if res := DOMXSSStaticReachability(queryPage, DOMSourceQuery, "other"); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a different query parameter must not be credited, got %s sites=%v", res.Outcome, taintSinks(res))
	}
	if res := DOMXSSStaticReachability(queryPage, DOMSourceHash, ""); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a hash probe must not be credited by a query read, got %s sites=%v", res.Outcome, taintSinks(res))
	}

	hashPage := taintPage(`var q = decodeURIComponent(location.hash.slice(1));
document.write('<img src="/t.gif?q=' + q + '">');`)
	if res := DOMXSSStaticReachability(hashPage, DOMSourceHash, ""); res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("a hash read must reach the sink for the hash source, got %s", res.Outcome)
	}
	if res := DOMXSSStaticReachability(hashPage, DOMSourceQuery, ""); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a hash read must not be credited to the query source, got %s", res.Outcome)
	}
}

// TestDOMXSSStaticTemplateAndLetConst covers let/const bindings and template
// interpolation, the two remaining supported shapes.
func TestDOMXSSStaticTemplateAndLetConst(t *testing.T) {
	page := taintPage("let q = new URLSearchParams(location.search).get('q');\n" +
		"const html = `<img src=x onerror=${q}>`;\n" +
		"document.getElementById('sink').innerHTML = html;")

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowTainted || !hasSink(res, DOMSinkInnerHTML) {
		t.Fatalf("template interpolation through let/const must reach innerHTML, got %s sites=%v unresolved=%+v", res.Outcome, taintSinks(res), res.Unresolved)
	}
}

// TestDOMXSSStaticStorageAndPostMessage covers the non-URL sources.
func TestDOMXSSStaticStorageAndPostMessage(t *testing.T) {
	storagePage := taintPage(`var v = localStorage.getItem('token');
document.getElementById('sink').innerHTML = v;`)
	if res := DOMXSSStaticReachability(storagePage, DOMSourceLocalStorage, "token"); res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("the tested storage key must reach innerHTML, got %s", res.Outcome)
	}
	if res := DOMXSSStaticReachability(storagePage, DOMSourceLocalStorage, "other-key"); res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("a different storage key must stay negative, got %s sites=%v", res.Outcome, taintSinks(res))
	}

	pmPage := taintPage(`window.addEventListener('message', function (e) {
  document.getElementById('sink').innerHTML = e.data;
});`)
	if res := DOMXSSStaticReachability(pmPage, DOMSourcePostMessage, ""); res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("event.data in a message listener must reach innerHTML, got %s unresolved=%+v", res.Outcome, res.Unresolved)
	}
}

// TestDOMXSSStaticDepthBoundIsExplicit proves the stated bound: a second
// user-defined function boundary is unresolved, not silently followed.
func TestDOMXSSStaticDepthBoundIsExplicit(t *testing.T) {
	page := taintPage(`
function inner(v) { document.write('<img src="/t.gif?q=' + v + '">'); }
function outer(v) { inner(v); }
var q = new URLSearchParams(location.search).get('q');
outer(q);`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowUnresolved {
		t.Fatalf("two function boundaries exceed the supported depth, got %s sites=%v", res.Outcome, taintSinks(res))
	}
	if !hasUnresolved(res, "flow depth") {
		t.Fatalf("the unresolved entry must name the depth bound, got %+v", res.Unresolved)
	}
}

// TestDOMXSSStaticEvalIsUnresolved: tainted data handed to eval is an explicit
// unknown.
func TestDOMXSSStaticEvalIsUnresolved(t *testing.T) {
	page := taintPage(`var q = new URLSearchParams(location.search).get('q');
eval(q);`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowUnresolved || !hasUnresolved(res, "dynamic code evaluation") {
		t.Fatalf("eval with tainted data must be unresolved, got %s %+v", res.Outcome, res.Unresolved)
	}
}

// TestDOMXSSStaticEscapingIsNotModelled pins the documented limitation: the
// static pass is structural, so an escaped value still counts as tainted. The
// browser fixture for the same escaping stays Rejected — only the browser can
// decide execution.
func TestDOMXSSStaticEscapingIsNotModelled(t *testing.T) {
	page := taintPage(`var q = new URLSearchParams(location.search).get('q');
var v = q.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
document.write('<img src="/t.gif?q=' + v + '">');`)

	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.Outcome != DOMXSSFlowTainted {
		t.Fatalf("the bounded pass does not model escaping, so this must remain a tainted path; got %s", res.Outcome)
	}
	if !hasUnresolved(res, "") && len(res.Unresolved) != 0 {
		t.Fatalf("no unresolved entry is expected for a resolvable flow, got %+v", res.Unresolved)
	}
}

// TestDOMXSSStaticExternalScriptIsNotCoverage counts an external script instead
// of pretending the page was fully analysed.
func TestDOMXSSStaticExternalScriptIsNotCoverage(t *testing.T) {
	page := `<!doctype html><body><script src="/app.js"></script><script>document.write('static');</script></body>`
	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if res.ExternalScripts != 1 {
		t.Fatalf("want one external script counted, got %d", res.ExternalScripts)
	}
	if res.Outcome != DOMXSSFlowNoTaintedPath {
		t.Fatalf("inline scripts contain no tainted path, got %s", res.Outcome)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "external") {
		t.Fatalf("the coverage limit must be stated in notes, got %v", res.Notes)
	}
}

// TestDOMXSSStaticRejectsUnknownSource keeps the entry point honest.
func TestDOMXSSStaticRejectsUnknownSource(t *testing.T) {
	res := DOMXSSStaticReachability(taintPage(`document.write('x')`), DOMXSSSource("location.port"), "")
	if res.Outcome != DOMXSSFlowUnresolved {
		t.Fatalf("an unimplemented source must be unresolved, got %s", res.Outcome)
	}
}

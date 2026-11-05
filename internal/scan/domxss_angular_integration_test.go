//go:build browser_integration

package scan

// Real-Chromium coverage for the angular_expression sink (AngularJS text-node
// interpolation — the PortSwigger Angular lab class):
//
//   - a page that boots AngularJS (ng-app) and has the source value in a text
//     node compiles the {{...}} candidate and CONFIRMS on the evaluated
//     result, which is the marker identifier; the candidate itself never
//     contains the contiguous marker.
//   - the same page with ng-app removed (plain text) stays Rejected: the
//     false-positive guard.
//   - a page with no Angular at all, echoing {{...}} as text, stays Rejected.
//   - a page whose CSP refuses dynamic evaluation (script-src without
//     'unsafe-eval', so Angular's $parse cannot build its expression function)
//     yields the DISTINCT csp_blocked outcome: Inconclusive, never Confirmed
//     and never a silent Rejected.
//   - the hash source works the same way through a page that $compile()s a
//     location.hash value.
//
// The fixture is the vendored upstream AngularJS 1.2.32 (see
// testdata/ANGULAR-README.md). Every navigation is to a local httptest server.

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func angularFixture(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/angular-1.2.32.min.js")
	if err != nil {
		t.Fatalf("read vendored AngularJS fixture: %v", err)
	}
	return body
}

// angularLab serves every Angular fixture path plus the vendored library.
func angularLab(t *testing.T) *httptest.Server {
	t.Helper()
	angular := angularFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/angular.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(angular)
			return
		case "/dom", "/noapp", "/plain", "/csp-angular", "/blocked", "/blocked-csp", "/textarea", "/parse-key", "/constant", "/parse-name", "/name-echo":
			if r.URL.Path == "/csp-angular" || r.URL.Path == "/blocked-csp" {
				// Allows the page's own inline code and same-origin scripts,
				// but NOT eval/new Function: the policy that stops a template
				// compiler without a CSP-safe interpreter.
				w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
			}
			if r.URL.Path == "/blocked" || r.URL.Path == "/blocked-csp" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintf(w, angularBlockedCompilerPage, r.URL.Query().Get("q"))
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			switch r.URL.Path {
			case "/parse-name":
				// The measured live lab shape (AngularJS 1.4.4, "sandbox escape
				// without strings"): for EVERY query parameter the page emits
				//     var key = '<NAME>';
				//     $scope.query[key] = '<VALUE>';
				//     $scope.value = $parse(key)($scope.query);
				// with ' and " rewritten to character references inside the
				// inline <script> (which the HTML parser does not decode), and
				// the template renders {{value}}. The parameter VALUE is data
				// and is never re-compiled; the parameter NAME is the Angular
				// expression $parse compiles.
				fmt.Fprintf(w, angularParseNamePage, angularParseNameBlocks(r.URL.RawQuery))
				return
			case "/name-echo":
				// False-positive guard: Angular is present and the whole query
				// string (names AND values, decoded) is rendered as text, but
				// no parameter name is ever handed to $parse. A name-shaped
				// candidate must not confirm merely because its own bytes are
				// displayed.
				fmt.Fprintf(w, `<!doctype html><html><body ng-app="labApp"><div id="out">You searched for: %s</div>
<script src="/angular.js"></script></body></html>`, html.EscapeString(angularDecodedQuery(r.URL.RawQuery)))
				return
			case "/textarea":
				// Angular compiles the textarea's text as template source, so
				// the evaluated result lands in the textarea's value, never in
				// a rendered body text node. The ng-bind echo is DATA (never
				// template source) and is only the reachability signal.
				value := html.EscapeString(r.URL.Query().Get("q"))
				fmt.Fprintf(w, `<!doctype html><html><body ng-app="lab" ng-controller="C"><div id="echo" ng-bind="echo"></div>
<textarea id="out">%s</textarea><script src="/angular.js"></script>
<script>angular.module('lab', []).controller('C', function($scope) {
  $scope.echo = new URLSearchParams(location.search).get('q') || '';
});</script></body></html>`, value)
				return
			case "/parse-key":
				// The measured without-strings lab shape: the server writes the
				// query value into a scope string with its quotes HTML-encoded,
				// the controller resolves the parameter NAME through $parse, and
				// the template only interpolates {{value}} — the value is data,
				// never re-compiled. Nothing can evaluate the candidate here.
				q := strings.ReplaceAll(r.URL.Query().Get("q"), "'", "&apos;")
				fmt.Fprintf(w, `<!doctype html><html><head><script src="/angular.js"></script></head>
<body ng-app="labApp"><section class="blog-header">
<script>angular.module('labApp', []).controller('vulnCtrl', function($scope, $parse) {
  $scope.query = {};
  var key = 'search';
  $scope.query[key] = '%s';
  $scope.value = $parse(key)($scope.query);
});</script>
<h1 ng-controller="vulnCtrl">0 search results for {{value}}</h1>
</section></body></html>`, q)
				return
			case "/constant":
				// ng-app is present, but ng-bind writes the value as DATA: a
				// string containing {{...}} is not template source and must
				// never be re-compiled by the observation.
				fmt.Fprint(w, `<!doctype html><html><body ng-app="lab" ng-controller="C"><div id="out" ng-bind="value"></div>
<script src="/angular.js"></script>
<script>angular.module('lab', []).controller('C', function($scope) {
  // Not $location.search(): without html5Mode AngularJS reads the HASH, so
  // the query string would never reach the binding.
  $scope.value = new URLSearchParams(location.search).get('q') || '';
});</script></body></html>`)
				return
			}
			app, script := " ng-app", `<script src="/angular.js"></script>`
			switch r.URL.Path {
			case "/noapp":
				app = ""
			case "/plain":
				app, script = "", ""
			}
			fmt.Fprintf(w, `<!doctype html><html><body%s><div id="out">You searched for: '%s'</div>%s</body></html>`,
				app, r.URL.Query().Get("q"), script)
			return
		case "/hash":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><script src="/angular.js"></script></head>
<body ng-app="lab" ng-controller="C"><div id="out"></div>
<script>
angular.module('lab', []).controller('C', function($scope, $compile) {
  var out = document.getElementById('out');
  out.textContent = decodeURIComponent(location.hash.slice(1));
  $compile(out)($scope);
});
</script></body></html>`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// angularParseNamePage is the parameter-NAME binding page: one
// `var key … $scope.value = $parse(key)(…)` block per query parameter, and a
// template that renders the last block's result. The blocks are in URL order,
// exactly like the measured live lab.
const angularParseNamePage = `<!doctype html><html><body ng-app="labApp">
<script src="/angular.js"></script>
<script>angular.module('labApp', []).controller('vulnCtrl', function($scope, $parse) {
$scope.query = {};
%s
});</script>
<h1 ng-controller="vulnCtrl">0 search results for {{value}}</h1></body></html>`

// angularAttributeEscape reproduces the lab's escaping inside its inline
// <script>: both quote styles become character references, so a string literal
// cannot survive in either style (the HTML parser does not decode references in
// raw-text script content). The live page emits &apos; / &quot;; Go's escaper
// emits the numeric forms — both are the same character reference.
var angularAttributeEscape = strings.NewReplacer(
	"&#39;", "&apos;",
	"&#34;", "&quot;",
	"&#x27;", "&apos;",
	"&#x22;", "&quot;",
)

func angularLabEscaped(s string) string {
	return angularAttributeEscape.Replace(html.EscapeString(s))
}

// angularDecodedQuery returns the query string with names and values decoded,
// in URL order, for the /name-echo guard page.
func angularDecodedQuery(raw string) string {
	var b strings.Builder
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		b.WriteString(name + "=" + value + "&")
	}
	return b.String()
}

// angularParseNameBlocks emits the measured per-parameter blocks, in URL order.
func angularParseNameBlocks(rawQuery string) string {
	var b strings.Builder
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		fmt.Fprintf(&b, "var key = '%s';\n$scope.query[key] = '%s';\n$scope.value = $parse(key)($scope.query);\n",
			angularLabEscaped(name), angularLabEscaped(value))
	}
	return b.String()
}

type angularResult struct {
	findings []*domain.Finding
	cases    []*domain.TestCase
	detail   findingDetail
	marker   string
}

// runAngularJob probes one endpoint/source with the real executor.
func runAngularJob(t *testing.T, mgr *browser.Manager, labURL, path, source string, queryParam bool) angularResult {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(labURL+path+"?q=unused", domain.MethodGET)
	if queryParam {
		env.param(ep, "q", domain.LocationQuery, "unused")
	}
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, labURL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, source)); err != nil {
		t.Fatalf("dom-xss job for %s: %v", path, err)
	}
	fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	res := angularResult{findings: fs, cases: cases, marker: detection.NewProbe(env.scanID, ep.ID).Token}
	if len(fs) == 1 {
		res.detail = decodeFindingDetail(fs[0].Detail)
	}
	return res
}

func TestDOMAngularExpressionCompiled(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/dom", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("an ng-app page that compiles the interpolation must Confirm, got %s: %q", f.Verdict, f.Summary)
	}
	if !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeCompiled) {
		t.Fatalf("confirmed angular finding must carry the compiled outcome: %q", f.Summary)
	}
	if !strings.Contains(f.Summary, "not a sandbox escape") {
		t.Fatalf("confirmation must state that no escape was attempted: %q", f.Summary)
	}
	if !strings.Contains(f.Title, "angular_expression") {
		t.Fatalf("finding title must name the sink: %q", f.Title)
	}
	if len(res.detail.Candidates) != 1 {
		t.Fatalf("want one candidate: %+v", res.detail.Candidates)
	}
	cand := res.detail.Candidates[0]
	if string(cand.Context) != "angular_expression" || cand.ContextSub != "location.search" {
		t.Fatalf("candidate provenance: %+v", cand)
	}
	if !strings.HasPrefix(cand.Value, "{{") || strings.Contains(cand.Value, res.marker) {
		t.Fatalf("candidate must be a split-marker interpolation, got %q (marker %q)", cand.Value, res.marker)
	}
	if len(res.detail.Attempts) != 2 || res.detail.Attempts[1].Verdict != domain.VerdictConfirmed {
		t.Fatalf("want reachability + confirmed verification attempts: %+v", res.detail.Attempts)
	}
	for _, id := range f.EvidenceIDs {
		if id.Empty() {
			t.Fatal("empty evidence id")
		}
	}
	if !strings.Contains(f.Summary, "compiled interpolation RESULT") {
		t.Fatalf("summary must say what confirmed: %q", f.Summary)
	}
}

// TestDOMAngularExpressionParameterNameParse is the measured binding form:
// the page stores each parameter VALUE as data and hands each parameter NAME
// to $parse. The interpolation shape therefore stays inert text (an honest
// Rejected, recorded as its own attempt) and the parameter-NAME shape, which
// must survive the page rewriting both quote styles, is the one that confirms.
func TestDOMAngularExpressionParameterNameParse(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/parse-name", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("the parameter-NAME expression evaluates to the marker and must Confirm, got %s: %q", f.Verdict, f.Summary)
	}
	if !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeCompiled) {
		t.Fatalf("confirmed finding must carry the compiled outcome: %q", f.Summary)
	}
	if !strings.Contains(f.Summary, "query parameter NAME") {
		t.Fatalf("the summary must state which channel was compiled: %q", f.Summary)
	}
	if !strings.Contains(f.Summary, "not a sandbox escape") {
		t.Fatalf("confirmation must state that no escape was attempted: %q", f.Summary)
	}
	// Reachability, then the interpolation shape's honest negative, then the
	// parameter-NAME shape's confirmation.
	if len(res.detail.Attempts) != 3 {
		t.Fatalf("want reachability + interpolation + parameter-name attempts, got %+v", res.detail.Attempts)
	}
	if a := res.detail.Attempts[1]; a.Verdict != domain.VerdictRejected || !strings.Contains(a.Notes, domXSSAngularOutcomeInertText) {
		t.Fatalf("the interpolation shape must stay Rejected(inert_text) on a value-as-data page, got %s: %q", a.Verdict, a.Notes)
	}
	if a := res.detail.Attempts[2]; a.Verdict != domain.VerdictConfirmed {
		t.Fatalf("the parameter-name attempt must be the confirming one, got %s: %q", a.Verdict, a.Notes)
	}
	// The confirming navigation must really carry the candidate as a NAME.
	nav, err := url.Parse(res.detail.Attempts[2].URL)
	if err != nil {
		t.Fatalf("confirmed attempt URL does not parse: %v (%q)", err, res.detail.Attempts[2].URL)
	}
	q := nav.Query()
	if q.Get("q") != domXSSNamedExpressionAnchorValue {
		t.Fatalf("the anchor parameter must keep its benign value, got %q from %q", q.Get("q"), nav.RawQuery)
	}
	var delivered string
	for name := range q {
		if strings.HasPrefix(name, "[(") && strings.HasSuffix(name, "].join([])") {
			delivered = name
		}
	}
	if delivered == "" {
		t.Fatalf("no parameter-name expression found in %q", nav.RawQuery)
	}
	if strings.Contains(delivered, res.marker) {
		t.Fatalf("the delivered expression must never contain the contiguous marker: %q", delivered)
	}
	if strings.ContainsAny(delivered, `'"`) {
		t.Fatalf("the delivered expression must survive the page's quote encoding (no string literals): %q", delivered)
	}
	// Both shapes are recorded as candidates of the same finding (never a
	// near-duplicate row), and the value one was tried first.
	if len(res.detail.Candidates) != 2 {
		t.Fatalf("want both shapes recorded on one finding, got %+v", res.detail.Candidates)
	}
	if res.detail.Candidates[0].Shape != "angular_interpolation" || res.detail.Candidates[1].Shape != "angular_parse_expression" {
		t.Fatalf("candidate shapes must be ordered interpolation-then-name: %+v", res.detail.Candidates)
	}
	if len(f.EvidenceIDs) == 0 {
		t.Fatal("a confirmed finding must carry evidence")
	}
}

// TestDOMAngularExpressionNameEchoNeverConfirms is the false-positive guard
// for the parameter-NAME channel: the page renders the whole decoded query
// string — so the delivered parameter name appears in rendered text — but it
// never hands that name to $parse. Demonstrating the bytes is not compiling
// them, so the finding stays Rejected and no attempt may Confirm.
func TestDOMAngularExpressionNameEchoNeverConfirms(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/name-echo", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a page that only displays the parameter name must never Confirm: %q", f.Summary)
	}
	if f.Verdict != domain.VerdictRejected || !strings.Contains(f.Summary, domXSSAngularOutcomeInertText) {
		t.Fatalf("the echoed interpolation source is an inert-text rejection, got %s: %q", f.Verdict, f.Summary)
	}
	for _, a := range res.detail.Attempts {
		if a.Verdict == domain.VerdictConfirmed {
			t.Fatalf("no attempt may Confirm on a page that never compiles the name: %+v", a)
		}
	}
}

func TestDOMAngularExpressionRequiresBootstrap(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/noapp", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("the false-positive guard must still reach verification, got %d findings", len(res.findings))
	}
	f := res.findings[0]
	if f.Verdict != domain.VerdictRejected {
		t.Fatalf("without ng-app the literal must stay Rejected, got %s: %q", f.Verdict, f.Summary)
	}
	if !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeInertText) {
		t.Fatalf("rejection must explain inert text: %q", f.Summary)
	}
	if !strings.Contains(f.Summary, "never evaluated it") {
		t.Fatalf("rejection must state that no evaluation happened: %q", f.Summary)
	}
}

func TestDOMAngularExpressionPlainTextEcho(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/plain", "location.search", true)
	// A page with no AngularJS at all is not an Angular candidate: from the
	// DOM alone it is indistinguishable from every page that merely displays a
	// value as text, so claiming a reachable angular sink there would open a
	// rejected finding on every reflected search page. The honest outcome is
	// the existing negative — no implemented DOM-XSS sink reachable — and it
	// can never be Confirmed. The ng-app-removed fixture above is the
	// Angular-present control that does reach verification and is Rejected.
	if len(res.findings) != 0 {
		t.Fatalf("a page with no Angular must not fabricate an angular candidate, got %+v", res.findings)
	}
	if len(res.cases) != 1 || !strings.Contains(res.cases[0].Note, "no implemented DOM-XSS sink reachable") {
		t.Fatalf("want the explicit no-sink-reachable negative, got %+v", res.cases)
	}
}

func TestDOMAngularExpressionUnderCSPStillCompiles(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/csp-angular", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want one finding, got %d", len(res.findings))
	}
	f := res.findings[0]
	// AngularJS probes new Function once and, when CSP refuses it, switches to
	// its own CSP-safe interpreter. The marker is therefore NOT blocked, and
	// a CSP header alone must never be reported as csp_blocked.
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("Angular's CSP-safe interpreter compiled the marker, so the verdict must Confirm, got %s: %q", f.Verdict, f.Summary)
	}
	if strings.Contains(f.Summary, domXSSAngularOutcomeCSPBlocked) {
		t.Fatalf("a CSP header is not a blocked compile: %q", f.Summary)
	}
}

// angularBlockedCompilerPage is a minimal template compiler with NO CSP-safe
// fallback: it evaluates each {{...}} text-node expression with new Function
// and writes the result back, exactly the text-node write Angular performs.
// Under a script-src without 'unsafe-eval' the compile itself is refused, which
// is the case the csp_blocked outcome exists for. The /blocked control (same
// page, no CSP header) proves the fixture would compile if policy allowed it.
const angularBlockedCompilerPage = `<!doctype html><html><body ng-app><div id="out">You searched for: '%s'</div>
<script>
(function(){
  function compile(){
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null), n;
    while ((n = walker.nextNode())) {
      var data = n.nodeValue, m = /\{\{([^}]*)\}\}/.exec(data);
      if (!m) continue;
      var fn = new Function('$id', 'return (' + m[1] + ')');
      n.nodeValue = data.slice(0, m.index) + fn(42) + data.slice(m.index + m[0].length);
    }
  }
  document.addEventListener('DOMContentLoaded', compile);
})();
</script></body></html>`

func TestDOMAngularExpressionCSPBlocked(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/blocked-csp", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("the CSP page must still reach verification, got %d findings", len(res.findings))
	}
	f := res.findings[0]
	if f.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a refused compile must never Confirm: %q", f.Summary)
	}
	if f.Verdict == domain.VerdictRejected {
		t.Fatalf("a CSP refusal must not be recorded as a plain Rejected: %q", f.Summary)
	}
	if f.Verdict != domain.VerdictInconclusive {
		t.Fatalf("want Inconclusive for csp_blocked, got %s", f.Verdict)
	}
	if !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeCSPBlocked) || !strings.Contains(f.Summary, "script-src") || !strings.Contains(f.Summary, `blocked="eval"`) {
		t.Fatalf("csp_blocked outcome must name the blocking directive and eval: %q", f.Summary)
	}
	// Reachability, the CSP-blocked interpolation, and the parameter-NAME
	// shape's untested outcome. Neither attempt may upgrade the finding past
	// csp_blocked: a policy refusal stays Inconclusive on every shape.
	if len(res.detail.Attempts) != 3 {
		t.Fatalf("want reachability + interpolation + parameter-name attempts: %+v", res.detail.Attempts)
	}
	if a := res.detail.Attempts[1]; a.Verdict != domain.VerdictInconclusive || !strings.Contains(a.Notes, "outcome="+domXSSAngularOutcomeCSPBlocked) {
		t.Fatalf("the interpolation attempt must itself carry the csp_blocked Inconclusive verdict: %+v", a)
	}
	if a := res.detail.Attempts[2]; a.Verdict != domain.VerdictInconclusive {
		t.Fatalf("a CSP-blocked page must not be upgraded by the parameter-name shape, got %s: %q", a.Verdict, a.Notes)
	}
}

func TestDOMAngularExpressionCSPBlockedControl(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/blocked", "location.search", true)
	if len(res.findings) != 1 || res.findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("without CSP the same compiler must Confirm, proving the csp_blocked result is about the policy: %+v", res.findings)
	}
}

func TestDOMAngularExpressionFromHash(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/hash", "location.hash", false)
	if len(res.findings) != 1 {
		t.Fatalf("want one hash-sourced angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("a page that $compile()s the fragment must Confirm, got %s: %q", f.Verdict, f.Summary)
	}
	if len(res.detail.Candidates) != 1 || res.detail.Candidates[0].ContextSub != "location.hash" {
		t.Fatalf("hash provenance: %+v", res.detail.Candidates)
	}
}

// TestDOMAngularExpressionBindingResult covers the class where Angular does
// evaluate the interpolation but the write is not part of rendered body text:
// a textarea's content is compiled as template source, so the marker reaches
// the textarea's value and never a body text node. The harness must read the
// result from the interpolation function Angular itself compiled instead of
// giving up because the text walk cannot see it.
func TestDOMAngularExpressionBindingResult(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/textarea", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("an evaluated textarea interpolation must Confirm via the binding read, got %s: %q", f.Verdict, f.Summary)
	}
	if !strings.Contains(f.Summary, "compiled interpolation binding") {
		t.Fatalf("confirmation must say the result was read from Angular's binding: %q", f.Summary)
	}
	if !strings.Contains(f.Summary, "compiled interpolation RESULT") {
		t.Fatalf("summary must say what confirmed: %q", f.Summary)
	}
	if len(res.detail.Attempts) != 2 || res.detail.Attempts[1].Verdict != domain.VerdictConfirmed {
		t.Fatalf("want reachability + confirmed verification attempts: %+v", res.detail.Attempts)
	}
}

// TestDOMAngularExpressionWithoutStringsLabShape pins the measured
// without-strings lab: the server writes the query value into a scope string
// with its quotes HTML-encoded, the controller resolves the parameter NAME
// through $parse, and the template only interpolates {{value}}. The candidate
// is therefore inert, entity-encoded data — never re-compiled — so the honest
// verdict is Rejected(inert_text): not Confirmed, and no longer the old
// "unobserved" that a raw substring check produced.
func TestDOMAngularExpressionWithoutStringsLabShape(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/parse-key", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a page that never re-compiles the value must never Confirm: %q", f.Summary)
	}
	if f.Verdict != domain.VerdictRejected {
		t.Fatalf("the entity-encoded inert candidate must be Rejected, got %s: %q", f.Verdict, f.Summary)
	}
	if !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeInertText) {
		t.Fatalf("rejection must explain inert text: %q", f.Summary)
	}
}

// TestDOMAngularExpressionNgBindConstantStaysRejected is the constant-value
// guard: ng-app is present, but ng-bind writes the search value as DATA, so a
// string containing {{...}} is never template source and must stay Rejected.
// The binding read must not evaluate page-authored bindings either.
func TestDOMAngularExpressionNgBindConstantStaysRejected(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := angularLab(t)
	res := runAngularJob(t, mgr, lab.URL, "/constant", "location.search", true)
	if len(res.findings) != 1 {
		t.Fatalf("want exactly one angular finding, got %d: %+v", len(res.findings), res.findings)
	}
	f := res.findings[0]
	if f.Verdict == domain.VerdictConfirmed {
		t.Fatalf("ng-bind data is not template source and must never Confirm: %q", f.Summary)
	}
	if f.Verdict != domain.VerdictRejected || !strings.Contains(f.Summary, "outcome="+domXSSAngularOutcomeInertText) {
		t.Fatalf("the constant bound string must stay Rejected(inert_text), got %s: %q", f.Verdict, f.Summary)
	}
}

// TestDOMXSSExistingSinkConfirmationsUnchanged is the slice's behavioural
// regression gate: each pre-existing confirmed sink still confirms, with its
// own sink identity, after angular_expression was added. The angular fallback
// must never take over a page whose own code reaches a hooked sink.
func TestDOMXSSExistingSinkConfirmationsUnchanged(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	jq := jqueryFixture(t)
	cases := []struct {
		name, sink, action string
		usesJQuery         bool
	}{
		{"innerHTML", "innerHTML", `sink.innerHTML=value;`, false},
		{"outerHTML", "outerHTML", `sink.outerHTML='<div id="sink">'+value+'</div>';`, false},
		{"document.write", "document.write", `document.write(value);`, false},
		{"insertAdjacentHTML", "insertAdjacentHTML", `sink.insertAdjacentHTML('beforeend',value);`, false},
		{"createContextualFragment", "Range.createContextualFragment", `const range=document.createRange();range.selectNodeContents(sink);sink.appendChild(range.createContextualFragment(value));`, false},
		{"setTimeout", "setTimeout", `window.setTimeout(value,0);`, false},
		{"setInterval", "setInterval", `window.setInterval(value,0);`, false},
		{"jQuery.selector", "jQuery.selector", `$('#sink').html($(value));`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page := `<!doctype html><div id="sink"></div><script>const sink=document.getElementById('sink');const value=decodeURIComponent(location.hash.slice(1));` + tc.action + `</script>`
			var lab *httptest.Server
			if tc.usesJQuery {
				lab = jqueryLab(t, jq, `<!doctype html><div id="sink"></div><script src="/jq.js"></script><script>const sink=document.getElementById('sink');const value=decodeURIComponent(location.hash.slice(1));`+tc.action+`</script>`)
			} else {
				lab = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					fmt.Fprint(w, page)
				}))
				t.Cleanup(lab.Close)
			}
			env := newScanEnv(t)
			ep := env.endpoint(lab.URL, domain.MethodGET)
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.hash")); err != nil {
				t.Fatalf("dom-xss job: %v", err)
			}
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(fs) != 1 {
				t.Fatalf("%s: want exactly one finding, got %d: %+v", tc.sink, len(fs), fs)
			}
			if fs[0].Verdict != domain.VerdictConfirmed {
				t.Fatalf("%s: existing confirmed behaviour regressed: verdict=%s summary=%q", tc.sink, fs[0].Verdict, fs[0].Summary)
			}
			d := decodeFindingDetail(fs[0].Detail)
			if len(d.Candidates) == 0 || string(d.Candidates[0].Context) != tc.sink {
				t.Fatalf("%s: sink identity changed: %+v", tc.sink, d.Candidates)
			}
		})
	}
}

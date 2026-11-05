//go:build browser_integration

package scan

// Regression coverage for eval-sink attribution in the DOM-XSS harness.
//
// Eval reachability used to come from a wrapper installed over window.eval.
// Two defects: (1) Playwright's Page.Evaluate runs its expression through the
// page's eval, so every scanner-owned script carrying the candidate value (the
// window.name setter, the postMessage sender, activation scripts) was reported
// as a TARGET eval sink, producing spurious Context:eval findings and extra
// execution_* candidates; (2) a wrapper turns a target's DIRECT eval into an
// indirect, global-scope call. Reachability now comes from the browser
// engine's runtime provenance (compilations observed natively), which leaves
// eval untouched, and Page.Evaluate scripts are tagged so they are not
// attributed to the target. Target eval use, including a computed argument,
// must still be reported.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
)

func TestDOMXSSHarnessEvalAttribution(t *testing.T) {
	ctx := context.Background()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	marker := "indevalattribution0001"

	// serve a page whose OWN script calls eval, then collect the harness view of
	// it exactly the way the executor does (init-script reports + engine-level
	// runtime provenance).
	observe := func(t *testing.T, script string) (domXSSObservation, *browser.Page) {
		t.Helper()
		lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><body><script>`+script+`</script></body>`)
		}))
		t.Cleanup(lab.Close)
		bc, err := mgr.NewContext(ctx, browser.ContextOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { bc.Close() })
		ex := &domXSSExecutor{}
		page, err := ex.openObservedPage(ctx, bc, marker)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { page.Close() })
		if _, err := page.Navigate(ctx, lab.URL+"/", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
			t.Fatal(err)
		}
		obs, err := observePage(ctx, page, 300*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		return obs, page
	}

	t.Run("target direct eval of marker-carrying code is still reported", func(t *testing.T) {
		// A computed argument: V8 reports the compilation at the operator, not at
		// the eval( token (the measured XHR-echo lab evals 'var o = ' + body).
		obs, _ := observe(t, `var x = "`+marker+`"; eval("var probe = '" + x + "';");`)
		got := parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker)
		found := false
		for _, r := range got {
			if r == detection.DOMSinkEval {
				found = true
			}
		}
		if !found {
			t.Fatalf("a target eval(marker) must still establish reachability, got %+v runtime=%+v", got, obs.Runtime)
		}
	})

	t.Run("scanner evaluation carrying the marker is not a target eval sink", func(t *testing.T) {
		_, page := observe(t, ``)
		if _, err := evaluateDOMXSSScript(ctx, page, setWindowNameScript(marker), domXSSEvaluateBound); err != nil {
			t.Fatal(err)
		}
		if got, _ := page.Evaluate(ctx, "window.name"); got != marker {
			t.Fatalf("the scanner script must still run natively, window.name=%v", got)
		}
		obs, err := observePage(ctx, page, 300*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if got := parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker); len(got) != 0 {
			t.Fatalf("scanner-owned evaluation was reported as target sink(s) %v; runtime=%+v", got, obs.Runtime)
		}
	})

	// Live-Chromium syntax controls for the computed-argument recovery: V8
	// reports the compilation at the operator, and text that merely looks like
	// an eval( call (a comment, a string) must not be read as the callee.
	t.Run("a string timer whose comment mentions eval( is not an eval sink", func(t *testing.T) {
		obs, _ := observe(t, `var x = "`+marker+`"; setTimeout(/* eval( */ "var probe = '" + x + "';", 0);`)
		// The timer itself is a legitimately hooked setTimeout sink; what must
		// not appear is any eval attribution.
		if len(obs.Runtime.Compilations) != 0 {
			t.Fatalf("a comment must not make a timer compilation an eval sink, compilations=%+v", obs.Runtime.Compilations)
		}
		for _, r := range parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker) {
			if r == detection.DOMSinkEval {
				t.Fatal("a comment must not make a timer compilation an eval sink")
			}
		}
	})

	t.Run("a computed argument whose string mentions eval( is not an eval sink", func(t *testing.T) {
		obs, _ := observe(t, `var x = "`+marker+`"; setTimeout("eval(" + x + ");", 0);`)
		// The timer itself is a legitimately hooked setTimeout sink; what must
		// not appear is any eval attribution.
		if len(obs.Runtime.Compilations) != 0 {
			t.Fatalf("a string must not make a timer compilation an eval sink, compilations=%+v", obs.Runtime.Compilations)
		}
		for _, r := range parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker) {
			if r == detection.DOMSinkEval {
				t.Fatal("a string must not make a timer compilation an eval sink")
			}
		}
	})

	t.Run("a genuine eval with a comment and a computed argument is reported", func(t *testing.T) {
		obs, _ := observe(t, `var x = "`+marker+`"; eval(/* note: eval( */ "var probe = '" + x + "';");`)
		found := false
		for _, r := range parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker) {
			found = found || r == detection.DOMSinkEval
		}
		if !found {
			t.Fatalf("a real eval must stay reachable despite a comment in its arguments, runtime=%+v", obs.Runtime)
		}
	})

	t.Run("eval of code without the marker is not reported", func(t *testing.T) {
		obs, _ := observe(t, `eval("var probe = 'constant';");`)
		if got := parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker); len(got) != 0 {
			t.Fatalf("no marker reached eval, got %+v", got)
		}
	})

	t.Run("direct eval keeps its lexical scope with the harness installed", func(t *testing.T) {
		obs, _ := observe(t, `(function () {
  var local = 1;
  var read = eval("local + 10");
  eval("local = 5");
  eval("var declared = 7");
  document.title = JSON.stringify({ read: read, local: local, declared: typeof declared === 'undefined' ? null : declared });
})();`)
		if !strings.Contains(obs.HTML, `<title>{"read":11,"local":5,"declared":7}</title>`) &&
			!strings.Contains(obs.HTML, `{&#34;read&#34;:11,&#34;local&#34;:5,&#34;declared&#34;:7}`) &&
			!strings.Contains(obs.HTML, `{"read":11,"local":5,"declared":7}`) {
			t.Fatalf("direct eval lost its lexical scope (page threw?): errors=%v html=%s", obs.PageErrors, obs.HTML)
		}
	})
}

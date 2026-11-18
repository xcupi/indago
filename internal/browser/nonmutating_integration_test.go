// These tests drive a REAL Chromium and prove the browser method gate's
// end-to-end behaviour against a loopback server the test owns: a GET page whose
// own JavaScript issues a POST must not reach the server unless the context was
// explicitly granted the scan's AllowStateChanging opt-in. Every fixture also
// proves its own GET control succeeds, so a zero POST count cannot be explained
// by "the script never ran". Like the other real-browser tests here, they skip
// (quickly) when no Chromium can be found.
package browser_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

// methodGateFixture is a loopback site with one page that fires a GET control
// and a POST from its own inline script. The server counts what actually arrived.
type methodGateFixture struct {
	srv     *httptest.Server
	page    atomic.Int64
	control atomic.Int64
	mutate  atomic.Int64
	// lastMutation records the method and body of the most recent POST.
	lastMethod atomic.Value // string
	lastBody   atomic.Value // string
}

const methodGatePage = `<!doctype html><html><body>
<div id="get">pending</div><div id="post">pending</div>
<script>
fetch('/control').then(function(){ document.getElementById('get').textContent = 'done'; })
                 .catch(function(){ document.getElementById('get').textContent = 'failed'; });
fetch('/mutate', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'k=v'})
  .then(function(){ document.getElementById('post').textContent = 'sent'; })
  .catch(function(){ document.getElementById('post').textContent = 'blocked'; });
</script></body></html>`

func newMethodGateFixture(t *testing.T) *methodGateFixture {
	t.Helper()
	f := &methodGateFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		f.page.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, methodGatePage)
	})
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("/control saw %s, want GET", r.Method)
		}
		f.control.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		f.mutate.Add(1)
		f.lastMethod.Store(r.Method)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 256))
		f.lastBody.Store(string(body))
		_, _ = fmt.Fprint(w, "ok")
	})
	// A form/JSON replay target plus a 307 hop, used by the explicit-opt-in test.
	mux.HandleFunc("/form-target", func(w http.ResponseWriter, r *http.Request) {
		f.lastMethod.Store(r.Method)
		_, _ = fmt.Fprint(w, "<!doctype html><body>form ok</body>")
	})
	mux.HandleFunc("/json-target", func(w http.ResponseWriter, r *http.Request) {
		f.lastMethod.Store(r.Method)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, "<!doctype html><body>json ok</body>")
	})
	mux.HandleFunc("/redir307", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/form-target", http.StatusTemporaryRedirect)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *methodGateFixture) allowAll(raw string) bool {
	return strings.HasPrefix(raw, f.srv.URL)
}

// newMethodGateManager starts a Manager for this file's real-browser tests. Like
// internal/verification's helper, it lowers isolation ONLY when the operator
// explicitly asks for it with INDAGO_TEST_BROWSER_NO_SANDBOX=1 (a restricted
// container without user namespaces); the default keeps Chromium's sandbox ON.
func newMethodGateManager(t *testing.T) *browser.Manager {
	t.Helper()
	cfg := browser.DefaultConfig()
	if os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1" {
		cfg.DisableSandbox = true
	}
	return newManagerOrSkip(t, cfg)
}

// waitForPageText polls one element of the loaded page until it reaches want.
// The page sets these itself, so seeing "done" for the GET control proves the
// inline script executed and the control request actually completed.
func waitForPageText(t *testing.T, ctx context.Context, p *browser.Page, id, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		raw, err := p.Evaluate(ctx, `(() => { const el = document.getElementById("`+id+`"); return el ? el.textContent : ""; })()`)
		if err == nil {
			if s, ok := raw.(string); ok {
				last = s
				if s == want {
					return
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("page element #%s never became %q (last observed %q)", id, want, last)
}

// TestIntegrationDefaultContextBlocksPageInitiatedPOST is the scan-default case:
// an in-scope GET page runs its own script, the GET control reaches the server,
// and the POST the same script issues does not.
func TestIntegrationDefaultContextBlocksPageInitiatedPOST(t *testing.T) {
	f := newMethodGateFixture(t)
	m := newMethodGateManager(t)
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, browser.ContextOptions{AllowRequest: f.allowAll}) // AllowStateChanging defaults to false
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	nav, err := p.Navigate(ctx, f.srv.URL+"/page", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("navigate: %v", err)
	}
	if nav.Status != http.StatusOK {
		t.Fatalf("page status = %d, want 200", nav.Status)
	}
	// The control proves the page's own script ran and a GET it issued reached
	// the server, so the zero POST count below is a refusal, not an inert page.
	waitForPageText(t, ctx, p, "get", "done")
	waitForPageText(t, ctx, p, "post", "blocked")

	if got := f.control.Load(); got != 1 {
		t.Fatalf("GET control reached the server %d times, want 1", got)
	}
	if got := f.mutate.Load(); got != 0 {
		t.Fatalf("the page's POST reached the server %d times under the non-mutating default (method=%v body=%q), want 0", got, f.lastMethod.Load(), f.lastBody.Load())
	}
	t.Logf("RESULT default-context page=%d control=%d mutate=%d (POST refused by browser)", f.page.Load(), f.control.Load(), f.mutate.Load())
}

// TestIntegrationStateChangingOptInAllowsPagePOST is the positive control: the
// same fixture and page, with the explicit opt-in, must let the POST through.
func TestIntegrationStateChangingOptInAllowsPagePOST(t *testing.T) {
	f := newMethodGateFixture(t)
	m := newMethodGateManager(t)
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, browser.ContextOptions{AllowRequest: f.allowAll, AllowStateChanging: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.Navigate(ctx, f.srv.URL+"/page", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	waitForPageText(t, ctx, p, "get", "done")
	waitForPageText(t, ctx, p, "post", "sent")

	if got := f.mutate.Load(); got != 1 {
		t.Fatalf("POST reached the server %d times with the opt-in, want 1", got)
	}
	if got, _ := f.lastMethod.Load().(string); got != http.MethodPost {
		t.Fatalf("server saw method %q, want POST", got)
	}
	if got, _ := f.lastBody.Load().(string); got != "k=v" {
		t.Fatalf("server saw body %q, want k=v", got)
	}
	t.Logf("RESULT opt-in page=%d control=%d mutate=%d method=%v body=%q", f.page.Load(), f.control.Load(), f.mutate.Load(), f.lastMethod.Load(), f.lastBody.Load())
}

// TestIntegrationExplicitPOSTReplayNeedsOptIn pins the explicit replay paths
// (form and JSON navigations) to the same opt-in. Without it they fail with a
// named error before anything is sent; with it they are replayed normally, and
// a 307 that preserves the POST is followed.
func TestIntegrationExplicitPOSTReplayNeedsOptIn(t *testing.T) {
	f := newMethodGateFixture(t)
	m := newMethodGateManager(t)
	defer m.Close()
	ctx := context.Background()

	t.Run("default-refuses", func(t *testing.T) {
		c, err := m.NewContext(ctx, browser.ContextOptions{AllowRequest: f.allowAll})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		p, err := c.NewPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()

		if _, err := p.NavigateForm(ctx, http.MethodPost, f.srv.URL+"/form-target", map[string]string{"q": "x"}, browser.NavOptions{Timeout: 5 * time.Second}); !errors.Is(err, browser.ErrStateChangingBlocked) {
			t.Fatalf("NavigateForm err = %v, want ErrStateChangingBlocked", err)
		}
		if _, err := p.NavigateJSON(ctx, f.srv.URL+"/json-target", []byte(`{"q":"x"}`), "application/json", browser.NavOptions{Timeout: 5 * time.Second}); !errors.Is(err, browser.ErrStateChangingBlocked) {
			t.Fatalf("NavigateJSON err = %v, want ErrStateChangingBlocked", err)
		}
		if got := f.mutate.Load(); got != 0 {
			t.Fatalf("%d POST(s) reached /mutate without the opt-in, want 0", got)
		}
	})

	t.Run("opt-in-replays", func(t *testing.T) {
		c, err := m.NewContext(ctx, browser.ContextOptions{AllowRequest: f.allowAll, AllowStateChanging: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		p, err := c.NewPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()

		if _, err := p.NavigateForm(ctx, http.MethodPost, f.srv.URL+"/form-target", map[string]string{"q": "x"}, browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second}); err != nil {
			t.Fatalf("NavigateForm with the opt-in: %v", err)
		}
		if got, _ := f.lastMethod.Load().(string); got != http.MethodPost {
			t.Fatalf("form replay method = %q, want POST", got)
		}
		if _, err := p.NavigateJSON(ctx, f.srv.URL+"/json-target", []byte(`{"q":"x"}`), "application/json", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second}); err != nil {
			t.Fatalf("NavigateJSON with the opt-in: %v", err)
		}
		if got, _ := f.lastMethod.Load().(string); got != http.MethodPost {
			t.Fatalf("JSON replay method = %q, want POST", got)
		}
		// A 307 preserves POST; with the opt-in the redirect gate must let it
		// through rather than over-blocking an allowed replay.
		if _, err := p.NavigateForm(ctx, http.MethodPost, f.srv.URL+"/redir307", map[string]string{"q": "x"}, browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second}); err != nil {
			t.Fatalf("307-preserving POST replay with the opt-in: %v", err)
		}
		if got, _ := f.lastMethod.Load().(string); got != http.MethodPost {
			t.Fatalf("307 redirect hop method = %q, want POST preserved", got)
		}
	})
}

// TestIntegrationPopupPOSTBlockedByMethodGate covers the popup surface. The
// context is UNSCOPED on purpose, so the popup itself is allowed to open: what
// stops its POST is the method gate alone, reached through the same context
// route that serves ordinary pages. The popup reports its own outcome into the
// parent (same origin), and the server counts what arrived.
func TestIntegrationPopupPOSTBlockedByMethodGate(t *testing.T) {
	const popupPage = `<!doctype html><html><body><div id="popup-post">pending</div>
<script>
fetch('/popup-control').catch(function(){});
fetch('/popup-mutate', {method: 'POST', body: 'p=1'})
  .then(function(){ document.getElementById('popup-post').textContent = 'sent'; })
  .catch(function(){ document.getElementById('popup-post').textContent = 'blocked'; });
</script></body></html>`
	const parentPage = `<!doctype html><html><body><div id="parent">opening</div>
<script>
var w = window.open('/popup-page', '_blank');
var tries = 0;
var timer = setInterval(function () {
  tries++;
  try {
    if (w && w.document && w.document.getElementById('popup-post') &&
        w.document.getElementById('popup-post').textContent === 'blocked') {
      document.getElementById('parent').textContent = 'popup-blocked';
      clearInterval(timer);
    }
  } catch (e) {}
  if (tries > 400) { clearInterval(timer); }
}, 25);
</script></body></html>`

	var popupOpened, popupControl, popupMutate atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/popup-parent", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, parentPage)
	})
	mux.HandleFunc("/popup-page", func(w http.ResponseWriter, r *http.Request) {
		popupOpened.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, popupPage)
	})
	mux.HandleFunc("/popup-control", func(w http.ResponseWriter, r *http.Request) {
		popupControl.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/popup-mutate", func(w http.ResponseWriter, r *http.Request) {
		popupMutate.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := newMethodGateManager(t)
	defer m.Close()
	ctx := context.Background()
	// No AllowRequest: an unscoped context, so the scope gate cannot be what
	// keeps the popup's POST out.
	c, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.Navigate(ctx, srv.URL+"/popup-parent", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second}); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	waitForPageText(t, ctx, p, "parent", "popup-blocked")

	if got := popupOpened.Load(); got != 1 {
		t.Fatalf("popup document was opened %d times, want 1 (the popup must be allowed so the method gate is what stops the POST)", got)
	}
	if got := popupControl.Load(); got != 1 {
		t.Fatalf("popup GET control reached the server %d times, want 1 (the popup's own script must have run)", got)
	}
	if got := popupMutate.Load(); got != 0 {
		t.Fatalf("popup POST reached the server %d times, want 0", got)
	}
	t.Logf("RESULT popup opened=%d control=%d mutate=%d (popup POST refused by method gate)", popupOpened.Load(), popupControl.Load(), popupMutate.Load())
}

// These tests drive a REAL Chromium via Playwright. They run by default and skip
// (quickly) when no Chromium can be found, so `go test ./...` never fails on a
// machine without one. Chromium is located via $INDAGO_CHROMIUM_PATH or the
// Playwright cache (~/.cache/ms-playwright/chromium-*); it is launched by
// explicit path, so the Playwright driver and the installed revision need not
// match. Install one with `playwright install chromium`.
package browser_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

// findChromium locates an installed Chromium: $INDAGO_CHROMIUM_PATH, then the
// newest build in the Playwright cache. The Playwright driver and the installed
// Chromium revision can differ; launching by explicit path lets them be paired.
func findChromium() string {
	if p := os.Getenv("INDAGO_CHROMIUM_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func newManagerOrSkip(t *testing.T, cfg browser.Config) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	if cfg.ExecutablePath == "" {
		cfg.ExecutablePath = findChromium()
	}
	if cfg.ExecutablePath == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	m, err := browser.NewManager(cfg, nil)
	if err != nil {
		t.Skipf("browser engine unavailable (install Playwright/Chromium or set INDAGO_CHROMIUM_PATH): %v", err)
	}
	return m
}

func TestIntegrationRenderRealBrowser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><head><title>t</title></head>
<body><h1 id="h">hello indago</h1>
<script>console.log("from page");localStorage.setItem("k","v");</script>
</body></html>`)
	}))
	defer srv.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()

	res, err := m.Render(context.Background(), srv.URL, browser.RenderOptions{
		WaitUntil:  browser.WaitLoad,
		Screenshot: true,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status = %d", res.Status)
	}
	if !strings.Contains(res.HTML, "hello indago") {
		t.Fatalf("HTML missing content: %.100s", res.HTML)
	}
	if len(res.Screenshot) == 0 {
		t.Fatal("no screenshot captured")
	}
	if len(res.Network) == 0 {
		t.Fatal("no network events observed")
	}
}

func TestIntegrationRenderCapturesJSONPostDataForDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script>
fetch('/api/search', {method:'POST', headers:{'Content-Type':'application/vnd.api+json; charset=utf-8'}, body:JSON.stringify({query:'api-xss-input', page:2})});
fetch('/api/large', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({large:'x'.repeat(70 * 1024)})});
</script>`)
	})
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/large", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	res, err := m.Render(context.Background(), srv.URL+"/", browser.RenderOptions{
		WaitUntil:    browser.WaitNetworkIdle,
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL) },
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var observed *browser.NetworkEvent
	for i := range res.Network {
		if res.Network[i].URL == srv.URL+"/api/search" {
			observed = &res.Network[i]
			break
		}
	}
	if observed == nil {
		t.Fatalf("JSON API request not observed: %#v", res.Network)
	}
	if observed.Method != "POST" || observed.ContentType != "application/vnd.api+json; charset=utf-8" || observed.PostData != `{"query":"api-xss-input","page":2}` {
		t.Fatalf("observed JSON request = %#v", *observed)
	}
	encoded, err := json.Marshal(*observed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "api-xss-input") {
		t.Fatalf("ephemeral JSON body escaped through NetworkEvent serialization: %s", encoded)
	}
	var oversized *browser.NetworkEvent
	for i := range res.Network {
		if res.Network[i].URL == srv.URL+"/api/large" {
			oversized = &res.Network[i]
			break
		}
	}
	if oversized == nil || oversized.PostData != "" {
		t.Fatalf("oversized request body should be discarded, event=%#v", oversized)
	}
}

func TestIntegrationRequestObserverDoesNotWaitForResponse(t *testing.T) {
	unblock := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script>fetch('/api/pending', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{"query":"response-pending"}'});</script>`)
	})
	mux.HandleFunc("/api/pending", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-unblock:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(unblock)

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := m.Render(ctx, srv.URL+"/", browser.RenderOptions{
		WaitUntil:    browser.WaitLoad,
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL) },
	})
	if err != nil {
		t.Fatalf("load page while JSON response remains pending: %v", err)
	}
	for _, event := range res.Network {
		if event.URL == srv.URL+"/api/pending" {
			if event.PostData != `{"query":"response-pending"}` {
				t.Fatalf("captured body = %q, want bounded request body", event.PostData)
			}
			return
		}
	}
	t.Fatalf("pending JSON request was not observed: %#v", res.Network)
}

func TestIntegrationContextIsolationReal(t *testing.T) {
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	ctx := context.Background()

	cA, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer cA.Close()
	cB, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer cB.Close()

	if err := cA.SetCookies(ctx, []browser.Cookie{{Name: "sid", Value: "s", URL: "https://example.com/"}}); err != nil {
		t.Fatal(err)
	}
	a, _ := cA.Cookies(ctx)
	b, _ := cB.Cookies(ctx)
	if len(a) == 0 {
		t.Fatal("context A should have its cookie")
	}
	if len(b) != 0 {
		t.Fatalf("context B must not see A's cookie: %v", b)
	}
}

func TestIntegrationCancellationReal(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(block)

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()

	c, err := m.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := p.Navigate(ctx, srv.URL, browser.NavOptions{}); err == nil {
		t.Fatal("expected navigation to be canceled")
	}
}

func TestIntegrationNavigateJSONRedirectScopeGate(t *testing.T) {
	var outsideHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outside" {
			outsideHits.Add(1)
			return
		}
		http.Redirect(w, r, "/outside", http.StatusFound)
	}))
	defer srv.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	ctx, err := m.NewContext(context.Background(), browser.ContextOptions{AllowRequest: func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && strings.HasPrefix(u.Path, "/api/")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	page, err := ctx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	_, _ = page.NavigateJSON(context.Background(), srv.URL+"/api/search", []byte(`{"q":"marker"}`), "application/json", browser.NavOptions{})
	if outsideHits.Load() != 0 {
		t.Fatalf("scope-violating redirect reached the target %d times", outsideHits.Load())
	}
}

func TestIntegrationScopeGateBlocksBackslashPathRedirect(t *testing.T) {
	var insideHits, outsideHits atomic.Int64
	const location = `\outside`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/start":
			insideHits.Add(1)
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusFound)
		case "/outside":
			outsideHits.Add(1)
			fmt.Fprint(w, "outside")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	_, _ = m.Render(context.Background(), srv.URL+"/api/start", browser.RenderOptions{
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") },
	})
	if insideHits.Load() == 0 {
		t.Fatal("the in-scope redirect response was never reached")
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("browser-normalized backslash redirect reached out-of-scope path %d times (Location=%q)", outsideHits.Load(), location)
	}
}

func TestIntegrationScopeGateAllowsInScopeRedirect(t *testing.T) {
	var finalHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/start" {
			http.Redirect(w, r, "/api/final", http.StatusFound)
			return
		}
		if r.URL.Path == "/api/final" {
			finalHits.Add(1)
			fmt.Fprint(w, "in scope")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	res, err := m.Render(context.Background(), srv.URL+"/api/start", browser.RenderOptions{
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") },
	})
	if err != nil {
		t.Fatalf("render in-scope redirect: %v", err)
	}
	if finalHits.Load() != 1 || res.FinalURL != srv.URL+"/api/final" {
		t.Fatalf("in-scope redirect result: hits=%d finalURL=%q", finalHits.Load(), res.FinalURL)
	}
}

func TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect(t *testing.T) {
	var insideHits, outsideHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/start" {
			insideHits.Add(1)
			http.Redirect(w, r, "/api/middle", http.StatusFound)
			return
		}
		if r.URL.Path == "/api/middle" {
			insideHits.Add(1)
			http.Redirect(w, r, "/outside", http.StatusFound)
			return
		}
		if r.URL.Path == "/outside" {
			outsideHits.Add(1)
			fmt.Fprint(w, "outside")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	_, _ = m.Render(context.Background(), srv.URL+"/api/start", browser.RenderOptions{
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") },
	})
	if insideHits.Load() != 2 {
		t.Fatalf("in-scope redirect chain reached the server %d times, want both in-scope hops", insideHits.Load())
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("out-of-scope navigation redirect reached the target %d times", outsideHits.Load())
	}
}

func TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect(t *testing.T) {
	var outsideHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><img src="/api/redirect-image">`)
		case "/api/redirect-image":
			http.Redirect(w, r, "/outside/image", http.StatusFound)
		case "/outside/image":
			outsideHits.Add(1)
			fmt.Fprint(w, "outside")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	_, err := m.Render(context.Background(), srv.URL+"/api/page", browser.RenderOptions{
		WaitUntil:    browser.WaitNetworkIdle,
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") },
	})
	if err != nil {
		t.Fatalf("render in-scope page: %v", err)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("out-of-scope subresource redirect reached the target %d times", outsideHits.Load())
	}
}

func TestIntegrationScopeGateBlocksWebSocketTraffic(t *testing.T) {
	var websocketHits atomic.Int64
	websocketServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		websocketHits.Add(1)
		http.Error(w, "unexpected websocket request", http.StatusBadRequest)
	}))
	defer websocketServer.Close()
	wsURL := "ws" + strings.TrimPrefix(websocketServer.URL, "http") + "/socket"

	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!doctype html><script>new WebSocket(%q)</script>`, wsURL)
	}))
	defer inside.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	if _, err := m.Render(context.Background(), inside.URL+"/api/page", browser.RenderOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("render unscoped WebSocket control: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if websocketHits.Load() == 0 {
		t.Fatal("WebSocket fixture did not reach its loopback server in the unscoped control")
	}
	websocketHits.Store(0)
	_, err := m.Render(context.Background(), inside.URL+"/api/page", browser.RenderOptions{
		WaitUntil:    browser.WaitLoad,
		AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, inside.URL+"/api/") },
	})
	if err != nil {
		t.Fatalf("render scoped websocket fixture: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if websocketHits.Load() != 0 {
		t.Fatalf("out-of-scope WebSocket handshake reached the target %d times", websocketHits.Load())
	}
}

func TestIntegrationScopeGateBlocksServiceWorkerTraffic(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer outside.Close()
	var serviceWorkerScriptHits atomic.Int64
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><body>service worker scope control</body>`)
		case "/api/sw.js":
			serviceWorkerScriptHits.Add(1)
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = fmt.Fprintf(w, `self.addEventListener('install',event=>event.waitUntil(fetch(%q,{mode:'no-cors'})));`, outside.URL+"/outside")
		default:
			http.NotFound(w, r)
		}
	}))
	defer inside.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	registerScript := `(async () => {
		try {
			await navigator.serviceWorker.register('/api/sw.js');
			return 'registered';
		} catch (_) { return 'blocked'; }
	})()`

	// Prove that the fixture would create service-worker traffic without the
	// scoped-context restriction, so a quiet scoped run is a meaningful control.
	controlCtx, err := m.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	controlPage, err := controlCtx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlPage.Navigate(context.Background(), inside.URL+"/api/page", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate unscoped service worker control: %v", err)
	}
	controlResult, err := controlPage.Evaluate(context.Background(), registerScript)
	if err != nil {
		t.Fatalf("register unscoped service worker control: %v", err)
	}
	if controlResult != "registered" {
		t.Fatalf("service worker control did not register: result=%v", controlResult)
	}
	if _, err := controlPage.Evaluate(context.Background(), `navigator.serviceWorker.ready.then(() => true)`); err != nil {
		t.Fatalf("wait for unscoped service worker activation: %v", err)
	}
	if serviceWorkerScriptHits.Load() == 0 || outsideHits.Load() == 0 {
		t.Fatalf("service worker control did not activate: script=%d outside=%d", serviceWorkerScriptHits.Load(), outsideHits.Load())
	}
	if err := controlCtx.Close(); err != nil {
		t.Fatal(err)
	}
	baselineScriptHits, baselineOutsideHits := serviceWorkerScriptHits.Load(), outsideHits.Load()

	ctx, err := m.NewContext(context.Background(), browser.ContextOptions{AllowRequest: func(raw string) bool {
		return strings.HasPrefix(raw, inside.URL+"/api/")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	page, err := ctx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	if _, err := page.Navigate(context.Background(), inside.URL+"/api/page", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate service worker fixture: %v", err)
	}
	evalCtx, cancelEval := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelEval()
	result, err := page.Evaluate(evalCtx, registerScript)
	if err != nil {
		t.Fatalf("attempt service worker registration: %v", err)
	}
	if serviceWorkerScriptHits.Load() != baselineScriptHits || outsideHits.Load() != baselineOutsideHits {
		t.Fatalf("scope-gated service worker escaped: result=%v script=%d/%d outside=%d/%d", result, serviceWorkerScriptHits.Load(), baselineScriptHits, outsideHits.Load(), baselineOutsideHits)
	}
}

func TestIntegrationScopeGateBlocksPopupRedirect(t *testing.T) {
	var popupHits, outsideHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><a id="popup" target="_blank" href="/api/popup-start">open</a><form id="popup-form" target="_blank" action="/api/popup-start"><input name="q" value="x"></form><form id="override-form" action="/api/popup-start"><button id="formtarget" type="submit" formtarget="_blank">submit</button></form>`)
		case "/api/popup-start":
			popupHits.Add(1)
			http.Redirect(w, r, "/outside", http.StatusFound)
		case "/outside":
			outsideHits.Add(1)
			fmt.Fprint(w, "outside")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	ctx, err := m.NewContext(context.Background(), browser.ContextOptions{AllowRequest: func(raw string) bool {
		return strings.HasPrefix(raw, srv.URL+"/api/")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	page, err := ctx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	if _, err := page.Navigate(context.Background(), srv.URL+"/api/page", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate scoped popup fixture: %v", err)
	}
	if _, err := page.Evaluate(context.Background(), `document.querySelector('#popup').click(); document.querySelector('#popup-form').submit(); document.querySelector('#formtarget').click(); window.open('/api/popup-start', 'popup'); true`); err != nil {
		t.Fatalf("trigger scoped popup paths: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if popupHits.Load() != 0 || outsideHits.Load() != 0 {
		t.Fatalf("scoped context allowed popup traffic: popup=%d out-of-scope=%d", popupHits.Load(), outsideHits.Load())
	}
}

// The scope gate must stop out-of-scope requests from LEAVING the browser, not
// merely hide them from the observations.
func TestIntegrationScopeGateBlocksRequestsRealBrowser(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideHits.Add(1)
		fmt.Fprint(w, "x")
	}))
	defer outside.Close()

	var insideHits atomic.Int64
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			insideHits.Add(1)
			fmt.Fprint(w, "{}")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><body>hi
<img src="%[1]s/tracker.png">
<script>fetch("%[1]s/beacon"); fetch("/api");</script></body>`, outside.URL)
	}))
	defer inside.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()

	res, err := m.Render(context.Background(), inside.URL, browser.RenderOptions{
		WaitUntil:    browser.WaitNetworkIdle,
		AllowRequest: func(u string) bool { return strings.HasPrefix(u, inside.URL) },
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("the browser sent %d request(s) to the out-of-scope host", outsideHits.Load())
	}
	if insideHits.Load() == 0 {
		t.Fatal("the in-scope fetch should have gone through")
	}
	for _, ev := range res.Network {
		if !strings.HasPrefix(ev.URL, inside.URL) {
			t.Fatalf("out-of-scope request recorded as an observation: %s", ev.URL)
		}
	}
	if len(res.Blocked) == 0 {
		t.Fatal("blocked requests should be reported")
	}
}

// TestIntegrationNavigateRefererReachesDocumentReferrerRealBrowser proves
// NavOptions.Referer (threaded to pageHandle.Goto's referer override) is
// actually observable as document.referrer in a REAL Chromium — the
// mechanism DOM-XSS's document.referrer source (internal/scan/domxss.go,
// navigateWithReferrer) depends on. Debugging note for anyone touching
// this again: Chromium only honors an explicit Referer override for a
// cross-origin top-level navigation when the override's origin itself
// would be considered a plausible referrer (i.e. it does not simply
// accept an arbitrary string) — this test pins the exact, realistic shape
// (an http(s) URL) that is known to work, so a future regression in
// either Playwright or this package's own threading is caught here
// rather than only in a live DOM-XSS scan.
func TestIntegrationNavigateRefererReachesDocumentReferrerRealBrowser(t *testing.T) {
	var gotReferer atomic.Value
	gotReferer.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the tested document counts, not later favicon/subresource requests.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		gotReferer.Store(r.Header.Get("Referer"))
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body><div id="sink"></div>
<script>document.getElementById('sink').innerHTML = document.referrer;</script>
</body></html>`)
	}))
	defer srv.Close()

	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	ctx := context.Background()

	c, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	referer := "https://attacker.example/evil-page"
	if _, err := p.Navigate(ctx, srv.URL, browser.NavOptions{WaitUntil: browser.WaitLoad, Referer: referer}); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	if got := gotReferer.Load(); got != referer {
		t.Fatalf("server-observed Referer header = %q, want %q", got, referer)
	}
	html, err := p.Content(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, referer) {
		t.Fatalf("document.referrer did not reach the sink; rendered HTML: %.300s", html)
	}
}

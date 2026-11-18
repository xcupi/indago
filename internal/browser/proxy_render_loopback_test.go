package browser

// Real-Chromium, loopback-only checks for the per-scan operator proxy on
// browser RENDERING, plus the existing per-context proxy that browser
// verification and DOM XSS already use. Everything is 127.0.0.1: a recording
// forward proxy, an origin, and the browser. Nothing here reaches the network.
//
// They assert effects measured at the proxy and at the origin (counters and the
// recorded request line), never what the browser claims.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func findChromiumForProxyRender() string {
	if p := os.Getenv("INDAGO_CHROMIUM_PATH"); p != "" {
		return p
	}
	for _, cand := range []string{"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
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

func newProxyRenderManager(t *testing.T) *Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := findChromiumForProxyRender()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or install one)")
	}
	t.Logf("chromium=%s sandboxDisabled=%v", exe, os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1")
	m, err := NewManager(Config{
		Headless:          true,
		PoolSize:          1,
		ExecutablePath:    exe,
		NavigationTimeout: 15 * time.Second,
		DisableSandbox:    os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1",
	}, nil)
	if err != nil {
		t.Skipf("browser engine unavailable (sandboxDisabled=%v): %v", os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

type proxyRenderRequest struct {
	Method string
	URL    string
	Host   string
	Cookie string
}

// proxyRenderRecorder is a minimal forward proxy: absolute-form HTTP only,
// loopback only. It records the request line a browser actually sent, then
// forwards it, so "through the proxy" is measured at the proxy and "reached the
// target" is measured at the origin.
type proxyRenderRecorder struct {
	srv *httptest.Server
	tr  *http.Transport

	mu   sync.Mutex
	reqs []proxyRenderRequest
}

func newProxyRenderRecorder(t *testing.T) *proxyRenderRecorder {
	t.Helper()
	rp := &proxyRenderRecorder{tr: &http.Transport{Proxy: nil, DisableCompression: true}}
	t.Cleanup(rp.tr.CloseIdleConnections)
	rp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// Loopback fixtures are http:// only; a tunnel attempt is not part
			// of this test and must not be counted as a request.
			http.Error(w, "tunnel not supported by this fixture", http.StatusBadGateway)
			return
		}
		if !r.URL.IsAbs() {
			http.Error(w, "expected absolute-form at a forward proxy", http.StatusBadRequest)
			return
		}
		rp.mu.Lock()
		rp.reqs = append(rp.reqs, proxyRenderRequest{
			Method: r.Method, URL: r.URL.String(), Host: r.Host, Cookie: r.Header.Get("Cookie"),
		})
		rp.mu.Unlock()

		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Host = r.Host
		out.Header = r.Header.Clone()
		for _, h := range []string{"Proxy-Connection", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
			out.Header.Del(h)
		}
		out.Close = false
		resp, err := rp.tr.RoundTrip(out)
		if err != nil {
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(rp.srv.Close)
	return rp
}

func (rp *proxyRenderRecorder) url() string { return rp.srv.URL }

func (rp *proxyRenderRecorder) snapshot() []proxyRenderRequest {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return append([]proxyRenderRequest(nil), rp.reqs...)
}

func (rp *proxyRenderRecorder) count() int { return len(rp.snapshot()) }

func (rp *proxyRenderRecorder) pathsFor(host string) []string {
	var out []string
	for _, r := range rp.snapshot() {
		if r.Host != host {
			out = append(out, "!other-host:"+r.Host)
			continue
		}
		out = append(out, r.URL)
	}
	return out
}

// proxyRenderOrigin serves one HTML page that issues a same-origin fetch, and
// records the Cookie header it receives (the stored-session check).
type proxyRenderOrigin struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  int
	cooks []string
}

func newProxyRenderOrigin(t *testing.T) *proxyRenderOrigin {
	t.Helper()
	o := &proxyRenderOrigin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits++
		o.cooks = append(o.cooks, r.Header.Get("Cookie"))
		o.mu.Unlock()
		if r.URL.Path == "/xhr" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>proxy-render</title><body><p>page</p><script>fetch('/xhr')</script></body>`)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *proxyRenderOrigin) hitsCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits
}

func (o *proxyRenderOrigin) sawCookie(cookie string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, c := range o.cooks {
		if strings.Contains(c, cookie) {
			return true
		}
	}
	return false
}

func proxyRenderStorageState(t *testing.T, host, name, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	body := fmt.Sprintf(`{"cookies":[{"name":%q,"value":%q,"domain":%q,"path":"/","expires":-1,"httpOnly":false,"secure":false,"sameSite":"Lax"}],"origins":[]}`, name, value, host)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func proxyRenderAllowAll(string) bool { return true }

func proxyRenderOriginHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestRenderWithProxyPoolGoesThroughTheProxy is the discovery-shaped check:
// the decorator renders through the operator proxy, the target is reached via
// the proxy, and the scan's stored session cookie travels with it.
func TestRenderWithProxyPoolGoesThroughTheProxy(t *testing.T) {
	mgr := newProxyRenderManager(t)
	rp := newProxyRenderRecorder(t)
	origin := newProxyRenderOrigin(t)
	host := proxyRenderOriginHost(t, origin.srv.URL)
	state := proxyRenderStorageState(t, host, "sid", "abc123")

	b := WithProxyPool(mgr, []string{rp.url()})
	res, err := b.Render(context.Background(), origin.srv.URL+"/page", RenderOptions{
		AllowRequest:      proxyRenderAllowAll,
		SessionStatePath:  state,
		ObservationWindow: 750 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("render through proxy: %v", err)
	}
	if res.Status != 200 || !strings.Contains(res.HTML, "proxy-render") {
		t.Fatalf("render result status=%d html=%q", res.Status, res.HTML)
	}

	seen := rp.pathsFor(host)
	if !proxyRenderContains(seen, origin.srv.URL+"/page") {
		t.Fatalf("proxy did not receive the page request; recorded=%v", seen)
	}
	if !proxyRenderContains(seen, origin.srv.URL+"/xhr") {
		t.Fatalf("proxy did not receive the page's fetch; recorded=%v", seen)
	}
	for _, s := range seen {
		if strings.HasPrefix(s, "!other-host:") {
			t.Fatalf("a request left the origin host: %v", seen)
		}
	}
	if !origin.sawCookie("sid=abc123") {
		t.Fatalf("the stored session cookie did not reach the origin through the proxy")
	}
}

func proxyRenderContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestRenderWithoutProxyStaysDirect is the control: the same render path with
// no pool must not touch the proxy at all.
func TestRenderWithoutProxyStaysDirect(t *testing.T) {
	mgr := newProxyRenderManager(t)
	rp := newProxyRenderRecorder(t)
	origin := newProxyRenderOrigin(t)

	res, err := mgr.Render(context.Background(), origin.srv.URL+"/page", RenderOptions{
		AllowRequest:      proxyRenderAllowAll,
		ObservationWindow: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("direct render: %v", err)
	}
	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if n := rp.count(); n != 0 {
		t.Fatalf("the proxy recorded %d request(s) for a scan with no proxy pool", n)
	}
	if origin.hitsCount() == 0 {
		t.Fatalf("the origin was never reached")
	}
}

// TestContextProxyServerRoutesThroughProxy covers the mechanism browser
// verification and DOM XSS already use (ContextOptions.ProxyServer): it must
// also route loopback through the proxy (Playwright's per-context
// "<-loopback>" bypass rule), since the scan's targets are often loopback.
func TestContextProxyServerRoutesThroughProxy(t *testing.T) {
	mgr := newProxyRenderManager(t)
	rp := newProxyRenderRecorder(t)
	origin := newProxyRenderOrigin(t)
	host := proxyRenderOriginHost(t, origin.srv.URL)

	c, err := mgr.NewContext(context.Background(), ContextOptions{
		AllowRequest: proxyRenderAllowAll,
		ProxyServer:  rp.url(),
	})
	if err != nil {
		t.Fatalf("new proxied context: %v", err)
	}
	defer c.Close()
	page, err := c.NewPage(context.Background())
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	if _, err := page.Navigate(context.Background(), origin.srv.URL+"/via-context", NavOptions{WaitUntil: WaitLoad}); err != nil {
		t.Fatalf("navigate: %v", err)
	}
	seen := rp.pathsFor(host)
	if !proxyRenderContains(seen, origin.srv.URL+"/via-context") {
		t.Fatalf("ContextOptions.ProxyServer did not route through the proxy; recorded=%v", seen)
	}
}

// TestRenderAndRenderThroughProxyAgree is the drift guard for the copy of
// Render in proxy_render.go: the same page rendered with and without a proxy
// must produce the same status, HTML and observed request set.
func TestRenderAndRenderThroughProxyAgree(t *testing.T) {
	mgr := newProxyRenderManager(t)
	rp := newProxyRenderRecorder(t)
	origin := newProxyRenderOrigin(t)

	opts := RenderOptions{AllowRequest: proxyRenderAllowAll, ObservationWindow: 500 * time.Millisecond}
	direct, err := mgr.Render(context.Background(), origin.srv.URL+"/drift", opts)
	if err != nil {
		t.Fatalf("direct render: %v", err)
	}
	proxied, err := mgr.renderThroughProxy(context.Background(), origin.srv.URL+"/drift", opts, rp.url())
	if err != nil {
		t.Fatalf("proxied render: %v", err)
	}
	if direct.Status != proxied.Status {
		t.Fatalf("status differs: direct=%d proxied=%d", direct.Status, proxied.Status)
	}
	if direct.HTML != proxied.HTML {
		t.Fatalf("HTML differs between Render and renderThroughProxy; the two copies have drifted")
	}
	if got, want := proxyRenderURLSet(proxied), proxyRenderURLSet(direct); !proxyRenderSameSet(got, want) {
		t.Fatalf("observed network differs: direct=%v proxied=%v", want, got)
	}
}

func proxyRenderURLSet(res *RenderResult) []string {
	var urls []string
	for _, ev := range res.Network {
		urls = append(urls, ev.URL)
	}
	for _, b := range res.Blocked {
		urls = append(urls, "blocked:"+b)
	}
	sort.Strings(urls)
	return urls
}

func proxyRenderSameSet(a, b []string) bool {
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

package discovery_test

// Loopback-only check that a scan's operator proxy now reaches browser
// DISCOVERY: the network source renders the seed through the proxy, the proxy
// records the page and the page's own fetch, and the target is reached through
// it. The proxy and the origin are both 127.0.0.1; no external network.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func discoveryProxyChromium() string {
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

func newDiscoveryProxyManager(t *testing.T) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := discoveryProxyChromium()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or install one)")
	}
	m, err := browser.NewManager(browser.Config{
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

// discoveryRecordingProxy is a minimal absolute-form HTTP forward proxy that
// records what a browser actually asked for. Loopback fixtures only.
type discoveryRecordingProxy struct {
	srv *httptest.Server
	tr  *http.Transport

	mu   sync.Mutex
	urls []string
}

func newDiscoveryRecordingProxy(t *testing.T) *discoveryRecordingProxy {
	t.Helper()
	p := &discoveryRecordingProxy{tr: &http.Transport{Proxy: nil, DisableCompression: true}}
	t.Cleanup(p.tr.CloseIdleConnections)
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || !r.URL.IsAbs() {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.urls = append(p.urls, r.URL.String())
		p.mu.Unlock()
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Host = r.Host
		out.Header = r.Header.Clone()
		for _, h := range []string{"Proxy-Connection", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
			out.Header.Del(h)
		}
		resp, err := p.tr.RoundTrip(out)
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
	t.Cleanup(p.srv.Close)
	return p
}

func (p *discoveryRecordingProxy) URL() string { return p.srv.URL }

func (p *discoveryRecordingProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.urls...)
}

func TestNetworkSourceRendersThroughOperatorProxy(t *testing.T) {
	mgr := newDiscoveryProxyManager(t)
	rp := newDiscoveryRecordingProxy(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xhr" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>discovery-proxy</title><body><p>seed</p><script>fetch('/xhr')</script></body>`)
	}))
	defer origin.Close()

	proxied := browser.WithProxyPool(mgr, []string{rp.URL()})
	src := discovery.NewNetworkSource(proxied, discovery.DefaultConfig())
	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
	if err := src.Run(context.Background(), discovery.Input{Scope: scope, SeedURLs: []string{origin.URL + "/page"}}, &spySink{}); err != nil {
		t.Fatalf("network source run: %v", err)
	}

	seen := rp.seen()
	if !discoveryProxySeen(seen, origin.URL+"/page") {
		t.Fatalf("the proxy did not record the discovery seed render; recorded=%v", seen)
	}
	if !discoveryProxySeen(seen, origin.URL+"/xhr") {
		t.Fatalf("the proxy did not record the page's own fetch; recorded=%v", seen)
	}
	for _, u := range seen {
		if !strings.HasPrefix(u, origin.URL) {
			t.Fatalf("a discovery request left the operator proxy's target: %q", u)
		}
	}
}

func TestNetworkSourceWithoutProxyStaysDirect(t *testing.T) {
	mgr := newDiscoveryProxyManager(t)
	rp := newDiscoveryRecordingProxy(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><title>direct</title>ok`)
	}))
	defer origin.Close()

	src := discovery.NewNetworkSource(mgr, discovery.DefaultConfig())
	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
	if err := src.Run(context.Background(), discovery.Input{Scope: scope, SeedURLs: []string{origin.URL + "/page"}}, &spySink{}); err != nil {
		t.Fatalf("network source run: %v", err)
	}
	if seen := rp.seen(); len(seen) != 0 {
		t.Fatalf("a scan with no proxy pool sent %d request(s) through a proxy: %v", len(seen), seen)
	}
}

func discoveryProxySeen(seen []string, want string) bool {
	for _, u := range seen {
		if u == want {
			return true
		}
	}
	return false
}

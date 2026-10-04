// These tests drive a REAL Chromium via Playwright. They run by default and skip
// (quickly) when no Chromium can be found, so `go test ./...` never fails on a
// machine without one. Chromium is located via $INDAGO_CHROMIUM_PATH or the
// Playwright cache (~/.cache/ms-playwright/chromium-*); it is launched by
// explicit path, so the Playwright driver and the installed revision need not
// match. Install one with `playwright install chromium`.
package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

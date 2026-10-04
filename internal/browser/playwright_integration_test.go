//go:build browser_integration

// These tests drive a REAL Chromium via Playwright. They are excluded from the
// default build so `go test ./...` never requires a browser. Run them with:
//
//	go test -tags browser_integration ./internal/browser/
//
// They require Playwright + Chromium to be installed (`playwright install
// chromium`, or the playwright-go driver). If the engine cannot start, the tests
// skip rather than fail.
package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

func newManagerOrSkip(t *testing.T, cfg browser.Config) *browser.Manager {
	t.Helper()
	m, err := browser.NewManager(cfg, nil)
	if err != nil {
		t.Skipf("browser engine unavailable (install Playwright/Chromium): %v", err)
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

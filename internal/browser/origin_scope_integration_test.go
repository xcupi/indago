package browser_test

// A real browser is the surface where "the host is in scope on every port" used
// to be most dangerous: a page can fetch() a sibling service on another port of
// the same host without the crawler ever seeing a URL. The scope gate is built
// from domain.Scope.Permits, so an origin list applies to navigations,
// subresources and redirects alike.
//
// What this test measures is REQUESTS at the second origin (its HTTP handler's
// counter). It does not observe TCP connections: Chromium can still preconnect
// to a navigation target before the gate refuses the request, which is the
// documented "Known gap: connections" in docs/browser-scope-boundary.md. A zero
// here proves no request was sent, not that no packet left the machine.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// newOriginGateManager lowers isolation only when the operator explicitly asks
// for it (a restricted container without user namespaces), exactly like the
// method-gate fixture. The default keeps Chromium's sandbox ON.
func newOriginGateManager(t *testing.T) *browser.Manager {
	t.Helper()
	cfg := browser.DefaultConfig()
	if os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1" {
		cfg.DisableSandbox = true
	}
	return newManagerOrSkip(t, cfg)
}

func loopbackOrigin(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return domain.ScopeOrigin{Scheme: u.Scheme, Host: u.Hostname(), Port: port}.String()
}

func waitForDone(t *testing.T, ctx context.Context, p *browser.Page) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := p.Evaluate(ctx, `document.title`)
		if err == nil && raw == "done" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the page never signalled that its fetch settled")
}

// A redirect is the classic way to leave the origin the scope authorized: the
// entry page is in scope and its 302 points at another port of the same host.
// The CDP response gate must refuse the hop before Chromium follows it.
func TestIntegrationScopeGateBlocksRedirectToAnotherPort(t *testing.T) {
	var siblingHits atomic.Int64
	sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siblingHits.Add(1)
		_, _ = io.WriteString(w, "sibling")
	}))
	defer sibling.Close()

	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sibling.URL+"/landing", http.StatusFound)
	}))
	defer entry.Close()

	sc := domain.Scope{
		IncludeHosts:   []string{"127.0.0.1"},
		AllowedOrigins: []string{loopbackOrigin(t, entry.URL)},
	}
	m := newOriginGateManager(t)
	defer m.Close()
	ctx := context.Background()

	// Control: without the gate the redirect reaches the sibling, so a zero
	// below is meaningful.
	ungated, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	up, err := ungated.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.Navigate(ctx, entry.URL+"/jump", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 15 * time.Second}); err != nil {
		t.Fatalf("control navigation: %v", err)
	}
	if siblingHits.Load() == 0 {
		t.Fatal("the control redirect never reached the sibling; the fixture proves nothing")
	}
	ungated.Close()

	// Gated: the entry page is declared, the redirect target is not.
	siblingHits.Store(0)
	gated, err := m.NewContext(ctx, browser.ContextOptions{
		AllowRequest: func(raw string) bool { return sc.Permits(raw).Allowed },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gated.Close()
	gp, err := gated.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The navigation itself may surface as a browser error (the request was
	// aborted); the assertion is the absence of traffic at the sibling.
	_, _ = gp.Navigate(ctx, entry.URL+"/jump", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 10 * time.Second})
	time.Sleep(300 * time.Millisecond)
	if got := siblingHits.Load(); got != 0 {
		t.Fatalf("the redirect reached the undeclared origin %d time(s)", got)
	}
}

func TestIntegrationScopeGateBlocksAnotherPortOfAnInScopeHost(t *testing.T) {
	var siblingHits atomic.Int64
	sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siblingHits.Add(1)
		_, _ = io.WriteString(w, "sibling")
	}))
	defer sibling.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The fetch settles either way (resolved, or rejected after the gate
		// aborts it); the title records that the page had its chance.
		fmt.Fprintf(w, `<!doctype html><body>origin gate
<script>
fetch(%q, {mode: "no-cors"})
  .then(() => { document.title = "done"; })
  .catch(() => { document.title = "done"; });
</script></body>`, sibling.URL+"/collect")
	}))
	defer page.Close()

	sc := domain.Scope{
		IncludeHosts:   []string{"127.0.0.1"},
		AllowedOrigins: []string{loopbackOrigin(t, page.URL)},
	}
	if d := sc.Permits(sibling.URL + "/"); d.Allowed {
		t.Fatalf("setup: the sibling port is already authorized: %+v", d)
	}

	m := newOriginGateManager(t)
	defer m.Close()
	ctx := context.Background()

	// Control: without the scope gate the same page reaches the sibling. This
	// makes a zero in the gated run meaningful.
	ungated, err := m.NewContext(ctx, browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := ungated.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Navigate(ctx, page.URL+"/", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 15 * time.Second}); err != nil {
		t.Fatalf("control navigation: %v", err)
	}
	waitForDone(t, ctx, p)
	if siblingHits.Load() == 0 {
		t.Fatal("the control page never reached the sibling; the fixture proves nothing")
	}
	ungated.Close()

	// Gated: the page loads (its own origin is declared) but the fetch to the
	// undeclared port never reaches the sibling.
	siblingHits.Store(0)
	gated, err := m.NewContext(ctx, browser.ContextOptions{
		AllowRequest: func(raw string) bool { return sc.Permits(raw).Allowed },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gated.Close()
	gp, err := gated.NewPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gp.Navigate(ctx, page.URL+"/", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 15 * time.Second}); err != nil {
		t.Fatalf("gated page load (its own origin is declared): %v", err)
	}
	waitForDone(t, ctx, gp)
	time.Sleep(300 * time.Millisecond) // let any escaped request land
	if got := siblingHits.Load(); got != 0 {
		t.Fatalf("the undeclared origin received %d request(s) through the browser", got)
	}

	// A direct navigation to the undeclared origin is refused as well.
	if _, err := gp.Navigate(ctx, sibling.URL+"/collect", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 5 * time.Second}); err == nil {
		t.Fatal("navigation to the undeclared origin unexpectedly succeeded")
	}
	if got := siblingHits.Load(); got != 0 {
		t.Fatalf("the undeclared origin received %d request(s) after the direct navigation", got)
	}
}

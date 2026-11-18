package scopeproxy

// Real-Chromium tests for the primitive. They start a real browser with the
// switches ChromiumArgs returns, against loopback-only fixtures, and assert the
// property that matters: an out-of-scope destination sees NO TCP connection at
// all — not merely no request. The control tests exist to show each mechanism
// is load-bearing; without them a zero would prove nothing.
//
// They skip (quickly) when no Chromium or driver is installed, like the rest of
// the repository's browser tests. Chromium's process sandbox stays ON unless the
// operator sets INDAGO_TEST_BROWSER_NO_SANDBOX=1 for a restricted host; the
// skip/failure messages report which mode was used.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	pw "github.com/mxschmitt/playwright-go"
)

func findChromiumForProxy() string {
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

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) observe(ev Event) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

func (l *eventLog) snapshot() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

// waitFor polls until pred matches an event or the deadline passes.
func (l *eventLog) waitFor(pred func(Event) bool, d time.Duration) (Event, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, ev := range l.snapshot() {
			if pred(ev) {
				return ev, true
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return Event{}, false
}

// launchChromium starts a real headless Chromium with exactly args plus the
// Playwright-required plumbing, and never disables the process sandbox unless
// the operator opted out for the test host.
func launchChromium(t *testing.T, args []string) pw.Browser {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := findChromiumForProxy()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	p, err := pw.Run()
	if err != nil {
		t.Skipf("Playwright driver unavailable (install it: go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 install chromium): %v", err)
	}
	noSandbox := os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1"
	b, err := p.Chromium.Launch(pw.BrowserTypeLaunchOptions{
		Headless:        pw.Bool(true),
		ChromiumSandbox: pw.Bool(!noSandbox),
		ExecutablePath:  pw.String(exe),
		Args:            args,
	})
	if err != nil {
		_ = p.Stop()
		t.Skipf("Chromium launch failed (sandboxDisabled=%v): %v; set INDAGO_TEST_BROWSER_NO_SANDBOX=1 on a host that cannot sandbox, and say so when reporting the result", noSandbox, err)
	}
	t.Cleanup(func() {
		_ = b.Close()
		_ = p.Stop()
	})
	return b
}

func openPage(t *testing.T, b pw.Browser, url string) pw.Page {
	t.Helper()
	ctx, err := b.NewContext()
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	if _, err := page.Goto(url, pw.PageGotoOptions{
		WaitUntil: pw.WaitUntilStateLoad,
		Timeout:   pw.Float(float64((15 * time.Second).Milliseconds())),
	}); err != nil {
		t.Fatalf("goto %s: %v", url, err)
	}
	return page
}

// TestChromiumScopeProxyRefusesOutOfScopeLoopback is the hardening claim: a page
// on an in-scope loopback origin embeds an out-of-scope loopback destination,
// and that destination sees zero TCP connections — closing the preconnect gap
// recorded in docs/browser-scope-boundary.md, where an ungated browser opened a
// socket before the request gate could abort it.
func TestChromiumScopeProxyRefusesOutOfScopeLoopback(t *testing.T) {
	out := newConnCounter(t)
	outHost, outPort := out.hostPort(t)
	body := fmt.Sprintf(`<!doctype html><title>in-scope</title>
<iframe src="http://%s/leak-frame"></iframe>
<img src="http://%s/leak.png">`, out.addr(), out.addr())
	in := newOriginWithBody(t, body)
	log := &eventLog{}
	s := startProxy(t, Config{Policy: allow(in.hostPort(t)), Observer: log.observe})

	args, err := ChromiumArgs(s.ProxyURL())
	if err != nil {
		t.Fatalf("ChromiumArgs: %v", err)
	}
	b := launchChromium(t, args)
	page := openPage(t, b, in.srv.URL+"/")
	if title, _ := page.Title(); title != "in-scope" {
		t.Fatalf("page title = %q, want in-scope: the in-scope page did not load through the proxy", title)
	}

	ev, ok := log.waitFor(func(ev Event) bool {
		return !ev.Allowed && ev.Host == outHost && ev.Port == outPort
	}, 10*time.Second)
	if !ok {
		t.Fatalf("the proxy never saw the out-of-scope attempt (stats=%+v, direct connections=%d); the test cannot discriminate", s.Stats(), out.count.Load())
	}
	if ev.Reason != ReasonPolicyDenied {
		t.Fatalf("denial reason = %q, want %q (event=%+v)", ev.Reason, ReasonPolicyDenied, ev)
	}
	// Settle: a bypassed (direct) connection would have been attempted at the
	// same moment the proxied attempt was refused.
	time.Sleep(500 * time.Millisecond)
	if n := out.count.Load(); n != 0 {
		t.Fatalf("out-of-scope listener saw %d TCP connections, want 0: Chromium opened a socket the proxy never authorized", n)
	}
	if st := s.Stats(); st.Forwarded < 1 {
		t.Fatalf("stats = %+v: the in-scope page should have been forwarded at least once", st)
	}
}

// TestChromiumLoopbackBypassIsLoadBearing is the control for
// --proxy-bypass-list=<-loopback>: with the same proxy but the default implicit
// loopback bypass left in place, Chromium reaches the out-of-scope loopback
// destination DIRECTLY and the proxy sees nothing. If this ever stops failing
// that way, the flag (and the claim above) must be re-established.
func TestChromiumLoopbackBypassIsLoadBearing(t *testing.T) {
	out := newConnCounter(t)
	_, outPort := out.hostPort(t)
	body := fmt.Sprintf(`<!doctype html><title>in-scope</title><iframe src="http://%s/leak-frame"></iframe>`, out.addr())
	in := newOriginWithBody(t, body)
	log := &eventLog{}
	s := startProxy(t, Config{Policy: allow(in.hostPort(t)), Observer: log.observe})

	// Deliberately missing ChromiumArgs' --proxy-bypass-list=<-loopback>.
	args := []string{
		"--proxy-server=" + s.ProxyURL(),
		"--host-resolver-rules=" + chromiumResolverRules,
		"--dns-prefetch-disable",
	}
	b := launchChromium(t, args)
	page := openPage(t, b, in.srv.URL+"/")
	if title, _ := page.Title(); title != "in-scope" {
		t.Fatalf("page title = %q, want in-scope", title)
	}

	deadline := time.Now().Add(10 * time.Second)
	for out.count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if n := out.count.Load(); n == 0 {
		t.Fatalf("control did not reach the out-of-scope loopback destination, so a zero in the main test would prove nothing; stats=%+v", s.Stats())
	}
	// Chromium's own background traffic (accounts.google.com and friends) is
	// still proxied and denied; what must be absent is any loopback event,
	// because loopback was reached directly.
	for _, ev := range log.snapshot() {
		if ev.Port == in.port(t) || ev.Port == outPort {
			t.Fatalf("control expected Chromium to bypass the proxy for loopback, but the proxy saw %+v", ev)
		}
	}
}

// TestChromiumProxyCarriesNamesWithoutBrowserDNS proves the DNS half: Chromium
// resolves nothing itself (every name lookup inside the browser fails), yet a
// page whose name only the PROXY can resolve still loads, and the out-of-scope
// name is never looked up anywhere.
func TestChromiumProxyCarriesNamesWithoutBrowserDNS(t *testing.T) {
	out := newConnCounter(t)
	outHost, outPort := out.hostPort(t)
	body := fmt.Sprintf(`<!doctype html><title>in-scope-name</title>
<iframe src="http://out-of-scope.test:%d/leak-frame"></iframe>`, outPort)
	in := newOriginWithBody(t, body)
	res := newRecordingResolver()
	// Only the in-scope name has an answer; the out-of-scope name deliberately
	// has none, so a lookup for it would both fail and be visible.
	res.answers["in-scope.test"] = []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}
	log := &eventLog{}
	s := startProxy(t, Config{
		Policy:   allow(fmt.Sprintf("in-scope.test:%d", in.port(t))),
		Resolver: res,
		Observer: log.observe,
	})

	args, err := ChromiumArgs(s.ProxyURL())
	if err != nil {
		t.Fatalf("ChromiumArgs: %v", err)
	}
	b := launchChromium(t, args)
	page := openPage(t, b, fmt.Sprintf("http://in-scope.test:%d/", in.port(t)))
	if title, _ := page.Title(); title != "in-scope-name" {
		t.Fatalf("page title = %q, want in-scope-name: the proxy did not carry the unresolvable name", title)
	}

	ev, ok := log.waitFor(func(ev Event) bool {
		return !ev.Allowed && ev.Host == "out-of-scope.test" && ev.Port == outPort
	}, 10*time.Second)
	if !ok {
		t.Fatalf("the proxy never saw the out-of-scope name (stats=%+v); the test cannot discriminate", s.Stats())
	}
	if ev.Reason != ReasonPolicyDenied {
		t.Fatalf("denial reason = %q, want %q", ev.Reason, ReasonPolicyDenied)
	}
	for _, name := range res.lookedUp() {
		if name != "in-scope.test" {
			t.Fatalf("resolver was asked for %q; only the policy-approved name may ever be looked up", name)
		}
	}
	if names := res.lookedUp(); len(names) == 0 {
		t.Fatalf("the in-scope name was never resolved; the page could not have loaded through the proxy")
	}
	time.Sleep(500 * time.Millisecond)
	if n := out.count.Load(); n != 0 {
		t.Fatalf("out-of-scope listener saw %d TCP connections, want 0", n)
	}
	if outHost != "127.0.0.1" || !strings.HasPrefix(in.srv.URL, "http://127.0.0.1:") {
		t.Fatalf("fixtures must be loopback-only (out=%s in=%s)", outHost, in.srv.URL)
	}
}

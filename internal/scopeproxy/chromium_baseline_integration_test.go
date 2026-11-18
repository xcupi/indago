package scopeproxy

// Baseline control for the hardening claim: with NO proxy at all, the same
// page reaches the out-of-scope loopback destination directly. This is the
// behaviour docs/browser-scope-boundary.md records as the "Known gap:
// connections" — a TCP connect (and, for https, a ClientHello) reaches the host
// even though the request gate aborts the request. Measuring the baseline here
// is what makes the proxied zero mean something.

import (
	"fmt"
	"testing"
	"time"
)

func TestChromiumWithoutProxyReachesOutOfScopeLoopback(t *testing.T) {
	out := newConnCounter(t)
	body := fmt.Sprintf(`<!doctype html><title>in-scope</title><iframe src="http://%s/leak-frame"></iframe>`, out.addr())
	in := newOriginWithBody(t, body)

	// No --proxy-server, no resolver rules: an ordinary headless Chromium.
	b := launchChromium(t, nil)
	page := openPage(t, b, in.srv.URL+"/")
	if title, _ := page.Title(); title != "in-scope" {
		t.Fatalf("page title = %q, want in-scope", title)
	}
	deadline := time.Now().Add(10 * time.Second)
	for out.count.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if n := out.count.Load(); n == 0 {
		t.Fatalf("baseline control never reached the out-of-scope loopback destination, so the proxied zero would be meaningless")
	}
	t.Logf("baseline (no proxy): out-of-scope listener saw %d direct TCP connection(s)", out.count.Load())
}

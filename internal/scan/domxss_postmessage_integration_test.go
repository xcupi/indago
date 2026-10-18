//go:build browser_integration

package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/verification"
)

const postMessageMetaPrefix = "__POSTMESSAGE_META__"

func TestDOMXSSPostMessageFromOpaqueCrossOriginSenderReachesAndConfirms(t *testing.T) {
	manager, ctx, targetURL, scoped, denied := newPostMessageBrowserLab(t)
	defer manager.Close()
	defer ctx.Close()

	marker := "indagopostmsgpositive"
	exec := &domXSSExecutor{}
	canary := detection.DOMXSSCanary(marker)
	console, pageErrors, targetHTML, _, err := exec.navigateWithPostMessage(context.Background(), ctx, targetURL("/vulnerable"), marker, canary)
	if err != nil {
		t.Fatalf("deliver canary from opaque sandboxed sender: %v", err)
	}
	assertOpaqueSenderMessage(t, console, targetHTML)
	if sinks := parseDOMXSSReachability(console, marker); len(sinks) == 0 {
		t.Fatalf("cross-origin sender canary did not reach an HTML sink; console=%v pageErrors=%v", console, pageErrors)
	}

	candidate, ok := detection.DOMXSSPayloadFor(detection.DOMSourcePostMessage, detection.DOMSinkInnerHTML, marker)
	if !ok {
		t.Fatal("could not create DOM-XSS verification candidate")
	}
	console, pageErrors, targetHTML, _, err = exec.navigateWithPostMessage(context.Background(), ctx, targetURL("/vulnerable"), marker, candidate.Value)
	if err != nil {
		t.Fatalf("deliver verification payload from opaque sandboxed sender: %v", err)
	}
	assertOpaqueSenderMessage(t, console, targetHTML)
	consoleErrors := postMessageConsoleErrors(console)
	if _, _, confirmed := verification.MatchExecutionSignal(marker, pageErrors, consoleErrors); !confirmed {
		t.Fatalf("real browser execution signal was not captured from the target page; pageErrors=%v console=%v", pageErrors, console)
	}
	if got := scoped.Load(); got < 2 {
		t.Fatalf("scope gate checked only %d network requests, want both target navigations", got)
	}
	if got := denied.Load(); got != 0 {
		t.Fatalf("scope gate denied %d requests during an in-scope probe", got)
	}
}

func TestDOMXSSPostMessageRejectsOpaqueCrossOriginSender(t *testing.T) {
	manager, ctx, targetURL, scoped, denied := newPostMessageBrowserLab(t)
	defer manager.Close()
	defer ctx.Close()

	marker := "indagopostmsgnegative"
	exec := &domXSSExecutor{}
	canary := detection.DOMXSSCanary(marker)
	console, pageErrors, targetHTML, _, err := exec.navigateWithPostMessage(context.Background(), ctx, targetURL("/validated"), marker, canary)
	if err != nil {
		t.Fatalf("deliver canary from opaque sandboxed sender: %v", err)
	}
	assertOpaqueSenderMessage(t, console, targetHTML)
	if sinks := parseDOMXSSReachability(console, marker); len(sinks) != 0 {
		t.Fatalf("origin/source-validated handler unexpectedly reached an HTML sink: %v; console=%v", sinks, console)
	}

	candidate, ok := detection.DOMXSSPayloadFor(detection.DOMSourcePostMessage, detection.DOMSinkInnerHTML, marker)
	if !ok {
		t.Fatal("could not create DOM-XSS verification candidate")
	}
	console, pageErrors, targetHTML, _, err = exec.navigateWithPostMessage(context.Background(), ctx, targetURL("/validated"), marker, candidate.Value)
	if err != nil {
		t.Fatalf("deliver verification payload from opaque sandboxed sender: %v", err)
	}
	assertOpaqueSenderMessage(t, console, targetHTML)
	if signal, text, confirmed := verification.MatchExecutionSignal(marker, pageErrors, postMessageConsoleErrors(console)); confirmed {
		t.Fatalf("sender-validated handler produced a Confirmed-capable browser signal %s: %q", signal, text)
	}
	if got := scoped.Load(); got < 2 {
		t.Fatalf("scope gate checked only %d network requests, want both target navigations", got)
	}
	if got := denied.Load(); got != 0 {
		t.Fatalf("scope gate denied %d requests during an in-scope probe", got)
	}
}

func TestSelfPostFalsePositiveControl(t *testing.T) {
	manager, ctx, targetURL, scoped, denied := newPostMessageBrowserLab(t)
	defer manager.Close()
	defer ctx.Close()

	marker := "indagopostmsgselfcontrol"
	page, err := ctx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	if err := page.AddInitScript(context.Background(), domXSSHarnessScript(marker)); err != nil {
		t.Fatalf("install sink harness: %v", err)
	}
	if _, err := page.Navigate(context.Background(), targetURL("/validated"), browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate to validation control: %v", err)
	}

	canary := detection.DOMXSSCanary(marker)
	if _, err := page.Evaluate(context.Background(), selfPostMessageControlScript(canary)); err != nil {
		t.Fatalf("self-post canary control: %v", err)
	}
	console := page.ConsoleMessages()
	selfSenderObserved := false
	for _, message := range console {
		if strings.HasPrefix(message.Text, postMessageMetaPrefix) && strings.Contains(message.Text, `"sourceIsWindow":true`) && strings.Contains(message.Text, `"origin":"http://`) {
			selfSenderObserved = true
		}
	}
	if !selfSenderObserved {
		t.Fatalf("self-post control did not demonstrate target-origin/self-window sender: %v", console)
	}
	if sinks := parseDOMXSSReachability(console, marker); len(sinks) == 0 {
		t.Fatalf("self-post control should reach the sink, exposing the old false-positive path: %v", console)
	}

	candidate, ok := detection.DOMXSSPayloadFor(detection.DOMSourcePostMessage, detection.DOMSinkInnerHTML, marker)
	if !ok {
		t.Fatal("could not create DOM-XSS verification candidate")
	}
	if _, err := page.Evaluate(context.Background(), selfPostMessageControlScript(candidate.Value)); err != nil {
		t.Fatalf("self-post payload control: %v", err)
	}
	if _, _, confirmed := verification.MatchExecutionSignal(marker, page.PageErrors(), postMessageConsoleErrors(page.ConsoleMessages())); !confirmed {
		t.Fatal("same-origin/self post should produce the old Confirmed-capable false positive")
	}
	if scoped.Load() < 1 || denied.Load() != 0 {
		t.Fatalf("unexpected request scope results: allowed=%d denied=%d", scoped.Load(), denied.Load())
	}
}

func selfPostMessageControlScript(value string) string {
	return "(() => new Promise((resolve) => { window.postMessage(" + goQuoteJS(value) + ", '*'); setTimeout(resolve, 300); }))();"
}

func newPostMessageBrowserLab(t *testing.T) (*browser.Manager, *browser.Context, func(string) string, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	exe := os.Getenv("INDAGO_CHROMIUM_PATH")
	if exe == "" {
		exe = "/usr/bin/google-chrome"
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("real Chromium required for browser_integration tests (%s): %v", exe, err)
	}

	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		validated := r.URL.Path == "/validated"
		if r.URL.Path != "/vulnerable" && !validated {
			http.NotFound(w, r)
			return
		}
		if validated {
			fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>
window.addEventListener('message', function (e) {
  console.log("__POSTMESSAGE_META__" + JSON.stringify({origin:e.origin, sourceIsWindow:e.source === window}));
  if (e.origin !== location.origin || e.source !== window) return;
  document.getElementById('sink').innerHTML = e.data;
});
</script>`)
			return
		}
		fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>
window.addEventListener('message', function (e) {
  console.log("__POSTMESSAGE_META__" + JSON.stringify({origin:e.origin, sourceIsWindow:e.source === window}));
  document.getElementById('sink').innerHTML = e.data;
});
</script>`)
	}))
	t.Cleanup(lab.Close)

	parsedLab, err := url.Parse(lab.URL)
	if err != nil {
		t.Fatalf("parse lab URL: %v", err)
	}
	var scoped atomic.Int64
	var denied atomic.Int64
	allow := func(raw string) bool {
		u, parseErr := url.Parse(raw)
		allowed := parseErr == nil && u.Scheme == parsedLab.Scheme && u.Host == parsedLab.Host
		if !allowed {
			denied.Add(1)
		} else {
			scoped.Add(1)
		}
		return allowed
	}

	manager, err := browser.NewManager(browser.Config{
		Headless:          true,
		ExecutablePath:    exe,
		PoolSize:          1,
		NavigationTimeout: 15 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("start real Chromium: %v", err)
	}
	ctx, err := manager.NewContext(context.Background(), browser.ContextOptions{AllowRequest: allow})
	if err != nil {
		manager.Close()
		t.Fatalf("create scope-enforced browser context: %v", err)
	}
	return manager, ctx, func(path string) string { return lab.URL + path }, &scoped, &denied
}

func assertOpaqueSenderMessage(t *testing.T, console []browser.ConsoleMessage, targetHTML string) {
	t.Helper()
	for _, message := range console {
		if !strings.HasPrefix(message.Text, postMessageMetaPrefix) {
			continue
		}
		want := postMessageMetaPrefix + `{"origin":"null","sourceIsWindow":false}`
		if message.Text != want {
			t.Fatalf("message sender semantics = %q, want %q", message.Text, want)
		}
		return
	}
	t.Fatalf("opaque-sender event metadata not observed; console=%v targetHTML=%q", console, targetHTML)
}

func postMessageConsoleErrors(console []browser.ConsoleMessage) []string {
	var errors []string
	for _, message := range console {
		if message.Type == "error" {
			errors = append(errors, message.Text)
		}
	}
	return errors
}

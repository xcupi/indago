// These tests drive a REAL Chromium via Playwright, exercising BrowserVerifier
// exactly as the scan executor does. Like
// internal/browser/playwright_integration_test.go, they run by default and skip
// (quickly) when no Chromium can be found, so `go test ./...` never fails on a
// machine without one.
package verification_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// queryURL builds base + "?q=" + value with value properly percent-encoded,
// exactly as the real pipeline's buildRequest (internal/scan) does via
// url.Values.Encode() — never by raw string concatenation. This matters: e.g.
// an unescaped ';' in a query value is dropped by Go's own query parser.
func queryURL(base, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	q.Set("q", value)
	u.RawQuery = q.Encode()
	return u.String()
}

// --- Chromium discovery / skip helper (mirrors internal/browser's) ---

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

func newManagerOrSkip(t *testing.T) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := findChromium()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	m, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: exe}, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	return m
}

// marker is a deterministic, unique-enough token for one test case.
func marker(t *testing.T) string {
	return "ind" + detection.NewProbe(domain.ID(t.Name()), domain.ID("ip")).Token[3:]
}

func openScope() domain.Scope { return domain.Scope{IncludeHosts: []string{"127.0.0.1"}} }

// --- reflected but non-executable ---

func TestIntegrationVerifyReflectionOnlyIsRejected(t *testing.T) {
	m := marker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The marker lands in plain element text: markup only, nothing a browser
		// ever evaluates as code.
		fmt.Fprintf(w, `<!doctype html><html><body><p>%s</p></body></html>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<" + m + "x>"},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/", m), Scope: openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (reflected, not executed)", res.Verdict)
	}
	if res.Report == nil || !res.Report.MarkerInDOM || res.Report.Signal != verification.SignalNone {
		t.Fatalf("report = %+v", res.Report)
	}
}

// --- executable reflected candidate (HTML text context) ---

func TestIntegrationVerifyExecutableCandidateIsConfirmed(t *testing.T) {
	m := marker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body>%s</body></html>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	// The exact built-in HTML-text candidate shape: an onload handler whose body
	// is the bare marker. Loading it fires onload, which evaluates the marker as
	// code — an undeclared identifier, so the engine throws ReferenceError. No
	// alert/cookie/network call is ever part of this: the signal is the browser's
	// own exception report naming the marker, nothing we execute ourselves.
	value := "<svg onload=" + m + ">"
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/", value), Scope: openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; report=%+v", res.Verdict, res.Report)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
	if len(res.Evidence.Screenshot) == 0 {
		t.Fatal("expected screenshot bytes to be captured")
	}
	if res.Evidence.DOMHTML == "" {
		t.Fatal("expected rendered DOM to be captured")
	}
}

// --- HTML attribute context ---

func TestIntegrationVerifyHTMLAttributeContext(t *testing.T) {
	m := marker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body><input value="%s"></body></html>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	// The built-in attribute-breakout: close the attribute/tag, inject an <svg
	// onload> element referencing the marker.
	value := `"><svg onload=` + m + ">"
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Value: value},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/", value), Scope: openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed", res.Verdict)
	}
}

// --- JavaScript context ---

func TestIntegrationVerifyJavaScriptContext(t *testing.T) {
	m := marker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body><script>var a = "%s";</script></body></html>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	// The built-in JS-string breakout: close the string, reference the marker as
	// its own statement, comment out the rest of the line.
	value := `";` + m + "//"
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatJS, Value: value},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/", value), Scope: openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed", res.Verdict)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
}

// --- URL context: reflected, but a javascript: href never runs on page load ---

func TestIntegrationVerifyURLContextNotExecutedWithoutActivation(t *testing.T) {
	m := marker(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body><a href="%s">link</a></body></html>`, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	value := "javascript:" + m
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatURL, Value: value},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/", value), Scope: openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Merely reflecting a javascript: URL into an href must NOT be confirmed:
	// nothing activates (clicks) the link on passive page load.
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (reflected but not activated)", res.Verdict)
	}
	if !res.Report.MarkerInDOM {
		t.Fatal("the marker should still be observed in the DOM (reflected)")
	}
}

// --- authenticated page (persistent session via storage state) ---

func TestIntegrationVerifyUsesAuthenticatedSession(t *testing.T) {
	var sawCookie atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil && c.Value == "authed" {
			sawCookie.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body>ok</body></html>`)
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()

	// Save a session (cookie) to disk via a throwaway context, exactly as the
	// scan's auth flow would via domain.Session.StatePath.
	statePath := filepath.Join(t.TempDir(), "state.json")
	seedCtx, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedCtx.SetCookies(context.Background(), []browser.Cookie{{Name: "session", Value: "authed", URL: srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if err := seedCtx.SaveStorageState(context.Background(), statePath); err != nil {
		t.Fatal(err)
	}
	seedCtx.Close()

	m := marker(t)
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})
	_, err = v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: m},
		Marker:    m, Method: "GET", URL: srv.URL + "/", Scope: openScope(),
		SessionStatePath: statePath,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !sawCookie.Load() {
		t.Fatal("the authenticated session's cookie never reached the server")
	}
}

// --- out-of-scope navigation/request blocking ---

// domain.Scope matches by host, not port, so (as the rest of this codebase's
// scope tests already do — see scan.TestScopeEnforcedDuringDiscovery) in-scope
// vs out-of-scope is distinguished by PATH PREFIX on one httptest server, not by
// two servers on different ports of the same host.
func TestIntegrationVerifyBlocksOutOfScopeRequests(t *testing.T) {
	var outsideHits atomic.Int64
	var insideHits atomic.Int64
	m := marker(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outside/beacon" {
			outsideHits.Add(1)
			return
		}
		insideHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><html><body>%s
<script>fetch(%q).catch(()=>{});</script>
</body></html>`, r.URL.Query().Get("q"), srv.URL+"/outside/beacon")
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	value := "<svg onload=" + m + ">" // the same built-in HTML-text breakout used above
	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value},
		Marker:    m, Method: "GET", URL: queryURL(srv.URL+"/app/", value),
		Scope: scope,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("the in-scope navigation itself should still verify normally, got %s", res.Verdict)
	}
	if insideHits.Load() == 0 {
		t.Fatal("the in-scope navigation should have reached the server")
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("the browser sent %d request(s) to the out-of-scope path", outsideHits.Load())
	}
}

// A navigation URL that is itself out of scope must never be attempted.
func TestIntegrationVerifyRefusesOutOfScopeNavigation(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	m := marker(t)
	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}
	_, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: m},
		Marker:    m, Method: "GET", URL: srv.URL + "/outside/", Scope: scope,
	})
	if err == nil {
		t.Fatal("expected an error: the navigation target is out of scope")
	}
	if hits.Load() != 0 {
		t.Fatal("an out-of-scope URL must never be navigated to")
	}
}

// --- timeout ---

func TestIntegrationVerifyTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{NavigationTimeout: 200 * time.Millisecond})

	m := marker(t)
	_, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: m},
		Marker:    m, Method: "GET", URL: srv.URL + "/", Scope: openScope(),
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

// --- cancellation ---

func TestIntegrationVerifyCancellation(t *testing.T) {
	started := make(chan struct{})
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-block
	}))
	defer srv.Close()
	defer close(block)

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	m := marker(t)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := v.Verify(ctx, verification.Input{
			Candidate: detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: m},
			Marker:    m, Method: "GET", URL: srv.URL + "/", Scope: openScope(),
		})
		errc <- err
	}()
	<-started
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt verification")
	}
}

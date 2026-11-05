package httpengine_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/httpengine"
)

func mustClient(t *testing.T, cfg httpengine.Config) *httpengine.Client {
	t.Helper()
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func TestGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL))
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp.Status != 200 || string(resp.Body) != "hello" {
		t.Fatalf("status=%d body=%q", resp.Status, resp.Body)
	}
	if resp.Headers.Get("X-Custom") != "yes" {
		t.Fatalf("missing response header: %v", resp.Headers)
	}
	if resp.Proto == "" || resp.StatusText == "" {
		t.Fatalf("missing proto/status text: %q %q", resp.Proto, resp.StatusText)
	}
	if resp.Duration <= 0 {
		t.Fatal("duration not recorded")
	}
}

func TestPOSTForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		_ = r.ParseForm()
		_, _ = io.WriteString(w, r.PostFormValue("q"))
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	resp, err := c.Do(context.Background(), httpengine.POSTForm(srv.URL, url.Values{"q": {"inject"}}))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "inject" {
		t.Fatalf("form value not received, body=%q", resp.Body)
	}
}

func TestPOSTJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	req, err := httpengine.POSTJSON(srv.URL, map[string]any{"name": "value"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Body), `"name":"value"`) {
		t.Fatalf("json body not echoed: %q", resp.Body)
	}
}

func TestHeadersAndUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Test", r.Header.Get("X-Test"))
		w.Header().Set("X-Echo-UA", r.UserAgent())
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())

	// Default User-Agent is applied.
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL).WithHeader("X-Test", "abc"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Headers.Get("X-Echo-Test") != "abc" {
		t.Fatalf("custom header not sent: %q", resp.Headers.Get("X-Echo-Test"))
	}
	if resp.Headers.Get("X-Echo-UA") != httpengine.DefaultUserAgent {
		t.Fatalf("default UA = %q, want %q", resp.Headers.Get("X-Echo-UA"), httpengine.DefaultUserAgent)
	}

	// Per-request header overrides the default UA.
	resp, err = c.Do(context.Background(), httpengine.GET(srv.URL).WithHeader("User-Agent", "Custom/1"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Headers.Get("X-Echo-UA") != "Custom/1" {
		t.Fatalf("UA override failed: %q", resp.Headers.Get("X-Echo-UA"))
	}
}

func TestDefaultHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("X-Default"))
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.DefaultHeaders = map[string]string{"X-Default": "set"}
	c := mustClient(t, cfg)
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Headers.Get("X-Echo") != "set" {
		t.Fatalf("default header not applied: %q", resp.Headers.Get("X-Echo"))
	}
}

func TestCookieJarPersistsAcrossRequests(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session123", Path: "/"})
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("sid")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, ck.Value)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/set")); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/check"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "session123" {
		t.Fatalf("jar did not persist cookie, body=%q status=%d", resp.Body, resp.Status)
	}
}

func TestNoCookiesRequestIsAnonymous(t *testing.T) {
	var mu sync.Mutex
	var sawCookie []string
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session123", Path: "/"})
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawCookie = append(sawCookie, r.Header.Get("Cookie"))
		mu.Unlock()
		if _, err := r.Cookie("sid"); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/set")); err != nil {
		t.Fatal(err)
	}
	// The jar really does carry the cookie for an ordinary request.
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/check"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("ordinary request status = %d, want 200 (jar should carry the cookie)", resp.Status)
	}

	// NoCookies must bypass the jar AND any explicitly supplied cookies.
	req := httpengine.GET(srv.URL + "/check")
	req.NoCookies = true
	req.Cookies = []*http.Cookie{{Name: "sid", Value: "explicit"}}
	resp, err = c.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("NoCookies request status = %d, want 401 (a genuinely anonymous request)", resp.Status)
	}
	mu.Lock()
	last := sawCookie[len(sawCookie)-1]
	mu.Unlock()
	if last != "" {
		t.Fatalf("NoCookies request sent Cookie header %q, want none", last)
	}
}

// TestJarlessRequestSendsExplicitCookiesAndIgnoresTheJar: a jarless request
// sends only the cookies the caller supplied — nothing the jar stored, and its
// own Set-Cookie is not stored either.
func TestJarlessRequestSendsExplicitCookiesAndIgnoresTheJar(t *testing.T) {
	var mu sync.Mutex
	var sawCookie []string
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "jar", Value: "stored", Path: "/"})
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawCookie = append(sawCookie, r.Header.Get("Cookie"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "kept", Value: "nope", Path: "/"})
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/set")); err != nil {
		t.Fatal(err)
	}

	req := httpengine.GET(srv.URL + "/probe")
	req.Jarless = true
	req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := sawCookie[len(sawCookie)-1]
	mu.Unlock()
	if got != "explicit=only" {
		t.Fatalf("jarless request sent Cookie header %q, want only the explicit cookie", got)
	}

	// The jarless response's cookie must not have been stored for later
	// requests: the ordinary request sees the jar cookie, not "kept".
	mu.Lock()
	sawCookie = nil
	mu.Unlock()
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	ordinary := sawCookie[len(sawCookie)-1]
	mu.Unlock()
	if ordinary != "jar=stored" {
		t.Fatalf("ordinary request sent Cookie header %q, want only the jar cookie", ordinary)
	}
}

// TestNoJarRequestSendsExplicitCookiesAndLeavesTheJarAlone: a NoJar request
// still sends the cookies the caller supplied, but neither receives the jar's
// contents nor stores its own Set-Cookie. It is the transport primitive a
// disclosure fetch uses so its response cookie can be handed to exactly one
// follow-up probe instead of a process-wide jar.
func TestNoJarRequestSendsExplicitCookiesAndLeavesTheJarAlone(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Cookie")
		mu.Unlock()
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "jar", Value: "stored", Path: "/"})
		case "/probe":
			http.SetCookie(w, &http.Cookie{Name: "kept", Value: "nope", Path: "/"})
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/set")); err != nil {
		t.Fatal(err)
	}

	req := httpengine.GET(srv.URL + "/probe")
	req.NoJar = true
	req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := seen["/probe"]
	mu.Unlock()
	if got != "explicit=only" {
		t.Fatalf("NoJar request sent Cookie header %q, want only the explicit cookie", got)
	}

	// Its Set-Cookie must not have been stored: the ordinary request sees the
	// cookie /set stored, never "kept".
	mu.Lock()
	delete(seen, "/probe")
	mu.Unlock()
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	ordinary := seen["/probe"]
	mu.Unlock()
	if ordinary != "jar=stored" {
		t.Fatalf("ordinary request sent Cookie header %q, want only the jar cookie", ordinary)
	}
}

func TestRequestScopedCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("token"); err == nil {
			_, _ = io.WriteString(w, ck.Value)
		}
	}))
	defer srv.Close()

	// Disable the jar to prove the cookie comes from the request itself.
	cfg := httpengine.DefaultConfig()
	cfg.DisableCookies = true
	c := mustClient(t, cfg)
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL).WithCookie("token", "t0k"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "t0k" {
		t.Fatalf("request cookie not sent: %q", resp.Body)
	}
}

func TestRedirectsFollowedWithChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/b")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/c")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "final")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/a"))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "final" {
		t.Fatalf("did not follow to /c: %q", resp.Body)
	}
	if !strings.HasSuffix(resp.FinalURL, "/c") {
		t.Fatalf("final URL = %q", resp.FinalURL)
	}
	if len(resp.RedirectChain) != 2 {
		t.Fatalf("redirect chain = %v", resp.RedirectChain)
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false
	c := mustClient(t, cfg)
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.Status)
	}
	if resp.Headers.Get("Location") != "/elsewhere" {
		t.Fatalf("location = %q", resp.Headers.Get("Location"))
	}
}

func TestTooManyRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.MaxRedirects = 3
	c := mustClient(t, cfg)
	_, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/loop"))
	if !errors.Is(err, httpengine.ErrTooManyRedirects) {
		t.Fatalf("expected ErrTooManyRedirects, got %v", err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.Timeout = 50 * time.Millisecond
	c := mustClient(t, cfg)
	_, err := c.Do(context.Background(), httpengine.GET(srv.URL))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.Timeout = 0 // isolate cancellation from timeout
	c := mustClient(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := c.Do(ctx, httpengine.GET(srv.URL))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestProxyRouting(t *testing.T) {
	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For an http target, the transport sends an absolute-URI request here.
		proxied.Store(true)
		_, _ = io.WriteString(w, "via-proxy")
	}))
	defer proxy.Close()

	cfg := httpengine.DefaultConfig()
	cfg.ProxyURL = proxy.URL
	c := mustClient(t, cfg)

	// Target host is never resolved because everything goes through the proxy.
	resp, err := c.Do(context.Background(), httpengine.GET("http://indago.invalid/path"))
	if err != nil {
		t.Fatalf("do via proxy: %v", err)
	}
	if !proxied.Load() {
		t.Fatal("proxy was not used")
	}
	if string(resp.Body) != "via-proxy" {
		t.Fatalf("unexpected body via proxy: %q", resp.Body)
	}
}

func TestBodyLimitTruncates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 1000)))
	}))
	defer srv.Close()

	cfg := httpengine.DefaultConfig()
	cfg.MaxBodyBytes = 100
	c := mustClient(t, cfg)
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) != 100 || !resp.Truncated {
		t.Fatalf("expected truncated 100-byte body, got len=%d truncated=%v", len(resp.Body), resp.Truncated)
	}
}

func TestRequestResponseCapture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	resp, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/captured").WithHeader("X-Req", "1"))
	if err != nil {
		t.Fatal(err)
	}
	cap := resp.Request
	if cap == nil {
		t.Fatal("no captured request")
	}
	if cap.Method != "GET" || !strings.HasSuffix(cap.URL, "/captured") {
		t.Fatalf("captured method/url wrong: %s %s", cap.Method, cap.URL)
	}
	if cap.Headers.Get("X-Req") != "1" || cap.Headers.Get("User-Agent") != httpengine.DefaultUserAgent {
		t.Fatalf("captured headers wrong: %v", cap.Headers)
	}
	if resp.ReceivedAt.IsZero() {
		t.Fatal("ReceivedAt not set")
	}
}

func TestInvalidRequests(t *testing.T) {
	c := mustClient(t, httpengine.DefaultConfig())
	cases := []*httpengine.Request{
		nil,
		{URL: "://nonsense"},
		{URL: "ftp://example.com/"},     // non-http scheme
		{URL: "/relative/only"},         // not absolute
		{Method: "GET", URL: "http://"}, // no host
	}
	for i, req := range cases {
		if _, err := c.Do(context.Background(), req); !errors.Is(err, httpengine.ErrInvalidRequest) {
			t.Errorf("case %d: expected ErrInvalidRequest, got %v", i, err)
		}
	}
}

func TestInvalidProxyURL(t *testing.T) {
	cfg := httpengine.DefaultConfig()
	cfg.ProxyURL = "://not a url"
	if _, err := httpengine.New(cfg); err == nil {
		t.Fatal("expected error for invalid proxy URL")
	}
}

func TestStubReturnsNotImplemented(t *testing.T) {
	_, err := httpengine.Stub{}.Do(context.Background(), httpengine.GET("http://x/"))
	if !errors.Is(err, httpengine.ErrNotImplemented) {
		t.Fatalf("stub: expected ErrNotImplemented, got %v", err)
	}
}

func TestEngineInterfaceSatisfied(t *testing.T) {
	var _ httpengine.Engine = httpengine.NewDefault()
	var _ httpengine.Engine = httpengine.Stub{}
}

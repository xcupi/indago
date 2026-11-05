package httpengine_test

// The cookie-isolation modes must fail closed at the TRANSPORT level, not only
// inside the scope-enforcing engine.
//
// httpengine.Client is public and follows redirects itself, and a raw "Cookie"
// header (from Config.DefaultHeaders or Request.Headers) is cookie state just
// like Request.Cookies and the jar. For NoCookies, Jarless and NoJar the whole
// cookie state of the request must therefore be exactly what the caller
// declared: no default header, no raw header, no jar — and on a redirect the
// mode's cookies stop rather than being copied to the next hop (Go's client
// copies explicit Cookie headers to any same-host redirect, including an
// HTTPS->HTTP downgrade or a changed port).
//
// Ordinary (non-isolated) requests keep Go's normal behaviour: these tests pin
// that too, so the isolation cannot be implemented by disabling cookies
// everywhere.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/httpengine"
)

// isolationMode names one cookie-isolation mode of httpengine.Request.
type isolationMode struct {
	name  string
	apply func(*httpengine.Request)
}

func isolationModes() []isolationMode {
	return []isolationMode{
		{"nocookies", func(r *httpengine.Request) { r.NoCookies = true }},
		{"jarless", func(r *httpengine.Request) { r.Jarless = true }},
		{"nojar", func(r *httpengine.Request) { r.NoJar = true }},
	}
}

// cookieRecorder is a test server that records the raw Cookie header of every
// request it serves.
type cookieRecorder struct {
	*httptest.Server
	mu      sync.Mutex
	headers []string
}

func newCookieRecorder(t *testing.T, body string) *cookieRecorder {
	t.Helper()
	rec := &cookieRecorder{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.headers = append(rec.headers, r.Header.Get("Cookie"))
		rec.mu.Unlock()
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(rec.Server.Close)
	return rec
}

func (r *cookieRecorder) last(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.headers) == 0 {
		t.Fatal("the fixture was never requested")
	}
	return r.headers[len(r.headers)-1]
}

func (r *cookieRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.headers...)
}

// TestNoCookiesIgnoresRawAndDefaultCookieHeaders: NoCookies is a genuinely
// anonymous request. A "Cookie" header coming from the client's default headers
// or from the caller's own Headers map is cookie state like any other, so it
// must not reach the wire — otherwise the mode is only half anonymous.
func TestNoCookiesIgnoresRawAndDefaultCookieHeaders(t *testing.T) {
	rec := newCookieRecorder(t, "ok")

	cfg := httpengine.DefaultConfig()
	cfg.DefaultHeaders = map[string]string{"Cookie": "default=leak"}
	c := mustClient(t, cfg)
	t.Cleanup(c.Close)

	req := httpengine.GET(rec.URL + "/probe")
	req.NoCookies = true
	req.Headers = map[string]string{"Cookie": "raw=leak"}
	req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := rec.last(t); got != "" {
		t.Fatalf("NoCookies request sent Cookie header %q, want no cookie at all", got)
	}
}

// TestIsolationModesSendOnlyTheirExplicitCookies: Jarless and NoJar must send
// the cookies the caller put in Request.Cookies and nothing else. A raw or
// default "Cookie" header is ambient state the mode exists to exclude, and the
// jar's stored cookie proves the jar is bypassed too.
func TestIsolationModesSendOnlyTheirExplicitCookies(t *testing.T) {
	for _, mode := range isolationModes() {
		t.Run(mode.name, func(t *testing.T) {
			if mode.name == "nocookies" {
				t.Skip("NoCookies sends nothing; covered by TestNoCookiesIgnoresRawAndDefaultCookieHeaders")
			}
			rec := newCookieRecorder(t, "ok")

			cfg := httpengine.DefaultConfig()
			cfg.DefaultHeaders = map[string]string{"Cookie": "default=leak"}
			c := mustClient(t, cfg)
			t.Cleanup(c.Close)
			// Seed the jar through an ordinary request so a mode that still
			// consulted it would show the stored cookie. Cookies ignore ports,
			// so a second server on the same host scopes it to this probe.
			seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "jar", Value: "stored", Path: "/"})
				_, _ = io.WriteString(w, "seeded")
			}))
			t.Cleanup(seed.Close)
			if _, err := c.Do(context.Background(), httpengine.GET(seed.URL+"/set")); err != nil {
				t.Fatalf("seed jar: %v", err)
			}

			req := httpengine.GET(rec.URL + "/probe")
			mode.apply(req)
			req.Headers = map[string]string{"Cookie": "raw=leak"}
			req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
			if _, err := c.Do(context.Background(), req); err != nil {
				t.Fatalf("do: %v", err)
			}
			if got := rec.last(t); got != "explicit=only" {
				t.Fatalf("%s request sent Cookie header %q, want only the explicit cookie", mode.name, got)
			}
		})
	}
}

// TestIsolationModesDoNotForwardCookiesOnRedirect: a client that follows a
// redirect by itself copies an explicit Cookie header to any same-host
// destination, so a port change or an HTTPS->HTTP downgrade would leak the
// mode's cookies into a request the mode never authorised. Isolation is
// fail-closed: the next hop carries no cookie.
func TestIsolationModesDoNotForwardCookiesOnRedirect(t *testing.T) {
	for _, mode := range isolationModes() {
		t.Run(mode.name+"/changed-port", func(t *testing.T) {
			var target *cookieRecorder
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/landing", http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			target = newCookieRecorder(t, "landed")

			c := mustClient(t, httpengine.DefaultConfig())
			t.Cleanup(c.Close)

			req := httpengine.GET(origin.URL + "/start")
			mode.apply(req)
			req.Headers = map[string]string{"Cookie": "raw=leak"}
			req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
			if _, err := c.Do(context.Background(), req); err != nil {
				t.Fatalf("do: %v", err)
			}
			if got := target.last(t); strings.Contains(got, "explicit") || strings.Contains(got, "raw") {
				t.Fatalf("%s request forwarded cookies across a port change: %q", mode.name, got)
			}
		})

		t.Run(mode.name+"/https-to-http", func(t *testing.T) {
			var target *cookieRecorder
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/landing", http.StatusFound)
			}))
			t.Cleanup(origin.Close)
			target = newCookieRecorder(t, "landed")

			cfg := httpengine.DefaultConfig()
			cfg.InsecureSkipVerify = true
			c := mustClient(t, cfg)
			t.Cleanup(c.Close)

			req := httpengine.GET(origin.URL + "/start")
			mode.apply(req)
			req.Headers = map[string]string{"Cookie": "raw=leak"}
			req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
			if _, err := c.Do(context.Background(), req); err != nil {
				t.Fatalf("do: %v", err)
			}
			if got := target.last(t); strings.Contains(got, "explicit") || strings.Contains(got, "raw") {
				t.Fatalf("%s request forwarded cookies across an HTTPS->HTTP downgrade: %q", mode.name, got)
			}
		})
	}
}

// TestDefaultRequestKeepsNormalCookieBehaviour is the control: the isolation
// modes must not change what an ordinary request does. It still gets the jar's
// cookie, still sends the caller's explicit cookies (raw header included, which
// is how the header-injection flow supplies them), and Go's client still
// forwards that Cookie header on a same-host redirect.
func TestDefaultRequestKeepsNormalCookieBehaviour(t *testing.T) {
	var target *cookieRecorder
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/landing", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	target = newCookieRecorder(t, "landed")

	cfg := httpengine.DefaultConfig()
	c := mustClient(t, cfg)
	t.Cleanup(c.Close)

	// Seed the jar through the ordinary path.
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "jar", Value: "stored", Path: "/"})
		_, _ = io.WriteString(w, "seeded")
	}))
	t.Cleanup(seed.Close)
	if _, err := c.Do(context.Background(), httpengine.GET(seed.URL+"/set")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httpengine.GET(origin.URL + "/start")
	req.Headers = map[string]string{"Cookie": "raw=kept"}
	req.Cookies = []*http.Cookie{{Name: "explicit", Value: "only"}}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatalf("do: %v", err)
	}
	got := target.last(t)
	for _, want := range []string{"explicit=only", "raw=kept"} {
		if !strings.Contains(got, want) {
			t.Fatalf("ordinary redirected request lost %q: Cookie: %q", want, got)
		}
	}
}

// TestClientJarStillSharedForOrdinaryRequests pins the other half of "normal
// behaviour unchanged": an ordinary request still stores its Set-Cookie, and a
// later ordinary request still sends it.
func TestClientJarStillSharedForOrdinaryRequests(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Cookie"))
		mu.Unlock()
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "jar", Value: "stored", Path: "/"})
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := mustClient(t, httpengine.DefaultConfig())
	t.Cleanup(c.Close)
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/set")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), httpengine.GET(srv.URL+"/probe")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := seen[len(seen)-1]; got != "jar=stored" {
		t.Fatalf("ordinary request sent Cookie header %q, want the jar cookie", got)
	}
}

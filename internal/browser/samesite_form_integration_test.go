// These tests drive a REAL Chromium and pin the SameSite=cookie behaviour of
// NavigateForm against a loopback server the test owns.
//
// The bug they cover: NavigateForm writes its synthetic <form> into whatever
// document the page currently holds. On a fresh page that document is
// about:blank, whose origin is opaque, so Chromium submits the POST as a
// CROSS-SITE navigation and withholds every SameSite=Lax/Strict cookie — the
// scan's authenticated session among them. The candidate is then replayed
// unauthenticated and a reflected XSS at an authenticated POST endpoint is
// silently missed. NavigateForm now performs one bounded, read-only GET to the
// target's own URL first, which gives the document the origin a real form page
// would have had.
//
// Like the other real-browser tests here they skip (quickly) in -short mode and
// when no Chromium can be found. The second test is the negative control: it
// submits the same form from about:blank and shows the cookie is NOT sent, so
// the positive result cannot be explained by the fixture accepting anything.
package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

// laxSessionCookie is the session cookie every fixture here sets and requires.
// SameSite=Lax is the browser default for an unspecified cookie and the common
// choice for a session cookie, and it is exactly the value a cross-site POST
// (and only a cross-site POST) loses.
const laxSessionCookie = "sid"

type formFixtureRequest struct {
	method string
	path   string
	cookie string // raw Cookie header as received
	body   string
	status int
}

// laxFormFixture serves an authenticated, POST-only endpoint:
//   - GET /login sets the SameSite=Lax session cookie (the app's login step);
//   - POST /submit requires that cookie and renders the submitted field;
//   - GET /submit answers 405, the realistic shape of a POST-only endpoint,
//     so the warm-up has to tolerate a non-2xx document response.
type laxFormFixture struct {
	srv *httptest.Server

	mu   sync.Mutex
	reqs []formFixtureRequest
}

const laxLoginPage = `<!doctype html><html><body><form method="post" action="/submit">
<input name="q" value="hello"><button type="submit">go</button></form></body></html>`

func newLaxFormFixture(t *testing.T) *laxFormFixture {
	t.Helper()
	f := &laxFormFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     laxSessionCookie,
			Value:    "lax-session",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, laxLoginPage)
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		rec := formFixtureRequest{method: r.Method, path: r.URL.Path, cookie: r.Header.Get("Cookie")}
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			rec.body = r.PostForm.Get("q")
			if c, err := r.Cookie(laxSessionCookie); err != nil || c.Value != "lax-session" {
				rec.status = http.StatusUnauthorized
				f.record(rec)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, "<!doctype html><html><body><p id=login>authentication required</p></body></html>")
				return
			}
			rec.status = http.StatusOK
			f.record(rec)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, "<!doctype html><html><body><p id=posted>posted:%s</p></body></html>", rec.body)
			return
		}
		rec.status = http.StatusMethodNotAllowed
		f.record(rec)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = fmt.Fprint(w, "<!doctype html><html><body><p id=method>only POST is accepted here</p></body></html>")
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *laxFormFixture) record(r formFixtureRequest) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
}

func (f *laxFormFixture) requests() []formFixtureRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]formFixtureRequest(nil), f.reqs...)
}

func (f *laxFormFixture) posts() []formFixtureRequest {
	var out []formFixtureRequest
	for _, r := range f.requests() {
		if r.method == http.MethodPost {
			out = append(out, r)
		}
	}
	return out
}

func (f *laxFormFixture) allowAll(raw string) bool { return strings.HasPrefix(raw, f.srv.URL) }

// newSameSiteManager starts a Manager for this file's real-browser tests. Like
// internal/verification's helper it lowers isolation ONLY when the operator
// explicitly asks for it with INDAGO_TEST_BROWSER_NO_SANDBOX=1 (a restricted
// container without user namespaces); the default keeps Chromium's sandbox ON.
func newSameSiteManager(t *testing.T) *browser.Manager {
	t.Helper()
	cfg := browser.DefaultConfig()
	if os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1" {
		cfg.DisableSandbox = true
	}
	return newManagerOrSkip(t, cfg)
}

// writeLaxSessionState writes a Playwright storage-state file carrying one
// SameSite=Lax session cookie for rawURL's host — the same shape
// domain.Session.StatePath (auth.Existing / a completed login) has, so the
// test seeds the browser exactly the way production does.
func writeLaxSessionState(t *testing.T, rawURL string, name, value string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("parse fixture URL %q: %v", rawURL, err)
	}
	state := fmt.Sprintf(`{"cookies":[{"name":%q,"value":%q,"domain":%q,"path":"/","expires":-1,"httpOnly":true,"secure":false,"sameSite":"Lax"}],"origins":[]}`,
		name, value, u.Hostname())
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatalf("write storage state: %v", err)
	}
	return path
}

// TestIntegrationNavigateFormSendsSameSiteLaxSessionCookie is the fix's proof:
// a fresh page (about:blank) is warmed up to the target's origin, and the form
// POST then carries the SameSite=Lax session cookie and renders the POST
// response.
func TestIntegrationNavigateFormSendsSameSiteLaxSessionCookie(t *testing.T) {
	f := newLaxFormFixture(t)
	m := newSameSiteManager(t)
	defer m.Close()
	ctx := context.Background()

	statePath := writeLaxSessionState(t, f.srv.URL, laxSessionCookie, "lax-session")
	c, err := m.NewContext(ctx, browser.ContextOptions{
		AllowRequest:       f.allowAll,
		StorageStatePath:   statePath,
		AllowStateChanging: true, // the scan's explicit POST-replay opt-in
	})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	defer p.Close()

	if start, err := p.Evaluate(ctx, "location.href"); err != nil {
		t.Fatalf("read starting URL: %v", err)
	} else if s, _ := start.(string); s != "about:blank" {
		t.Fatalf("new page starts on %q, want about:blank (that is the case this test covers)", s)
	}

	nav, err := p.NavigateForm(ctx, http.MethodPost, f.srv.URL+"/submit",
		map[string]string{"q": "lax works"}, browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 15 * time.Second})
	if err != nil {
		t.Fatalf("NavigateForm: %v", err)
	}
	if nav.Status != http.StatusOK {
		t.Fatalf("POST status = %d, want 200: the request reached /submit unauthenticated", nav.Status)
	}
	html, err := p.Content(ctx)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	if !strings.Contains(html, "posted:lax works") {
		t.Fatalf("rendered POST response missing the submitted value: %.200s", html)
	}

	posts := f.posts()
	if len(posts) != 1 {
		t.Fatalf("server saw %d POST(s), want exactly 1", len(posts))
	}
	if !strings.Contains(posts[0].cookie, laxSessionCookie+"=lax-session") {
		t.Fatalf("POST Cookie header = %q, want the SameSite=Lax session cookie", posts[0].cookie)
	}
	var warmUps int
	for _, r := range f.requests() {
		if r.method == http.MethodGet {
			warmUps++
		}
	}
	if warmUps != 1 {
		t.Fatalf("server saw %d warm-up GET(s), want exactly 1 (one bounded same-origin navigation)", warmUps)
	}
	t.Logf("RESULT warmUpGET=%d posts=%d status=%d cookie=%q body=%q", warmUps, len(posts), posts[0].status, posts[0].cookie, posts[0].body)
}

// TestIntegrationNavigateFormCookieWithheldFromAboutBlank is the negative
// control for the test above: the SAME form, submitted from the same
// authenticated context but from about:blank's opaque origin, is a cross-site
// POST — Chromium withholds the SameSite=Lax cookie, the server answers 401 and
// the marker-bearing response is never rendered. It also shows the fixture
// really does require the cookie, so the positive test cannot pass by accident.
func TestIntegrationNavigateFormCookieWithheldFromAboutBlank(t *testing.T) {
	f := newLaxFormFixture(t)
	m := newSameSiteManager(t)
	defer m.Close()
	ctx := context.Background()

	statePath := writeLaxSessionState(t, f.srv.URL, laxSessionCookie, "lax-session")
	c, err := m.NewContext(ctx, browser.ContextOptions{
		AllowRequest:       f.allowAll,
		StorageStatePath:   statePath,
		AllowStateChanging: true,
	})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()
	p, err := c.NewPage(ctx)
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	defer p.Close()

	// Submit a plain form from the page's own (about:blank) document — the
	// mechanism NavigateForm used before the warm-up existed. A navigation
	// destroys the JS context, so the evaluate itself may report an error; the
	// server-side observation is what this control asserts on.
	script := fmt.Sprintf(`(() => {
  const f = document.createElement('form');
  f.method = 'POST';
  f.action = %q;
  const i = document.createElement('input');
  i.type = 'hidden'; i.name = 'q'; i.value = 'from about blank';
  f.appendChild(i);
  document.body.appendChild(f);
  f.submit();
  return 'submitted';
})()`, f.srv.URL+"/submit")
	_, _ = p.Evaluate(ctx, script)

	deadline := time.Now().Add(10 * time.Second)
	var posts []formFixtureRequest
	for time.Now().Before(deadline) {
		if posts = f.posts(); len(posts) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(posts) != 1 {
		t.Fatalf("server saw %d POST(s) from about:blank, want 1", len(posts))
	}
	if strings.Contains(posts[0].cookie, laxSessionCookie+"=") {
		t.Fatalf("about:blank POST carried the SameSite=Lax session cookie (%q); this control is meaningless, the fix's premise is wrong", posts[0].cookie)
	}
	if posts[0].status != http.StatusUnauthorized {
		t.Fatalf("about:blank POST status = %d, want 401", posts[0].status)
	}
	t.Logf("RESULT aboutBlank POST status=%d cookie=%q (SameSite=Lax withheld, as expected)", posts[0].status, posts[0].cookie)
}

// Real-Chromium regressions for POST/form verification against an AUTHENTICATED
// endpoint whose session cookie is SameSite=Lax.
//
// The defect: BrowserVerifier replays a POST/form candidate through
// browser.Page.NavigateForm, which used to write its synthetic <form> into a
// fresh, about:blank document. Chromium classifies a form submission by the
// SUBMITTING document's origin, so that POST is cross-site and the SameSite=Lax
// session cookie is withheld: the replay arrives unauthenticated, the server
// answers with a login/401 page, the marker is never re-observed and the
// verdict is Inconclusive — a false negative at every authenticated POST
// endpoint. NavigateForm now warms the page up on the target's own origin with
// one bounded, read-only GET first.
//
// Like the other tests in this package they run by default and skip (quickly)
// in -short mode or when no Chromium is installed.
package verification_test

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

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// laxSessionStatePath writes the Playwright storage-state file an authenticated
// scan would have saved (domain.Session.StatePath): one SameSite=Lax session
// cookie for rawURL's host.
func laxSessionStatePath(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("parse fixture URL %q: %v", rawURL, err)
	}
	state := fmt.Sprintf(`{"cookies":[{"name":"sid","value":"lax-session","domain":%q,"path":"/","expires":-1,"httpOnly":true,"secure":false,"sameSite":"Lax"}],"origins":[]}`, u.Hostname())
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatalf("write storage state: %v", err)
	}
	return path
}

// TestIntegrationVerifyFormPostSendsSameSiteLaxSessionCookie proves the whole
// path: an authenticated POST/form candidate is Confirmed (the marker executes
// in the POST response) because the replay carried the SameSite=Lax session
// cookie, and the unauthenticated control at the end shows the fixture — and
// therefore the verdict — really depends on that cookie.
func TestIntegrationVerifyFormPostSendsSameSiteLaxSessionCookie(t *testing.T) {
	m := marker(t)
	value := "<svg onload=" + m + ">"

	var mu sync.Mutex
	var cookieSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// A POST-only endpoint answering 405 to the warm-up GET is the
			// realistic shape; the warm-up only needs a same-origin document.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = fmt.Fprint(w, "<!doctype html><html><body>only POST is accepted here</body></html>")
			return
		}
		_ = r.ParseForm()
		cookie := r.Header.Get("Cookie")
		mu.Lock()
		cookieSeen = append(cookieSeen, cookie)
		mu.Unlock()
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "lax-session" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, "<!doctype html><html><body>authentication required</body></html>")
			return
		}
		// Authenticated: echo the injected field into the page, which is what
		// makes the candidate's own value execute on load.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><html><body>%s</body></html>", r.PostForm.Get("q"))
	}))
	defer srv.Close()

	mgr := newManagerOrSkip(t)
	defer mgr.Close()
	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})

	statePath := laxSessionStatePath(t, srv.URL)
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate:          detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value},
		Marker:             m,
		Method:             http.MethodPost,
		URL:                srv.URL + "/submit",
		Location:           domain.LocationForm,
		FormValues:         map[string]string{"q": value},
		Scope:              openScope(),
		SessionStatePath:   statePath,
		AllowStateChanging: true,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed (an authenticated POST replay must carry the SameSite=Lax session cookie): %+v", res.Verdict, res.Report)
	}
	mu.Lock()
	seen := append([]string(nil), cookieSeen...)
	mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("server saw %d POST(s), want exactly 1", len(seen))
	}
	if !strings.Contains(seen[0], "sid=lax-session") {
		t.Fatalf("POST Cookie header = %q, want the SameSite=Lax session cookie", seen[0])
	}

	// Control: without the session material the same replay cannot be
	// authenticated, so the marker cannot execute and the verdict must NOT be
	// Confirmed. This is what the fix prevents from happening by accident.
	control, err := v.Verify(context.Background(), verification.Input{
		Candidate:          detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value},
		Marker:             m,
		Method:             http.MethodPost,
		URL:                srv.URL + "/submit",
		Location:           domain.LocationForm,
		FormValues:         map[string]string{"q": value},
		Scope:              openScope(),
		AllowStateChanging: true,
	})
	if err != nil {
		t.Fatalf("control verify: %v", err)
	}
	if control.Verdict == domain.VerdictConfirmed {
		t.Fatalf("an unauthenticated POST replay was confirmed; the fixture does not require the session cookie")
	}
	mu.Lock()
	seen = append([]string(nil), cookieSeen...)
	mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("server saw %d POST(s) after the control, want 2", len(seen))
	}
	if strings.Contains(seen[1], "sid=") {
		t.Fatalf("control POST carried a session cookie (%q) despite no SessionStatePath", seen[1])
	}
	t.Logf("RESULT authenticated=%s cookie=%q control=%s controlCookie=%q", res.Verdict, seen[0], control.Verdict, seen[1])
}

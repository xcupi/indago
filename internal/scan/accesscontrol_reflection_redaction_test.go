package scan

// Response-body and derived-detail redaction for the access-control flow.
//
// Header-only redaction is not enough. A target can reflect the cookie values
// it received (and the ones it issued) straight into the HTML it serves:
//
//	<p>debug: sid=qa-…</p>
//	<a href="/admin/delete?username=wiener&debug=qa-…">Delete wiener</a>
//
// The first lands in the stored RESPONSE BODY; the second is body-derived data
// that the decision layer turns into an access-control Action.Target, so it
// reaches TestCase detail and Finding detail as well. The values must not be
// persisted in any of them — while the requests themselves keep carrying them,
// and while unrelated body content and the evidence's usefulness survive.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestAccessControlPageDisclosureRedactsReflectedCookieValues(t *testing.T) {
	const sessionValue = "qa-reflected-session-secret"

	env := newScanEnv(t)

	var mu sync.Mutex
	var adminCookieHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			// The disclosure response mints the anonymous cookie AND reflects
			// both cookie values into its own HTML, as a leaky target can.
			http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: acCookieValue(1), Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, fmt.Sprintf(`<!doctype html><html><body>
<p>debug: sid=%s</p>
<p>debug: %s=%s</p>
<script>
var isAdmin = false;
if (isAdmin) {
  adminPanelTag.setAttribute('href', '%s');
}
</script>
</body></html>`, sessionValue, acCookieName, acCookieValue(1), acAdminPath(1)))

		case r.URL.Path == acAdminPath(1):
			raw := r.Header.Get("Cookie")
			mu.Lock()
			adminCookieHeaders = append(adminCookieHeaders, raw)
			mu.Unlock()

			cookie, err := r.Cookie(acCookieName)
			if err != nil || cookie.Value != acCookieValue(1) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			// The panel reflects both values again; one of them sits inside an
			// action target, so it also flows into the derived detail.
			_, _ = io.WriteString(w, fmt.Sprintf(`<html><body><h1>Admin panel</h1>
<p>session sid=%s</p>
<table>
<tr><td>wiener</td><td><a href="/admin/delete?username=wiener&debug=%s">Delete wiener</a></td></tr>
<tr><td>carlos</td><td><a href="/admin/delete?username=carlos&debug=%s">Delete carlos</a></td></tr>
</table></body></html>`, sessionValue, sessionValue, acCookieValue(1)))

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: sessionValue, Domain: "127.0.0.1", Path: "/"},
	})
	ep := acEndpoint(t, env, srv.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := acCases(t, env)[0]
	d := acDetail(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: redaction must not change the decision", d.Verdict, d.Reason)
	}
	if len(d.Actions) == 0 {
		t.Fatalf("detail lost its actions: %s", tc.Detail)
	}
	findings := acFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	// The WIRE still carries the real values: redaction belongs at the
	// persistence boundary, never in the request itself.
	mu.Lock()
	headers := append([]string(nil), adminCookieHeaders...)
	mu.Unlock()
	var sawIssuedOnWire, sawSessionOnWire bool
	for _, raw := range headers {
		if strings.Contains(raw, acCookieName+"="+acCookieValue(1)) && !strings.Contains(raw, "sid=") {
			sawIssuedOnWire = true
		}
		if strings.Contains(raw, "sid="+sessionValue) {
			sawSessionOnWire = true
		}
	}
	if !sawIssuedOnWire {
		t.Fatalf("the anonymous probe lost the page-issued cookie on the wire; hits = %q", headers)
	}
	if !sawSessionOnWire {
		t.Fatalf("the non-admin comparison lost the saved session on the wire; hits = %q", headers)
	}

	// EVERY evidence blob this scan stored must omit both values.
	rows, err := env.st.Evidence().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no evidence was recorded")
	}
	var sawRedactedRequestHeader, sawPanelBody bool
	for _, row := range rows {
		_, body := env.evidenceBlob(row.ID)
		for _, secret := range []string{sessionValue, acCookieValue(1)} {
			if strings.Contains(body, secret) {
				t.Fatalf("raw cookie value %q persisted in %s evidence %s:\n%s", secret, row.Kind, row.ID, body)
			}
		}
		if row.Kind == domain.EvidenceRequest && strings.Contains(body, "Cookie:") &&
			strings.Contains(body, "sid=<redacted>") {
			sawRedactedRequestHeader = true
		}
		// Unrelated body content survives: the evidence still shows WHY the
		// path counted (a real admin panel), not an empty document.
		if row.Kind == domain.EvidenceResponse && strings.Contains(body, "Admin panel") {
			sawPanelBody = true
		}
	}
	if !sawRedactedRequestHeader {
		t.Fatal("request evidence must still show the cookie NAME with a redacted value")
	}
	if !sawPanelBody {
		t.Fatal("response evidence lost unrelated body content (the panel heading)")
	}

	for name, blob := range map[string][]byte{
		"test-case detail": tc.Detail,
		"finding detail":   findings[0].Detail,
		"finding summary":  []byte(findings[0].Summary + "\n" + findings[0].Title + "\n" + tc.Note),
	} {
		for _, secret := range []string{sessionValue, acCookieValue(1)} {
			if strings.Contains(string(blob), secret) {
				t.Fatalf("raw cookie value %q persisted in the %s:\n%s", secret, name, blob)
			}
		}
	}
	// Replacement, not deletion: the derived record still says where the
	// action pointed, with the value marked.
	if !strings.Contains(string(tc.Detail), "<redacted>") {
		t.Fatalf("test-case detail should mark the redacted value rather than drop the field:\n%s", tc.Detail)
	}
}

// TestAccessControlPageDisclosureRedactsShortCookieValues covers the case the
// length floor used to exempt: a short cookie value (here three bytes, the
// shape of the "sid=abc" lab credentials) is still credential and
// authorization state. The disclosure page reflects it into its HTML and the
// panel's action target embeds it, so the value reaches both a stored response
// body and a body-derived detail field. The requests must keep carrying it on
// the wire; every persisted blob must not.
func TestAccessControlPageDisclosureRedactsShortCookieValues(t *testing.T) {
	const (
		shortValue = "zqx"
		// The disclosed path deliberately embeds the short value too: the
		// finding's title and reason quote the path, so this exercises those
		// persistence surfaces as well as the body-derived action target.
		shortAdminPath = "/admin-" + shortValue
	)

	env := newScanEnv(t)

	var mu sync.Mutex
	var adminCookieHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: shortValue, Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, fmt.Sprintf(`<!doctype html><html><body>
<p>debug: %s=%s</p>
<script>
var isAdmin = false;
if (isAdmin) {
  adminPanelTag.setAttribute('href', '%s');
}
</script>
</body></html>`, acCookieName, shortValue, shortAdminPath))

		case r.URL.Path == shortAdminPath:
			raw := r.Header.Get("Cookie")
			mu.Lock()
			adminCookieHeaders = append(adminCookieHeaders, raw)
			mu.Unlock()

			cookie, err := r.Cookie(acCookieName)
			if err != nil || cookie.Value != shortValue {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			// The action target is body-derived data: accesscontrol.Analyze
			// turns this href into Action.Target, which reaches TestCase and
			// Finding detail.
			_, _ = io.WriteString(w, fmt.Sprintf(`<html><body><h1>Admin panel</h1>
<table>
<tr><td>wiener</td><td><a href="/admin/delete?username=wiener&debug=%s">Delete wiener</a></td></tr>
</table></body></html>`, shortValue))

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), openScope())
	ep := acEndpoint(t, env, srv.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	tc := acCases(t, env)[0]
	d := acDetail(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: redaction must not change the decision", d.Verdict, d.Reason)
	}
	findings := acFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	// The wire still carries the short value: it is the anonymous session the
	// disclosed path is bound to.
	mu.Lock()
	headers := append([]string(nil), adminCookieHeaders...)
	mu.Unlock()
	sawShortOnWire := false
	for _, raw := range headers {
		if strings.Contains(raw, acCookieName+"="+shortValue) {
			sawShortOnWire = true
		}
	}
	if !sawShortOnWire {
		t.Fatalf("the anonymous probe lost the short page-issued cookie on the wire; hits = %q", headers)
	}

	// The persisted derived records quote the disclosed path (title, summary)
	// and its action target (details); none may carry the short value. This
	// check runs before the evidence scan so a RED run names the title/summary
	// surface, not only the response body.
	blobs := map[string]string{
		"test-case detail": string(tc.Detail),
		"test-case note":   tc.Note,
		"test-case error":  tc.Error,
		"finding detail":   string(findings[0].Detail),
		"finding title":    findings[0].Title,
		"finding summary":  findings[0].Summary,
	}
	for name, blob := range blobs {
		if strings.Contains(blob, shortValue) {
			t.Fatalf("raw short cookie value %q persisted in the %s:\n%s", shortValue, name, blob)
		}
	}

	// EVERY evidence blob this scan stored must omit the value, while the
	// request evidence still shows the cookie NAME marked as redacted.
	rows, err := env.st.Evidence().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no evidence was recorded")
	}
	var sawRedactedRequestHeader, sawPanelBody bool
	for _, row := range rows {
		_, body := env.evidenceBlob(row.ID)
		if strings.Contains(body, shortValue) {
			t.Fatalf("raw short cookie value %q persisted in %s evidence %s:\n%s", shortValue, row.Kind, row.ID, body)
		}
		if row.Kind == domain.EvidenceRequest && strings.Contains(body, "Cookie:") &&
			strings.Contains(body, acCookieName+"=<redacted>") {
			sawRedactedRequestHeader = true
		}
		if row.Kind == domain.EvidenceResponse && strings.Contains(body, "Admin panel") {
			sawPanelBody = true
		}
	}
	if !sawRedactedRequestHeader {
		t.Fatal("request evidence must still show the cookie name with a redacted value")
	}
	if !sawPanelBody {
		t.Fatal("response evidence lost unrelated body content (the panel heading)")
	}

	// Replacement, not deletion: the derived action still says where it
	// pointed, with the credential marked.
	if !strings.Contains(string(tc.Detail), "<redacted>") {
		t.Fatalf("test-case detail should mark the redacted value rather than drop the field:\n%s", tc.Detail)
	}
	if !strings.Contains(string(findings[0].Detail), "<redacted>") {
		t.Fatalf("finding detail should mark the redacted value rather than drop the field:\n%s", findings[0].Detail)
	}
	if strings.Contains(string(tc.Detail), "Delete wiener") == false {
		t.Fatalf("test-case detail lost the action's own text:\n%s", tc.Detail)
	}
}

// TestAccessControlPageDisclosureNumericCookieKeepsDetailValid: a one-digit
// cookie value is redacted from cookie-derived strings, but the persisted
// TestCase/Finding detail must stay valid JSON with its numeric fields intact.
func TestAccessControlPageDisclosureNumericCookieKeepsDetailValid(t *testing.T) {
	const value = "2"
	env := newScanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: value, Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><body><script>
var isAdmin = false;
if (isAdmin) {
  adminPanelTag.setAttribute('href', '/admin-qq');
}
</script></body></html>`)
		case "/admin-qq":
			if c, err := r.Cookie(acCookieName); err != nil || c.Value != value {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><body><h1>Admin panel</h1><table>
<tr><td>wiener</td><td><a href="/admin/delete?username=wiener&debug=2">Delete wiener</a></td></tr>
</table></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	eng := newScopedEngine(noFollowClient(t), openScope())
	ep := acEndpoint(t, env, srv.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	tc := acCases(t, env)[0]
	findings := acFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	for name, blob := range map[string][]byte{"test-case detail": tc.Detail, "finding detail": findings[0].Detail} {
		var m map[string]any
		if err := json.Unmarshal(blob, &m); err != nil {
			t.Fatalf("%s must remain valid JSON: %v\n%s", name, err, blob)
		}
	}
	d := acDetail(t, tc)
	if d.Verdict != domain.VerdictConfirmed || d.PageStatus != 200 || d.AnonymousStatus != 200 {
		t.Fatalf("detail numbers/verdict corrupted: verdict=%q page=%d anon=%d", d.Verdict, d.PageStatus, d.AnonymousStatus)
	}
	var m map[string]any
	_ = json.Unmarshal(tc.Detail, &m)
	for _, s := range collectStrings(m) {
		if strings.Contains(s, "debug="+value) {
			t.Fatalf("raw numeric cookie value persisted in a detail string: %q", s)
		}
	}
	if len(d.Actions) != 1 || d.Actions[0].Target != "/admin/delete?username=wiener&debug=<redacted>" {
		t.Fatalf("cookie-derived action target = %+v, want the value redacted", d.Actions)
	}
}

// collectStrings returns every string leaf of a decoded JSON value.
func collectStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, collectStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, collectStrings(e)...)
		}
		return out
	}
	return nil
}

package scan

// Page-disclosure cookie continuity (Lab 19): an "unpredictable" admin path a
// page's own script discloses is commonly bound to the anonymous session
// cookie the SAME page response minted. The disclosure fetch and the follow-up
// panel probe must therefore keep same-origin response-cookie continuity within
// one scan — while never carrying the scan's authenticated session, another
// origin's cookies, or another scan's state.
//
// The fixtures below reproduce that shape faithfully: "/" mints a fresh cookie
// and discloses the admin path BOUND to it; the admin path only serves its
// user-delete panel when the matching cookie arrives.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

const acCookieName = "anon-session"

func acCookieValue(visit int) string { return fmt.Sprintf("anon-secret-%d", visit) }
func acAdminPath(visit int) string   { return fmt.Sprintf("/admin-%d", visit) }

// acPageDisclosureBody is the disclosure shape the live lab serves: the path
// exists only inside the page's own inline script, guarded by a role flag.
func acPageDisclosureBody(visit int) string {
	return fmt.Sprintf(`<!doctype html><html><body>
<script>
var isAdmin = false;
if (isAdmin) {
  adminPanelTag.setAttribute('href', '%s');
}
</script>
</body></html>`, acAdminPath(visit))
}

type acPageMode string

const (
	// acPageCookieBound: the page mints a cookie and discloses the path that
	// cookie unlocks. A scanner that keeps the cookie confirms.
	acPageCookieBound acPageMode = "bound"
	// acPageNoCookie: the page discloses the path but sets no cookie at all.
	acPageNoCookie acPageMode = "no-cookie"
	// acPageMismatched: the page sets a cookie, but not the one the disclosed
	// path is bound to (a rotated/stale value).
	acPageMismatched acPageMode = "mismatched"
	// acPageBarePanel: the cookie IS the right one and the disclosed path
	// answers 200 — but the page exposes no privileged action, so it must not
	// be confirmed. A status is not a finding.
	acPageBarePanel acPageMode = "bare-panel"
)

// acAdminHit is one request the fixture served for the disclosed admin path.
type acAdminHit struct {
	Path      string
	HadCookie bool
	Cookie    string
	Raw       string
}

type acPageServer struct {
	*httptest.Server
	mode acPageMode

	mu     sync.Mutex
	visits int
	hits   []acAdminHit
}

func newACPageServer(t *testing.T, mode acPageMode) *acPageServer {
	t.Helper()
	f := &acPageServer{mode: mode}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			f.mu.Lock()
			f.visits++
			visit := f.visits
			f.mu.Unlock()

			if mode != acPageNoCookie {
				value := acCookieValue(visit)
				if mode == acPageMismatched {
					// A cookie this page never bound to the disclosed path.
					value = acCookieValue(visit + 100)
				}
				http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: value, Path: "/"})
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acPageDisclosureBody(visit))

		case strings.HasPrefix(r.URL.Path, "/admin-"):
			visit, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/admin-"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			cookie, cookieErr := r.Cookie(acCookieName)
			hit := acAdminHit{Path: r.URL.Path, HadCookie: cookieErr == nil, Raw: r.Header.Get("Cookie")}
			if cookieErr == nil {
				hit.Cookie = cookie.Value
			}
			f.mu.Lock()
			f.hits = append(f.hits, hit)
			f.mu.Unlock()

			// The panel is served only to the anonymous session the same page
			// response issued for THIS path; anything else is a 404.
			if cookieErr != nil || cookie.Value != acCookieValue(visit) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			if mode == acPageBarePanel {
				_, _ = io.WriteString(w, `<html><body><h1>Admin panel</h1><p>Nothing to see here.</p></body></html>`)
				return
			}
			_, _ = io.WriteString(w, acAdminPanel)

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *acPageServer) adminHits() []acAdminHit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]acAdminHit(nil), f.hits...)
}

func acPageJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	job := acJob(env, ep)
	job.Payload = accessControlModePayload(accessModePage)
	return job
}

// TestAccessControlPageDisclosureCarriesIssuedCookieToDisclosedPath is the
// required positive: the admin path is only reachable with the cookie the
// disclosure page response minted, so the panel probe must carry it.
func TestAccessControlPageDisclosureCarriesIssuedCookieToDisclosedPath(t *testing.T) {
	env := newScanEnv(t)
	fx := newACPageServer(t, acPageCookieBound)

	ep := acEndpoint(t, env, fx.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	cases := acCases(t, env)
	if len(cases) != 1 {
		t.Fatalf("expected 1 access-control test case, got %d", len(cases))
	}
	tc := cases[0]
	d := acDetail(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: the page-issued anonymous cookie unlocks the disclosed admin path", d.Verdict, d.Reason)
	}
	if d.Kind != accessModePage || len(d.Actions) == 0 {
		t.Fatalf("confirmed detail incomplete: %+v", d)
	}
	if len(d.Refs) != 1 || d.Refs[0].Path != acAdminPath(1) {
		t.Fatalf("refs = %+v, want exactly the disclosed %s", d.Refs, acAdminPath(1))
	}

	// The probe must have carried the cookie the page response issued.
	hits := fx.adminHits()
	if len(hits) == 0 {
		t.Fatal("the disclosed admin path was never probed")
	}
	sawIssued := false
	for _, h := range hits {
		if h.HadCookie && h.Cookie == acCookieValue(1) {
			sawIssued = true
		}
	}
	if !sawIssued {
		t.Fatalf("admin-path probe hits = %+v, want one carrying the page-issued cookie", hits)
	}

	fs := acFindings(t, env)
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(fs))
	}
	if fs[0].VulnClass != domain.VulnAccessControl || fs[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = class %q verdict %q, want access_control/confirmed", fs[0].VulnClass, fs[0].Verdict)
	}

	// Requirement: the ephemeral cookie's VALUE is never persisted — not in
	// evidence, not in test-case detail, not in the finding detail. The name
	// and scope stay visible, so the evidence still says what was sent.
	secret := acCookieValue(1)
	var sawRedactedRequest, sawRedactedSetCookie bool
	ids := append(append([]domain.ID{}, tc.EvidenceIDs...), fs[0].EvidenceIDs...)
	for _, id := range ids {
		row, body := env.evidenceBlob(id)
		if strings.Contains(body, secret) {
			t.Fatalf("raw response-cookie value persisted in %s evidence %s:\n%s", row.Kind, id, body)
		}
		if row.Kind == domain.EvidenceRequest && strings.Contains(body, "GET "+acAdminPath(1)) &&
			strings.Contains(body, acCookieName+"=<redacted>") {
			sawRedactedRequest = true
		}
		if row.Kind == domain.EvidenceResponse && strings.Contains(body, "Set-Cookie: "+acCookieName+"=<redacted>") {
			sawRedactedSetCookie = true
		}
	}
	if !sawRedactedRequest {
		t.Fatal("the anonymous probe evidence must show the replayed cookie name with a redacted value")
	}
	if !sawRedactedSetCookie {
		t.Fatal("the disclosure-page evidence must show the Set-Cookie name with a redacted value")
	}
	if strings.Contains(string(tc.Detail), secret) {
		t.Fatalf("raw response-cookie value persisted in the test-case detail: %s", tc.Detail)
	}
	if strings.Contains(string(fs[0].Detail), secret) {
		t.Fatalf("raw response-cookie value persisted in the finding detail: %s", fs[0].Detail)
	}
}

// TestAccessControlPageDisclosureRejectsUnreachableDisclosedPath is the
// required negative control: continuity must never manufacture access. Without
// the issued cookie, with a cookie the path was not bound to, or with a 200 that
// exposes no privileged action, the disclosed path is not a finding.
func TestAccessControlPageDisclosureRejectsUnreachableDisclosedPath(t *testing.T) {
	for _, mode := range []acPageMode{acPageNoCookie, acPageMismatched, acPageBarePanel} {
		t.Run(string(mode), func(t *testing.T) {
			env := newScanEnv(t)
			fx := newACPageServer(t, mode)

			ep := acEndpoint(t, env, fx.URL+"/", domain.SourceCrawler, domain.MethodGET)
			ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev, ExecutorConfig{}, execLog(), nil, false)
			if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
				t.Fatalf("handle: %v", err)
			}

			d := acDetail(t, acCases(t, env)[0])
			if d.Verdict == domain.VerdictConfirmed {
				t.Fatalf("verdict = confirmed (%s); a disclosed path that does not expose a privileged action, or does not accept the cookie, must not be a finding", d.Reason)
			}
			if d.Verdict != domain.VerdictRejected {
				t.Fatalf("verdict = %q (%s), want rejected", d.Verdict, d.Reason)
			}
			if fs := acFindings(t, env); len(fs) != 0 {
				t.Fatalf("no finding may be created for an unreachable disclosed path: %+v", fs)
			}
		})
	}
}

// TestAccessControlPageDisclosureKeepsTheSessionOutOfTheAnonymousProbe covers
// the authenticated case: an existing session must still be used for the
// non-admin comparison, while the anonymous probe carries ONLY the cookie the
// disclosure page issued — never the scan's own session cookie.
func TestAccessControlPageDisclosureKeepsTheSessionOutOfTheAnonymousProbe(t *testing.T) {
	env := newScanEnv(t)
	fx := newACPageServer(t, acPageCookieBound)

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: "nonadmin", Domain: "127.0.0.1", Path: "/"},
	})
	ep := acEndpoint(t, env, fx.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}

	var sawIssued, sawSession bool
	for _, h := range fx.adminHits() {
		hasIssued := strings.Contains(h.Raw, acCookieName+"="+acCookieValue(1))
		hasSession := strings.Contains(h.Raw, "sid=")
		if hasSession {
			sawSession = true
		}
		if hasIssued && !hasSession {
			sawIssued = true
		}
	}
	if !sawIssued {
		t.Fatalf("no anonymous probe carried exactly the issued cookie; hits = %+v", fx.adminHits())
	}
	if !sawSession {
		t.Fatalf("the non-admin comparison request lost the scan's session cookie; hits = %+v", fx.adminHits())
	}
}

// TestAccessControlPageDisclosureCookieNeverLeavesItsOrigin is the required
// cross-origin control: the page fetch lands on origin B (a redirect), whose
// response mints a cookie and discloses a path. The disclosed path is resolved
// on the page's own origin A, and origin A must never receive origin B's
// cookie.
func TestAccessControlPageDisclosureCookieNeverLeavesItsOrigin(t *testing.T) {
	env := newScanEnv(t)

	var mu sync.Mutex
	var cookieAtA string
	var sawCookieAtA bool

	originB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/home" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: acCookieValue(1), Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, acPageDisclosureBody(1))
	}))
	defer originB.Close()

	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			http.Redirect(w, r, originB.URL+"/home", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/admin-"):
			mu.Lock()
			if c, err := r.Cookie(acCookieName); err == nil {
				sawCookieAtA, cookieAtA = true, c.Value
			}
			mu.Unlock()
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer originA.Close()

	ep := acEndpoint(t, env, originA.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if sawCookieAtA {
		t.Fatalf("origin %s received cookie %q issued by origin %s", originA.URL, cookieAtA, originB.URL)
	}
	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q (%s), want rejected: origin A never serves the path", d.Verdict, d.Reason)
	}
}

// TestAccessControlPageDisclosureEvidenceDoesNotPersistSessionCookieValue is
// the authenticated half of the evidence requirement. A NoJar disclosure fetch
// still attaches the scan's explicit saved session — that is deliberate request
// state — and the non-admin comparison carries it too, but a session cookie is
// a credential. Every access-control evidence blob must therefore show the
// cookie NAME with its value redacted, never the value itself.
func TestAccessControlPageDisclosureEvidenceDoesNotPersistSessionCookieValue(t *testing.T) {
	const sessionValue = "qa-nonadmin-secret"

	env := newScanEnv(t)
	fx := newACPageServer(t, acPageCookieBound)

	eng := newScopedEngine(noFollowClient(t), openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: sessionValue, Domain: "127.0.0.1", Path: "/"},
	})
	ep := acEndpoint(t, env, fx.URL+"/", domain.SourceCrawler, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}

	// The requests themselves must still carry the session (behaviour is
	// unchanged); only the persisted copy is redacted. The admin-path fixture
	// sees the comparison request, which is the one that carries it.
	var sawSessionOnWire, sawIssuedOnWire bool
	for _, h := range fx.adminHits() {
		if strings.Contains(h.Raw, "sid="+sessionValue) {
			sawSessionOnWire = true
		}
		if strings.Contains(h.Raw, acCookieName+"="+acCookieValue(1)) && !strings.Contains(h.Raw, "sid=") {
			sawIssuedOnWire = true
		}
	}
	if !sawSessionOnWire {
		t.Fatalf("the non-admin comparison did not carry the saved session; hits = %+v", fx.adminHits())
	}
	if !sawIssuedOnWire {
		t.Fatalf("the anonymous probe lost the page-issued cookie; hits = %+v", fx.adminHits())
	}

	// Every evidence blob this scan produced belongs to the access-control
	// flow; none may carry the session value.
	rows, err := env.st.Evidence().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no evidence was recorded")
	}
	var sawDisclosureRequest, sawComparisonRequest bool
	for _, row := range rows {
		_, body := env.evidenceBlob(row.ID)
		if strings.Contains(body, sessionValue) {
			t.Fatalf("raw saved-session cookie value persisted in %s evidence %s:\n%s", row.Kind, row.ID, body)
		}
		if row.Kind != domain.EvidenceRequest || !strings.Contains(body, "Cookie:") {
			continue
		}
		if strings.Contains(body, "GET / HTTP/1.1") && strings.Contains(body, "sid=<redacted>") {
			sawDisclosureRequest = true
		}
		if strings.Contains(body, "GET "+acAdminPath(1)) && strings.Contains(body, "sid=<redacted>") {
			sawComparisonRequest = true
		}
	}
	if !sawDisclosureRequest {
		t.Fatal("the disclosure-page request evidence must show Cookie: sid=<redacted>")
	}
	if !sawComparisonRequest {
		t.Fatal("the non-admin comparison request evidence must show Cookie: sid=<redacted>")
	}
}

// TestAccessControlPageDisclosureLeavesTheSharedJarAlone is the behavioural
// boundary the first candidate missed. The scanner shares ONE
// *httpengine.Client — and therefore one process-wide cookie jar — across every
// scoped engine it builds. A disclosure fetch that travels as an ordinary
// request stores the page's Set-Cookie in that jar, where an unrelated request
// from ANY scan can pick it up. Continuity must be job-local: the disclosure
// pass neither reads nor writes the ambient jar.
//
// The flow runs exactly as production wires it: one shared client, a scoped
// engine for the disclosure job, then another ordinary scoped engine (what a
// second scan builds) on that SAME client requesting a capture endpoint.
func TestAccessControlPageDisclosureLeavesTheSharedJarAlone(t *testing.T) {
	env := newScanEnv(t)

	var mu sync.Mutex
	var captureCookies []string
	var pageCookie string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			mu.Lock()
			pageCookie = r.Header.Get("Cookie")
			mu.Unlock()
			// The lab shape: a fresh anonymous session cookie plus the
			// admin path that exact cookie unlocks.
			http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: acCookieValue(1), Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, fmt.Sprintf(`<!doctype html><html><body>
<script>
var isAdmin = false;
if (isAdmin) {
  adminPanelTag.setAttribute('href', '%s');
}
</script>
<script src="/app.js"></script>
</body></html>`, acAdminPath(1)))

		case "/plant":
			// An unrelated response's cookie, i.e. what the shared jar already
			// holds when this pass starts.
			http.SetCookie(w, &http.Cookie{Name: "ambient", Value: "planted", Path: "/"})
			_, _ = io.WriteString(w, "planted")

		case "/app.js":
			// A disclosure script response can set cookies too; it is part of
			// the same pass and must not poison the shared jar either.
			http.SetCookie(w, &http.Cookie{Name: "script-session", Value: "script-secret", Path: "/"})
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, "var unused = 1;\n")

		case acAdminPath(1):
			cookie, err := r.Cookie(acCookieName)
			if err != nil || cookie.Value != acCookieValue(1) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acAdminPanel)

		case "/capture":
			mu.Lock()
			captureCookies = append(captureCookies, r.Header.Get("Cookie"))
			mu.Unlock()
			_, _ = io.WriteString(w, "captured")

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/", domain.SourceCrawler, domain.MethodGET)
	client := noFollowClient(t) // ONE client, shared by both engines, as in production
	scope := openScope()
	other := newScopedEngine(client, scope)

	// Prime the shared jar the way an earlier, unrelated request would: the
	// disclosure fetch must not READ that ambient state either.
	if _, err := other.Do(context.Background(), httpengine.GET(srv.URL+"/plant")); err != nil {
		t.Fatalf("prime shared jar: %v", err)
	}

	disclosure := newScopedEngine(client, scope)
	ex := newAccessControlExecutor(env.st, disclosure, env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// The continuity path must still work: a flow that stopped confirming
	// would pass this test for the wrong reason.
	if d := acDetail(t, acCases(t, env)[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: continuity itself must keep working", d.Verdict, d.Reason)
	}

	mu.Lock()
	gotPage := pageCookie
	mu.Unlock()
	if strings.Contains(gotPage, "ambient=planted") {
		t.Fatalf("the disclosure fetch read the shared jar: page request carried %q", gotPage)
	}

	// The second, ordinary scoped engine asks for a capture endpoint on the
	// SAME client — what a second scan (or any later, unrelated request) does.
	if _, err := other.Do(context.Background(), httpengine.GET(srv.URL+"/capture")); err != nil {
		t.Fatalf("capture request: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captureCookies) != 1 {
		t.Fatalf("expected exactly one capture request, got %d", len(captureCookies))
	}
	for _, leaked := range []string{acCookieName + "=" + acCookieValue(1), "script-session=script-secret"} {
		if strings.Contains(captureCookies[0], leaked) {
			t.Fatalf("the disclosure pass stored %q in the shared HTTP client jar; a request from another engine on that client carried it: %q",
				leaked, captureCookies[0])
		}
	}
}

// TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar covers
// the LAST request in the flow that still travelled as an ordinary request: the
// authenticated non-admin comparison. It deliberately carries the scan's saved
// session (that is its job), but it must neither inherit the process-wide jar's
// ambient cookies nor deposit the cookies its own response sets — the scan-local
// boundary has to hold for the comparison exactly as it does for the disclosure
// fetch, the script fetch and the anonymous carry.
//
// The fixture serves one shared client the way production wires it: a cookie
// planted in the jar by an unrelated request, a page-disclosure job on a second
// scoped engine, and a third ordinary engine that asks for a capture endpoint
// afterwards (what a second scan does).
func TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar(t *testing.T) {
	const (
		sessionValue    = "qa-comparison-secret"
		comparisonMints = "comparison-issued"
	)
	env := newScanEnv(t)

	var mu sync.Mutex
	var adminCookieHeaders []string
	var captureCookies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			http.SetCookie(w, &http.Cookie{Name: acCookieName, Value: acCookieValue(1), Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acPageDisclosureBody(1))

		case r.URL.Path == "/plant":
			// An unrelated response's cookie, i.e. what the shared jar holds
			// when this pass starts.
			http.SetCookie(w, &http.Cookie{Name: "ambient", Value: "planted", Path: "/"})
			_, _ = io.WriteString(w, "planted")

		case r.URL.Path == acAdminPath(1):
			raw := r.Header.Get("Cookie")
			mu.Lock()
			adminCookieHeaders = append(adminCookieHeaders, raw)
			mu.Unlock()

			if strings.Contains(raw, "sid="+sessionValue) {
				// This is the non-admin comparison. It is denied the panel (as
				// in the lab) and its response mints a fresh cookie that must
				// stay job-local.
				http.SetCookie(w, &http.Cookie{Name: "comparison-mint", Value: comparisonMints, Path: "/"})
				http.NotFound(w, r)
				return
			}
			cookie, err := r.Cookie(acCookieName)
			if err != nil || cookie.Value != acCookieValue(1) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acAdminPanel)

		case r.URL.Path == "/capture":
			mu.Lock()
			captureCookies = append(captureCookies, r.Header.Get("Cookie"))
			mu.Unlock()
			_, _ = io.WriteString(w, "captured")

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/", domain.SourceCrawler, domain.MethodGET)
	client := noFollowClient(t) // ONE client, shared by every engine, as in production
	scope := openScope()
	other := newScopedEngine(client, scope)

	// Prime the shared jar the way an earlier, unrelated request would.
	if _, err := other.Do(context.Background(), httpengine.GET(srv.URL+"/plant")); err != nil {
		t.Fatalf("prime shared jar: %v", err)
	}

	eng := newScopedEngine(client, scope).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: sessionValue, Domain: "127.0.0.1", Path: "/"},
	})
	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acPageJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// Continuity must still work: a flow that stopped confirming would pass
	// the isolation assertions for the wrong reason.
	if d := acDetail(t, acCases(t, env)[0]); d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed: continuity itself must keep working", d.Verdict, d.Reason)
	}

	mu.Lock()
	headers := append([]string(nil), adminCookieHeaders...)
	mu.Unlock()

	var sawSession bool
	for _, raw := range headers {
		if strings.Contains(raw, "sid="+sessionValue) {
			sawSession = true
		}
		if strings.Contains(raw, "ambient=planted") {
			t.Fatalf("the comparison request read the shared jar: Cookie: %q", raw)
		}
	}
	if !sawSession {
		t.Fatalf("the non-admin comparison did not carry the explicit saved session; admin-path Cookie headers = %q", headers)
	}

	// A second, ordinary scoped engine on the SAME client — what a second scan
	// builds — must not inherit the cookie the comparison response minted.
	if _, err := other.Do(context.Background(), httpengine.GET(srv.URL+"/capture")); err != nil {
		t.Fatalf("capture request: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captureCookies) != 1 {
		t.Fatalf("expected exactly one capture request, got %d", len(captureCookies))
	}
	for _, leaked := range []string{"comparison-mint=" + comparisonMints, acCookieName + "=" + acCookieValue(1)} {
		if strings.Contains(captureCookies[0], leaked) {
			t.Fatalf("the page-disclosure job stored %q in the shared HTTP client jar; another engine on that client carried it: %q",
				leaked, captureCookies[0])
		}
	}
}

package scan

// Access-control engine tests: the anonymous-vs-non-admin differential
// against real httptest servers, the honesty negatives (a 200 page with no
// privileged action, a path that requires a session, a path that was never
// discovered), evidence retention, correlation and the bounded probe pass.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/ratelimit"
)

const acAdminPanel = `<!doctype html><html><head><title>Admin panel</title></head><body>
<h1>Admin panel</h1>
<h2>User list</h2>
<table>
<tr><th>Username</th><th>Actions</th></tr>
<tr><td>wiener</td><td><a href="/admin/delete?username=wiener">Delete</a></td></tr>
<tr><td>carlos</td><td><a href="/admin/delete?username=carlos">Delete</a></td></tr>
</table>
</body></html>`

const acLoginPage = `<html><body><h1>Sign in</h1>
<form action="/login" method="post"><input name="username"><input type="password" name="password"><button>Log in</button></form>
</body></html>`

func acEndpoint(t *testing.T, env *scanEnv, rawURL string, src domain.DiscoverySource, method domain.HTTPMethod) *domain.Endpoint {
	t.Helper()
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: rawURL, Method: method, Source: src, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

func acJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	return &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobAccessControl,
		Target:   domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
		Attempts: 1, MaxAttempts: 2}
}

func acSessionEngine(t *testing.T) *scopedEngine {
	t.Helper()
	return newScopedEngine(noFollowClient(t), openScope()).WithSessionCookies([]*http.Cookie{
		{Name: "sid", Value: "nonadmin", Domain: "127.0.0.1", Path: "/"},
	})
}

func acCases(t *testing.T, env *scanEnv) []*domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

func acFindings(t *testing.T, env *scanEnv) []*domain.Finding {
	t.Helper()
	fs, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func acDetail(t *testing.T, tc *domain.TestCase) accessControlDetail {
	t.Helper()
	var d accessControlDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("decode access-control detail: %v (detail=%s)", err, tc.Detail)
	}
	return d
}

// TestAccessControlConfirmsAnonymousAdminPanel is the required positive: a
// robots-discovered /admin answers 200 anonymously, exposes a user list and a
// delete-user action, and the authenticated non-admin session is denied.
func TestAccessControlConfirmsAnonymousAdminPanel(t *testing.T) {
	env := newScanEnv(t)
	var mu sync.Mutex
	var requests []string
	var adminCookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.URL.Path == "/admin" {
			adminCookies = append(adminCookies, r.Header.Get("Cookie"))
		}
		mu.Unlock()

		switch r.URL.Path {
		case "/warm":
			// Put a cookie in the engine's jar so the anonymous probe proves
			// it bypasses the jar, not only the session cookie list.
			http.SetCookie(w, &http.Cookie{Name: "pref", Value: "warm", Path: "/"})
			return
		case "/admin":
			if _, err := r.Cookie("sid"); err == nil {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "forbidden")
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acAdminPanel)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/admin", domain.SourceRobots, domain.MethodGET)
	eng := acSessionEngine(t)
	// Warm the jar (the warm request itself may carry the session cookie).
	if _, err := eng.Do(context.Background(), httpengine.GET(srv.URL+"/warm")); err != nil {
		t.Fatal(err)
	}

	ex := newAccessControlExecutor(env.st, eng, env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	cases := acCases(t, env)
	if len(cases) != 1 {
		t.Fatalf("expected 1 access-control test case, got %d", len(cases))
	}
	d := acDetail(t, cases[0])
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if d.AnonymousStatus != 200 || !d.Compared || d.NonAdminStatus != 403 {
		t.Fatalf("differential detail incomplete: %+v", d)
	}
	if len(d.Actions) == 0 {
		t.Fatalf("confirmed detail must name the privileged actions: %+v", d)
	}

	fs := acFindings(t, env)
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.VulnClass != domain.VulnAccessControl || f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = class %q verdict %q, want access_control/confirmed", f.VulnClass, f.Verdict)
	}
	if f.EndpointID != ep.ID || f.Provenance.Engine != "access_control" || f.Provenance.DiscoverySource != domain.SourceRobots {
		t.Fatalf("finding provenance wrong: %+v", f)
	}
	if len(f.EvidenceIDs) < 4 {
		t.Fatalf("finding must reference anonymous AND non-admin request/response evidence, got %d ids", len(f.EvidenceIDs))
	}

	// The anonymous request must have carried NO Cookie header at all, even
	// though the jar held one from /warm and the scan had a session cookie.
	// The comparison request must have carried the session.
	var sawAnonymous, sawAuthenticated bool
	for _, id := range d.AnonymousEvidence {
		row, body := env.evidenceBlob(id)
		if row.Kind != domain.EvidenceRequest {
			continue
		}
		if !strings.Contains(body, "GET /admin") {
			continue
		}
		sawAnonymous = true
		if strings.Contains(body, "Cookie:") {
			t.Fatalf("anonymous probe sent cookies:\n%s", body)
		}
	}
	for _, id := range d.NonAdminEvidence {
		row, body := env.evidenceBlob(id)
		if row.Kind != domain.EvidenceRequest {
			continue
		}
		// The evidence must prove the cookie was sent without persisting the
		// credential itself: the NAME stays, the value is redacted.
		if strings.Contains(body, "Cookie:") && strings.Contains(body, "sid=<redacted>") {
			sawAuthenticated = true
		}
		if strings.Contains(body, "sid=nonadmin") {
			t.Fatalf("raw session cookie value persisted in access-control evidence:\n%s", body)
		}
	}
	if !sawAnonymous {
		t.Fatal("anonymous request evidence not found")
	}
	if !sawAuthenticated {
		t.Fatal("authenticated non-admin request evidence not found")
	}

	// Redaction happens on the persisted copy only: the target itself must
	// still have received the session on the comparison request.
	mu.Lock()
	seenCookies := append([]string(nil), adminCookies...)
	mu.Unlock()
	sawSessionOnWire := false
	for _, raw := range seenCookies {
		if strings.Contains(raw, "sid=nonadmin") {
			sawSessionOnWire = true
		}
	}
	if !sawSessionOnWire {
		t.Fatalf("the non-admin comparison lost the session cookie; target saw %v", seenCookies)
	}

	// Read-only by construction.
	for _, r := range requests {
		if !strings.HasPrefix(r, "GET ") {
			t.Fatalf("access-control engine sent a non-GET request: %s", r)
		}
	}
}

// TestAccessControlRejectsAdminRequiringSession is the required negative: the
// same admin page, but anonymous access is redirected to a login form.
func TestAccessControlRejectsAdminRequiringSession(t *testing.T) {
	env := newScanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			if _, err := r.Cookie("sid"); err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acAdminPanel)
		case "/login":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, acLoginPage)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/admin", domain.SourceRobots, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, acSessionEngine(t), env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q (%s), want rejected", d.Verdict, d.Reason)
	}
	if !strings.Contains(d.Reason, "login") && !strings.Contains(d.Reason, "authentication") {
		t.Fatalf("reason should say authentication is required: %q", d.Reason)
	}
	if fs := acFindings(t, env); len(fs) != 0 {
		t.Fatalf("a session-required admin path must not create a finding: %+v", fs)
	}
}

// TestAccessControlRejects200WithoutPrivilegedAction is the other required
// negative: the page answers 200 anonymously but contains no admin action.
func TestAccessControlRejects200WithoutPrivilegedAction(t *testing.T) {
	env := newScanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body><h1>Admin panel</h1><p>Nothing to see here.</p></body></html>`)
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/admin", domain.SourceRobots, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, acSessionEngine(t), env.ev, ExecutorConfig{}, execLog(), nil, true)
	if err := ex.Handle(context.Background(), acJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q (%s), want rejected", d.Verdict, d.Reason)
	}
	if fs := acFindings(t, env); len(fs) != 0 {
		t.Fatalf("a 200 page with no privileged action must not create a finding: %+v", fs)
	}
}

// TestAccessControlAnonymousScanStillConfirmsMissingAuth: without a session
// there is no non-admin comparison, but anonymous access to a privileged
// action is itself the finding.
func TestAccessControlAnonymousScanStillConfirmsMissingAuth(t *testing.T) {
	env := newScanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, acAdminPanel)
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/admin", domain.SourceSitemap, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev, ExecutorConfig{}, execLog(), nil, false)
	if err := ex.Handle(context.Background(), acJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	d := acDetail(t, acCases(t, env)[0])
	if d.Verdict != domain.VerdictConfirmed || d.Compared {
		t.Fatalf("verdict = %q compared=%v (%s), want confirmed without a comparison", d.Verdict, d.Compared, d.Reason)
	}
	if fs := acFindings(t, env); len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
}

// TestAccessControlCorrelationKeepsOneFinding proves a re-run at the same path
// (a resume re-enqueues the pass) ratchets the existing finding instead of
// duplicating it, and keeps both attempts' evidence.
func TestAccessControlCorrelationKeepsOneFinding(t *testing.T) {
	env := newScanEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, acAdminPanel)
	}))
	defer srv.Close()

	ep := acEndpoint(t, env, srv.URL+"/admin", domain.SourceRobots, domain.MethodGET)
	ex := newAccessControlExecutor(env.st, newScopedEngine(noFollowClient(t), openScope()), env.ev, ExecutorConfig{}, execLog(), nil, false)
	for i := 0; i < 2; i++ {
		if err := ex.Handle(context.Background(), acJob(env, ep)); err != nil {
			t.Fatalf("handle %d: %v", i, err)
		}
	}
	fs := acFindings(t, env)
	if len(fs) != 1 {
		t.Fatalf("expected 1 correlated finding after two runs, got %d", len(fs))
	}
	var d accessControlFindingDetail
	if err := json.Unmarshal(fs[0].Detail, &d); err != nil {
		t.Fatal(err)
	}
	if d.Occurrences != 2 || len(d.TestCaseIDs) != 2 {
		t.Fatalf("correlation did not absorb the second run: %+v", d)
	}
	if len(fs[0].EvidenceIDs) < 4 {
		t.Fatalf("correlated finding lost evidence: %d ids", len(fs[0].EvidenceIDs))
	}
}

// TestEnqueueAccessControlProbesSelectsRobotsAndSitemapAdminPaths covers the
// bounded pass: only GET endpoints discovered by robots/sitemap whose path is
// admin-like become jobs.
func TestEnqueueAccessControlProbesSelectsRobotsAndSitemapAdminPaths(t *testing.T) {
	env := newScanEnv(t)
	q := queue.NewMemory()
	c := &Controller{store: env.st, queue: q, log: execLog()}

	admin := acEndpoint(t, env, "http://127.0.0.1:1/admin", domain.SourceRobots, domain.MethodGET)
	dash := acEndpoint(t, env, "http://127.0.0.1:1/dashboard", domain.SourceSitemap, domain.MethodGET)
	acEndpoint(t, env, "http://127.0.0.1:1/public", domain.SourceRobots, domain.MethodGET)         // not admin-like
	acEndpoint(t, env, "http://127.0.0.1:1/administrator", domain.SourceCrawler, domain.MethodGET) // not robots/sitemap
	acEndpoint(t, env, "http://127.0.0.1:1/admin/delete", domain.SourceRobots, domain.MethodPOST)  // not a read

	c.enqueueAccessControlProbes(context.Background(), env.scanID)

	got := map[string]bool{}
	for {
		j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobAccessControl}, time.Minute)
		if err != nil || j == nil {
			break
		}
		if j.Target.URL == "" || j.Type != domain.JobAccessControl || j.ScanID != env.scanID {
			t.Fatalf("bad job: %+v", j)
		}
		got[j.Target.URL] = true
	}
	if len(got) != 2 || !got[admin.URL] || !got[dash.URL] {
		t.Fatalf("enqueued %v, want exactly %s and %s", got, admin.URL, dash.URL)
	}
}

// TestEnqueueAccessControlProbesNeedsRobotsOrSitemap is the required
// robots.txt-absent negative at the pass level: an admin path that was not
// disclosed is never probed by this engine.
func TestEnqueueAccessControlProbesNeedsRobotsOrSitemap(t *testing.T) {
	env := newScanEnv(t)
	q := queue.NewMemory()
	c := &Controller{store: env.st, queue: q, log: execLog()}
	acEndpoint(t, env, "http://127.0.0.1:1/admin", domain.SourceCrawler, domain.MethodGET)
	acEndpoint(t, env, "http://127.0.0.1:1/users", domain.SourceRobots, domain.MethodGET)

	c.enqueueAccessControlProbes(context.Background(), env.scanID)
	if j, _ := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobAccessControl}, time.Minute); j != nil {
		t.Fatalf("no access-control job may be enqueued for an undisclosed or non-admin path: %+v", j)
	}
}

// TestJobAccessControlIsWiredToTheHTTPGroup mirrors the IDOR wiring gate: the
// job type must be leased by the ordinary HTTP group and dispatched to the
// real handler.
func TestJobAccessControlIsWiredToTheHTTPGroup(t *testing.T) {
	env := newScanEnv(t)
	c := &Controller{store: env.st, log: execLog()}
	sc := &domain.Scan{Config: domain.ScanConfig{DiscoveryConcurrency: 1, HTTPConcurrency: 2, BrowserConcurrency: 1}}

	found := false
	for _, g := range c.poolConfig(sc).Groups {
		for _, ty := range g.Types {
			if ty != domain.JobAccessControl {
				continue
			}
			found = true
			if g.Name != GroupHTTP {
				t.Fatalf("JobAccessControl is routed to group %q, want %q", g.Name, GroupHTTP)
			}
		}
	}
	if !found {
		t.Fatal("JobAccessControl is not in any worker group: queued jobs would never be leased")
	}
	h := c.defaultHandlers(nil, openScope(), nil, ratelimit.New(0), nil)
	if _, ok := h[domain.JobAccessControl].(*accessControlExecutor); !ok {
		t.Fatalf("JobAccessControl handler = %T, want the real accessControlExecutor", h[domain.JobAccessControl])
	}
}

package discovery_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newCollector(t *testing.T, cfg discovery.Config) (*discovery.Collector, *memory.Store, *queue.Memory, domain.ID) {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	c := discovery.NewCollector(st, q, scanID, scope, false, cfg, quiet())
	return c, st, q, scanID
}

// newAuthenticatedCollector is newCollector's counterpart for tests of the
// session-terminating-link skip, which only applies to an authenticated scan.
func newAuthenticatedCollector(t *testing.T, cfg discovery.Config) (*discovery.Collector, *memory.Store, *queue.Memory, domain.ID) {
	t.Helper()
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	c := discovery.NewCollector(st, q, scanID, scope, true, cfg, quiet())
	return c, st, q, scanID
}

// A crawler-found link that looks like a logout endpoint must not be
// followed on an authenticated scan — visiting it would end the session the
// scan was specifically given to get past the login wall, silently turning
// every subsequent test unauthenticated. This was found via a real scan
// against DVWA: its nav bar's "Logout" link got crawled (even under -quick,
// which still follows links one hop from the seed page) and killed the
// session mid-scan, so the actually-interesting authenticated-only finding
// came back Inconclusive instead of Confirmed.
func TestCollectorSkipsLogoutLinkOnAuthenticatedScan(t *testing.T) {
	c, _, _, _ := newAuthenticatedCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	for _, u := range []string{
		"http://example.com/logout.php",
		"http://example.com/auth/sign-out",
		"http://example.com/user/log_off",
		"http://example.com/LOGOUT",
	} {
		id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: u, Method: domain.MethodGET, Source: domain.SourceCrawler})
		if err != nil {
			t.Fatalf("AddEndpoint(%q) returned an error, want a silent skip: %v", u, err)
		}
		if id != "" {
			t.Fatalf("AddEndpoint(%q) = %q, want skipped (empty id) on an authenticated scan", u, id)
		}
	}

	// A non-logout-looking link is unaffected.
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/vulnerabilities/xss_r/", Method: domain.MethodGET, Source: domain.SourceCrawler})
	if err != nil || id == "" {
		t.Fatalf("an ordinary crawled link should not be skipped: id=%q err=%v", id, err)
	}
}

// An unauthenticated scan has no session to lose, so nothing is skipped.
func TestCollectorDoesNotSkipLogoutLinkWhenUnauthenticated(t *testing.T) {
	c, _, _, _ := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/logout.php", Method: domain.MethodGET, Source: domain.SourceCrawler})
	if err != nil || id == "" {
		t.Fatalf("an anonymous scan should not skip a logout-looking link: id=%q err=%v", id, err)
	}
}

// An operator-provided seed is explicit intent and is never skipped, even on
// an authenticated scan and even though its URL matches the heuristic.
func TestCollectorNeverSkipsUserProvidedSeedEvenIfLogoutLooking(t *testing.T) {
	c, _, _, _ := newAuthenticatedCollector(t, discovery.DefaultConfig())
	ctx := context.Background()
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/logout.php", Method: domain.MethodGET, Source: domain.SourceUserProvided})
	if err != nil || id == "" {
		t.Fatalf("an explicit user-provided seed must never be skipped: id=%q err=%v", id, err)
	}
}

// --- Header/Cookie/Path injection points ---

// Every endpoint gets the same small, conservative DEFAULT set of Header
// injection points (User-Agent, Referer, X-Forwarded-For), regardless of the
// URL.
func TestCollectorRegistersDefaultHeaderInjectionPoints(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/plain", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	got := map[string]bool{}
	for _, p := range params {
		if p.Location == domain.LocationHeader {
			got[p.Name] = true
		}
	}
	want := []string{"User-Agent", "Referer", "X-Forwarded-For"}
	if len(got) != len(want) {
		t.Fatalf("header injection points = %v, want exactly %v", got, want)
	}
	for _, name := range want {
		if !got[name] {
			t.Fatalf("missing default header injection point %q: got %v", name, got)
		}
	}
}

// Cookie injection points are registered ONLY from the scan's own saved
// session cookies (Config.SessionCookies); scopedEngine scopes each one to
// matching request URLs and redirects. Auth/session cookies are excluded and
// no cookie values are fabricated.
func TestCollectorRegistersCookieInjectionPointsFromSessionExcludingAuthCookie(t *testing.T) {
	cfg := discovery.DefaultConfig()
	cfg.SessionCookies = []*http.Cookie{
		{Name: "PHPSESSID", Value: "abc123"}, // looks like the auth/session cookie: excluded
		{Name: "pref", Value: "orange"},      // an ordinary, non-auth cookie: registered
	}
	c, st, _, scanID := newCollector(t, cfg)
	ctx := context.Background()

	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/plain", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	var cookieParams []*domain.Parameter
	for _, p := range params {
		if p.Location == domain.LocationCookie {
			cookieParams = append(cookieParams, p)
		}
	}
	if len(cookieParams) != 1 || cookieParams[0].Name != "pref" || cookieParams[0].Example != "orange" {
		t.Fatalf("cookie injection points = %+v, want exactly one {pref, orange} (PHPSESSID excluded)", cookieParams)
	}
}

// No session (no SessionCookies) registers zero Cookie injection points —
// never a fabricated one.
func TestCollectorRegistersNoCookieInjectionPointsWithoutSession(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()
	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/plain", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	for _, p := range params {
		if p.Location == domain.LocationCookie {
			t.Fatalf("expected no Cookie injection points with no session, got %+v", p)
		}
	}
}

// A path segment that looks like a value (numeric, UUID, opaque slug with a
// digit) becomes a Path injection point; a literal route keyword never does.
func TestCollectorRegistersPathInjectionPointsHeuristically(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{
		URL: "http://example.com/api/v1/users/42/edit", Method: domain.MethodGET, Source: domain.SourceCrawler,
	}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	var pathParams []*domain.Parameter
	for _, p := range params {
		if p.Location == domain.LocationPath {
			pathParams = append(pathParams, p)
		}
	}
	// Segments: api(0) v1(1) users(2) 42(3) edit(4) — only "42" qualifies.
	if len(pathParams) != 1 || pathParams[0].Example != "42" {
		t.Fatalf("path injection points = %+v, want exactly one for the \"42\" segment", pathParams)
	}
	if idx, ok := discovery.ParsePathSegmentParamName(pathParams[0].Name); !ok || idx != 3 {
		t.Fatalf("path injection point name = %q, want to encode segment index 3", pathParams[0].Name)
	}
}

// An endpoint whose path has no qualifying segment registers zero Path
// injection points.
func TestCollectorRegistersNoPathInjectionPointWithoutQualifyingSegment(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()
	if _, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/api/v1/admin/login", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	for _, p := range params {
		if p.Location == domain.LocationPath {
			t.Fatalf("expected no Path injection points for an all-route-keyword path, got %+v", p)
		}
	}
}

func TestCollectorScopeEnforcement(t *testing.T) {
	c, st, q, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	// In scope → persisted + job.
	id, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/a", Method: domain.MethodGET, Source: domain.SourceCrawler})
	if err != nil || id == "" {
		t.Fatalf("in-scope endpoint should be accepted: id=%q err=%v", id, err)
	}

	// Out of scope → skipped silently (fail closed).
	id, err = c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://evil.com/a", Method: domain.MethodGET, Source: domain.SourceCrawler})
	if err != nil {
		t.Fatalf("out-of-scope should not error: %v", err)
	}
	if id != "" {
		t.Fatal("out-of-scope endpoint must be skipped")
	}

	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	if len(eps) != 1 || eps[0].URL != "http://example.com/a" {
		t.Fatalf("only the in-scope endpoint should persist: %+v", eps)
	}
	stats, _ := q.Stats(ctx, scanID)
	// one endpoint-level job + 3 default Header injection-point jobs
	// (User-Agent/Referer/X-Forwarded-For — see registerHeaderInjectionPoints).
	if stats.Queued != 4 {
		t.Fatalf("expected 4 queued jobs, got %+v", stats)
	}
}

func TestCollectorDeduplicates(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	id1, _ := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/dup", Method: domain.MethodGET, Source: domain.SourceCrawler})
	id2, _ := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/dup", Method: domain.MethodGET, Source: domain.SourceCrawler})
	// Same path, different query VALUE → still the same endpoint.
	id3, _ := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/dup", Method: domain.MethodGET, Source: domain.SourceCrawler})

	if id1 != id2 || id1 != id3 {
		t.Fatalf("duplicate endpoints should resolve to the same ID: %s %s %s", id1, id2, id3)
	}
	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint after dedup, got %d", len(eps))
	}
	e, p, _ := c.Counts()
	if e != 1 {
		t.Fatalf("endpoint count = %d, want 1", e)
	}
	_ = p
}

func TestCollectorQueryParamsBecomeInjectionPoints(t *testing.T) {
	c, st, q, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	_, err := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/search?q=hello&page=2", Method: domain.MethodGET, Source: domain.SourceCrawler})
	if err != nil {
		t.Fatal(err)
	}

	params, _ := st.Parameters().ListByScan(ctx, scanID)
	// 2 query params ("q", "page") + 3 default Header injection points
	// (User-Agent/Referer/X-Forwarded-For).
	if len(params) != 5 {
		t.Fatalf("expected 5 params, got %d", len(params))
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	if len(ips) != 5 {
		t.Fatalf("expected 5 injection points, got %d", len(ips))
	}
	// 1 endpoint job + 2 query injection-point jobs + 3 header injection-point jobs.
	stats, _ := q.Stats(ctx, scanID)
	if stats.Queued != 6 {
		t.Fatalf("expected 6 queued jobs, got %+v", stats)
	}
}

func TestCollectorAddParameterAutoCreatesEndpoint(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	err := c.AddParameter(ctx, discovery.ParamCandidate{
		EndpointURL:    "http://example.com/submit",
		EndpointMethod: domain.MethodPOST,
		Name:           "comment",
		Location:       domain.LocationForm,
		Source:         domain.SourceForm,
	})
	if err != nil {
		t.Fatal(err)
	}
	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	if len(eps) != 1 {
		t.Fatalf("expected endpoint auto-created, got %d", len(eps))
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	// "comment" (form) + 3 default Header injection points registered when
	// AddParameter auto-created the endpoint.
	if len(params) != 4 {
		t.Fatalf("expected 4 params, got %d", len(params))
	}
	var comment *domain.Parameter
	for _, p := range params {
		if p.Name == "comment" {
			comment = p
		}
	}
	if comment == nil || comment.Location != domain.LocationForm {
		t.Fatalf("param not registered correctly: %+v", params)
	}
}

func TestCollectorLimit(t *testing.T) {
	cfg := discovery.DefaultConfig()
	cfg.MaxEndpoints = 2
	c, _, _, _ := newCollector(t, cfg)
	ctx := context.Background()

	_, err1 := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/1", Method: domain.MethodGET, Source: domain.SourceCrawler})
	_, err2 := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/2", Method: domain.MethodGET, Source: domain.SourceCrawler})
	_, err3 := c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/3", Method: domain.MethodGET, Source: domain.SourceCrawler})

	if err1 != nil || err2 != nil {
		t.Fatalf("first two should succeed: %v %v", err1, err2)
	}
	if !errors.Is(err3, discovery.ErrLimitReached) {
		t.Fatalf("third should hit limit, got %v", err3)
	}
	e, _, _ := c.Counts()
	if e != 2 {
		t.Fatalf("endpoint count should cap at 2, got %d", e)
	}
}

func TestCollectorPreservesProvenance(t *testing.T) {
	c, st, _, scanID := newCollector(t, discovery.DefaultConfig())
	ctx := context.Background()

	_, _ = c.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/x", Method: domain.MethodGET, Source: domain.SourceSitemap})
	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	if len(eps) != 1 || eps[0].Source != domain.SourceSitemap {
		t.Fatalf("provenance not preserved: %+v", eps)
	}
}

// TestCollectorHydrateAvoidsDuplicatesAfterRestart simulates a restart: a second
// collector over the same store must recognize everything the first persisted,
// creating no duplicate endpoints, parameters, or jobs.
func TestCollectorHydrateAvoidsDuplicatesAfterRestart(t *testing.T) {
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	ctx := context.Background()

	first := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if _, err := first.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/s?q=1", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	if err := first.AddParameter(ctx, discovery.ParamCandidate{EndpointURL: "http://example.com/post", EndpointMethod: domain.MethodPOST, Name: "body", Location: domain.LocationForm, Source: domain.SourceForm}); err != nil {
		t.Fatal(err)
	}
	before, _ := q.Stats(ctx, scanID)
	e1, p1, _ := first.Counts()

	// "Restart": brand-new collector, same store and queue.
	second := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if err := second.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Hydrate(ctx); err != nil { // idempotent
		t.Fatal(err)
	}
	e2, p2, _ := second.Counts()
	if e2 != e1 || p2 != p1 {
		t.Fatalf("hydrated counts differ: endpoints %d vs %d, params %d vs %d", e2, e1, p2, p1)
	}

	// Re-discovering the same items must now be a no-op.
	_, _ = second.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/s?q=2", Method: domain.MethodGET, Source: domain.SourceCrawler})
	_ = second.AddParameter(ctx, discovery.ParamCandidate{EndpointURL: "http://example.com/post", EndpointMethod: domain.MethodPOST, Name: "body", Location: domain.LocationForm, Source: domain.SourceForm})

	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	after, _ := q.Stats(ctx, scanID)
	if len(eps) != e1 || len(params) != p1 {
		t.Fatalf("duplicates persisted after hydrate: endpoints=%d (want %d) params=%d (want %d)", len(eps), e1, len(params), p1)
	}
	if after.Total() != before.Total() {
		t.Fatalf("duplicate jobs enqueued after hydrate: %d -> %d", before.Total(), after.Total())
	}
}

// failingEnqueue simulates a shutdown landing between a collector's persist
// and enqueue steps: every Enqueue fails as if the run context were canceled.
type failingEnqueue struct{ queue.Queue }

func (failingEnqueue) Enqueue(context.Context, *domain.TestJob) error { return context.Canceled }

// jobTargets returns, per injection point (or "endpoint:<id>" for an
// endpoint-level job), how many JobTest jobs target it.
func jobTargets(t *testing.T, q queue.Queue, scanID domain.ID) map[string]int {
	t.Helper()
	jobs, err := q.Jobs(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, j := range jobs {
		if j.Target.InjectionPointID.Empty() {
			out["endpoint:"+string(j.Target.EndpointID)]++
		} else {
			out[string(j.Target.InjectionPointID)]++
		}
	}
	return out
}

// Regression for the restart-recovery completion bug: an endpoint + parameter
// + injection point persisted by a run that was interrupted before their test
// jobs were enqueued must get those jobs on the next run's Hydrate. Before the
// fix, Hydrate only marked them "seen", so they were never tested and the scan
// completed anyway (TestE2E_RestartRecoversInterruptedVerification: "expected
// exactly one finding ... got 0").
func TestCollectorHydrateEnqueuesJobsLostToInterruption(t *testing.T) {
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	ctx := context.Background()

	first := discovery.NewCollector(st, failingEnqueue{q}, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if _, err := first.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/s?q=1", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	// 1 query injection point ("q") + 3 default Header injection points.
	if len(ips) != 4 {
		t.Fatalf("setup: want 4 persisted injection points, got %d", len(ips))
	}
	if st, _ := q.Stats(ctx, scanID); st.Total() != 0 {
		t.Fatalf("setup: interrupted run must have enqueued nothing, got %+v", st)
	}

	second := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	for i := 0; i < 2; i++ { // second pass proves idempotence
		if err := second.Hydrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	got := jobTargets(t, q, scanID)
	want := map[string]int{"endpoint:" + string(eps[0].ID): 1}
	for _, ip := range ips {
		want[string(ip.ID)] = 1
	}
	if len(got) != len(want) {
		t.Fatalf("reconciled jobs = %v, want exactly %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("reconciled jobs = %v, want exactly %v", got, want)
		}
	}
}

// An endpoint persisted without its own query parameters (interrupted right
// after the endpoint row was written) gets them — parameter, injection point,
// and job — on Hydrate. Re-adding the endpoint alone cannot do this: the dedup
// check returns early for a known endpoint.
func TestCollectorHydrateRegistersMissingQueryParams(t *testing.T) {
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	ctx := context.Background()

	info, err := discovery.Normalize("http://example.com/s?q=1")
	if err != nil {
		t.Fatal(err)
	}
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: info.Canonical, Method: domain.MethodGET,
		Source: domain.SourceCrawler, Fingerprint: discovery.EndpointKey(domain.MethodGET, info)}
	if err := st.Endpoints().Create(ctx, ep); err != nil {
		t.Fatal(err)
	}

	c := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if err := c.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	// "q" (the missing query param) + 3 default Header injection points,
	// all registered by the same Hydrate/reconcile pass.
	if len(params) != 4 {
		t.Fatalf("expected 4 params after hydrate, got %d: %+v", len(params), params)
	}
	var q1 *domain.Parameter
	for _, p := range params {
		if p.Name == "q" {
			q1 = p
		}
	}
	if q1 == nil || q1.Example != "1" || q1.Source != domain.SourceCrawler {
		t.Fatalf("missing query parameter not registered correctly: %+v", params)
	}
	if len(ips) != 4 {
		t.Fatalf("expected 4 injection points after hydrate, got %d", len(ips))
	}
	got := jobTargets(t, q, scanID)
	if len(got) != 5 || got["endpoint:"+string(ep.ID)] != 1 { // endpoint job + 4 injection-point jobs
		t.Fatalf("jobs = %v, want one endpoint job and one job per injection point (5 total)", got)
	}
	for _, ip := range ips {
		if got[string(ip.ID)] != 1 {
			t.Fatalf("injection point %s has %d jobs, want 1 (jobs=%v)", ip.ID, got[string(ip.ID)], got)
		}
	}
}

// A parameter persisted without its injection point gets one (and its job).
func TestCollectorHydrateCreatesMissingInjectionPoint(t *testing.T) {
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	ctx := context.Background()

	first := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if err := first.AddParameter(ctx, discovery.ParamCandidate{EndpointURL: "http://example.com/post", EndpointMethod: domain.MethodPOST, Name: "body", Location: domain.LocationForm, Source: domain.SourceForm}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	// Simulate the interruption: a second parameter row with no injection point.
	orphan := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: params[0].EndpointID, Name: "extra", Location: domain.LocationForm, Source: domain.SourceForm}
	if err := st.Parameters().Create(ctx, orphan); err != nil {
		t.Fatal(err)
	}

	second := discovery.NewCollector(st, q, scanID, scope, false, discovery.DefaultConfig(), quiet())
	if err := second.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	// "body" (form) + 3 default Header injection points (from the
	// AddParameter-triggered AddEndpoint auto-create) + 1 reconciled
	// injection point for the orphaned "extra" param.
	if len(ips) != 5 {
		t.Fatalf("want 5 injection points (4 original + 1 reconciled), got %d", len(ips))
	}
	got := jobTargets(t, q, scanID)
	for _, ip := range ips {
		if got[string(ip.ID)] != 1 {
			t.Fatalf("injection point %s has %d jobs, want 1 (jobs=%v)", ip.ID, got[string(ip.ID)], got)
		}
	}
}

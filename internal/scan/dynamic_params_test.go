package scan

// End-to-end proof of the single-use anti-CSRF token refresh (see
// dynamic_params.go): a server that rejects any request whose token doesn't
// match its current one, and rotates that token on every accepted request —
// exactly DVWA's "impossible" level xss_r behavior, and the scenario that
// motivated this file.

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
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// csrfServer mimics a form that embeds a rotating, single-use token: a
// request carrying the name parameter is treated as a real submission (and
// is rejected, without reflecting name, unless its token matches the
// server's current one — after which the token rotates); a request with no
// name parameter is a plain page view that shows the current token without
// consuming it. generateSessionToken-style rotation only happens on an
// ACCEPTED submission, matching DVWA.
type csrfServer struct {
	mu    sync.Mutex
	token string
	n     int
	// primeDelay, when set, sleeps before answering a plain page view (the
	// priming fetch) — widens the window between "read the current token"
	// and "spend it" enough that concurrent, unserialized callers reliably
	// observe the race instead of winning it by sheer scheduling luck.
	primeDelay time.Duration
}

func (s *csrfServer) server(t *testing.T) *httptest.Server {
	t.Helper()
	s.token = "token-0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !q.Has("name") && s.primeDelay > 0 {
			time.Sleep(s.primeDelay)
		}
		s.mu.Lock()
		current := s.token
		s.mu.Unlock()
		if !q.Has("name") {
			// Plain page view: show the current token, don't consume it.
			fmt.Fprintf(w, `<form method="GET"><input name="name"><input type="hidden" name="token" value="%s"></form>`, current)
			return
		}
		if q.Get("token") != current {
			io.WriteString(w, `<p>CSRF token is incorrect</p>`)
			return
		}
		s.mu.Lock()
		s.n++
		s.token = fmt.Sprintf("token-%d", s.n)
		s.mu.Unlock()
		fmt.Fprintf(w, `<p>Hello %s</p><input type="hidden" name="token" value="%s">`, q.Get("name"), s.token)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Without refreshDynamicParams, a reflection test built with a stale
// discovery-time token example would get "CSRF token is incorrect" instead
// of ever reaching the reflecting code — reading as "not reflected" even
// though nothing about the parameter's handling was actually exercised.
func TestReflectionSucceedsWithStaleCSRFTokenViaRefresh(t *testing.T) {
	s := &csrfServer{}
	srv := s.server(t)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	// Deliberately stale: discovery captured this long ago; the server's
	// CURRENT token ("token-0") is different.
	env.param(ep, "token", domain.LocationQuery, "stale-token-from-discovery")
	ip := env.injection(ep, name)

	tc, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("outcome = %s, want success", tc.Outcome)
	}
	if !rep.Reflected {
		t.Fatal("expected the marker to reflect once the stale token was refreshed to the server's current one")
	}
}

// Same proof one layer up: the candidate-testing phase (runCandidate, run
// via a JobTest carrying a candidate payload) must also refresh — it builds
// an entirely separate request from the reflection phase, so reusing even
// the reflection phase's own (already-rotated) token would still be stale
// by the time the candidate fires.
func TestCandidateTestingSucceedsWithStaleCSRFTokenViaRefresh(t *testing.T) {
	s := &csrfServer{}
	srv := s.server(t)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	env.param(ep, "token", domain.LocationQuery, "stale-token-from-discovery")
	ip := env.injection(ep, name)

	m := marker(env.scanID, ip.ID)
	value := "<svg onload=" + m + ">"
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value, Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)

	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	out := env.only()
	if out.Outcome != domain.OutcomeSuccess {
		t.Fatalf("outcome = %s", out.Outcome)
	}
	rep := detailReport(t, out)
	if !rep.Reflected || !strings.Contains(out.Note, "reflected at") {
		t.Fatalf("expected the candidate to reflect once the stale token was refreshed; reflected=%v note=%q", rep.Reflected, out.Note)
	}
}

// The endpoint URL itself may already carry a stale token (discovery found a
// link such as /?token=old). The refreshed value must replace it: keeping the
// URL's copy sends the stale token, the server answers "CSRF token is
// incorrect", and the miss reads as "not reflected" without ever exercising
// the parameter under test.
func TestReflectionRefreshReplacesStaleTokenAlreadyInEndpointURL(t *testing.T) {
	s := &csrfServer{}
	srv := s.server(t)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/?token=stale-token-in-url", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	env.param(ep, "token", domain.LocationQuery, "stale-token-in-url")
	ip := env.injection(ep, name)

	tc, rep := reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("outcome = %s, want success", tc.Outcome)
	}
	if !rep.Reflected {
		t.Fatal("the refreshed token must replace the stale one already present in the endpoint URL")
	}
}

func TestCandidateRefreshReplacesStaleTokenAlreadyInEndpointURL(t *testing.T) {
	s := &csrfServer{}
	srv := s.server(t)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/?token=stale-token-in-url", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	env.param(ep, "token", domain.LocationQuery, "stale-token-in-url")
	ip := env.injection(ep, name)

	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := env.only()
	rep := detailReport(t, out)
	if !rep.Reflected || !strings.Contains(out.Note, "reflected at") {
		t.Fatalf("expected the candidate to reflect with the refreshed token; reflected=%v note=%q", rep.Reflected, out.Note)
	}
}

// Control: only dynamic-looking names are replaced. An ordinary query value
// already present in the endpoint URL stays the observed one.
func TestRefreshDoesNotOverrideOrdinaryQueryValueInEndpointURL(t *testing.T) {
	var seen sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store("mode", r.URL.Query().Get("mode"))
		fmt.Fprintf(w, `<form method="GET"><input name="name"><input name="mode" value="discovery-example"><input type="hidden" name="token" value="fresh"></form><p>%s</p>`, r.URL.Query().Get("name"))
	}))
	t.Cleanup(srv.Close)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/?mode=observed-in-url", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	env.param(ep, "mode", domain.LocationQuery, "discovery-example")
	env.param(ep, "token", domain.LocationQuery, "stale")
	ip := env.injection(ep, name)

	reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if got, _ := seen.Load("mode"); got != "observed-in-url" {
		t.Fatalf("an ordinary value already in the URL must stay the observed one, got %v", got)
	}
}

// A hidden token field that a script fills in later has an empty value in the
// served HTML. The empty refreshed value must not erase a token the endpoint
// URL already carries.
func TestRefreshEmptyTokenDoesNotEraseTokenInEndpointURL(t *testing.T) {
	var seen sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("name") {
			seen.Store("token", r.URL.Query().Get("token"))
			fmt.Fprintf(w, "<p>%s</p>", r.URL.Query().Get("name"))
			return
		}
		fmt.Fprint(w, `<form method="GET"><input name="name"><input type="hidden" name="token" value=""></form>`)
	}))
	t.Cleanup(srv.Close)

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/?token=url-token", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "obs")
	env.param(ep, "token", domain.LocationQuery, "url-token")
	ip := env.injection(ep, name)

	reflectReport(t, env, ExecutorConfig{}, env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}))
	if got, _ := seen.Load("token"); got != "url-token" {
		t.Fatalf("an empty refreshed token erased the one in the endpoint URL, server saw %q", got)
	}
}

// --- unit-level: isDynamicTokenName / refreshDynamicParams ---

func TestIsDynamicTokenName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"user_token", true},
		{"csrf_token", true},
		{"csrfmiddlewaretoken", true},
		{"_token", true},
		{"authenticity_token", true},
		{"__RequestVerificationToken", true},
		{"xsrf-token", true},
		{"nonce", true},
		{"CSRF", true},
		// Ordinary, non-dynamic parameters must not match.
		{"name", false},
		{"id", false},
		{"q", false},
		{"page", false},
		{"email", false},
	}
	for _, c := range cases {
		if got := isDynamicTokenName(c.name); got != c.want {
			t.Errorf("isDynamicTokenName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// No parameter looks dynamic → refreshDynamicParams must not fetch anything
// (no extra request, no behavior change) and must return the exact same
// slice values.
func TestRefreshDynamicParamsSkipsFetchWhenNothingLooksDynamic(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "hello")
	page := env.param(ep, "page", domain.LocationQuery, "2")

	out := refreshDynamicParams(context.Background(), scopedClient(t, openScope()), 5e9, ep, []*domain.Parameter{q, page}, q)
	if hits != 0 {
		t.Fatalf("expected no priming fetch, got %d request(s)", hits)
	}
	if len(out) != 2 || out[0] != q || out[1] != page {
		t.Fatalf("params should be returned unchanged: %+v", out)
	}
}

// A priming fetch that fails (connection error, here via an endpoint whose
// host nothing is listening on) must leave params unchanged — best-effort,
// never fatal to the caller.
func TestRefreshDynamicParamsBestEffortOnFetchFailure(t *testing.T) {
	env := newExecEnv(t)
	ep := env.endpoint("http://127.0.0.1:1/", domain.MethodGET) // nothing listens here
	name := env.param(ep, "name", domain.LocationQuery, "hello")
	tok := env.param(ep, "token", domain.LocationQuery, "stale")

	out := refreshDynamicParams(context.Background(), scopedClient(t, domain.Scope{IncludeHosts: []string{"127.0.0.1"}}), 2e8, ep, []*domain.Parameter{name, tok}, name)
	if len(out) != 2 || out[1].Example != "stale" {
		t.Fatalf("a failed priming fetch must leave params unchanged: %+v", out)
	}
}

// eng == nil (a scan/test with no HTTP engine wired) must not panic and must
// return params unchanged.
func TestRefreshDynamicParamsNilEngine(t *testing.T) {
	env := newExecEnv(t)
	ep := env.endpoint("http://example.com/", domain.MethodGET)
	name := env.param(ep, "name", domain.LocationQuery, "hello")
	tok := env.param(ep, "token", domain.LocationQuery, "stale")

	out := refreshDynamicParams(context.Background(), nil, 5e9, ep, []*domain.Parameter{name, tok}, name)
	if len(out) != 2 || out[1].Example != "stale" {
		t.Fatalf("a nil engine must leave params unchanged: %+v", out)
	}
}

// The focus parameter is never "refreshed", even when its own name matches
// the dynamic-token heuristic — its value for this request is the
// injection, decided by the caller, not something this helper should touch.
func TestRefreshDynamicParamsNeverTouchesFocus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<input type="hidden" name="csrf_token" value="fresh-value">`)
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)
	// The parameter under test itself happens to be named like a token.
	focus := env.param(ep, "csrf_token", domain.LocationQuery, "original-value")

	out := refreshDynamicParams(context.Background(), scopedClient(t, openScope()), 5e9, ep, []*domain.Parameter{focus}, focus)
	if out[0].Example != "original-value" {
		t.Fatalf("focus parameter must be left untouched, got %q", out[0].Example)
	}
}

// --- concurrency: the race withDynamicTokenLock exists to close ---

// runConcurrentCandidates fires n concurrent refresh→build→send sequences —
// exactly what n candidates verifying/testing the same injection point do —
// against a single-use-token server, each under withDynamicTokenLock(mu, …).
// Returns how many got a clean "Hello <name>" back (as opposed to the
// server's own "CSRF token is incorrect" rejection).
func runConcurrentCandidates(t *testing.T, mu *sync.Mutex, n int, primeDelay time.Duration) int {
	t.Helper()
	s := &csrfServer{primeDelay: primeDelay}
	srv := s.server(t)
	eng := scopedClient(t, openScope())
	ep := &domain.Endpoint{URL: srv.URL + "/", Method: domain.MethodGET}
	name := &domain.Parameter{ID: domain.NewID(), Name: "name", Location: domain.LocationQuery, Example: "obs"}
	tok := &domain.Parameter{ID: domain.NewID(), Name: "token", Location: domain.LocationQuery, Example: "stale-from-discovery"}
	params := []*domain.Parameter{name, tok}

	var wg sync.WaitGroup
	var mu2 sync.Mutex
	ok := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			withDynamicTokenLock(mu, params, name, func() {
				fresh := refreshDynamicParams(context.Background(), eng, 5e9, ep, params, name)
				req, err := buildRequest(ep, fresh, &injection{param: name, value: "v" + strconv.Itoa(i)})
				if err != nil {
					return
				}
				resp, err := eng.Do(context.Background(), req)
				if err != nil {
					return
				}
				if !strings.Contains(string(resp.Body), "CSRF token is incorrect") {
					mu2.Lock()
					ok++
					mu2.Unlock()
				}
			})
		}(i)
	}
	wg.Wait()
	return ok
}

// With the shared lock held across the entire refresh→build→send sequence,
// every one of n concurrent candidates against the same single-use-token
// endpoint succeeds — none can read the current token only to have a
// sibling spend it first.
func TestWithDynamicTokenLockSerializesConcurrentRequests(t *testing.T) {
	const n = 8
	mu := &sync.Mutex{}
	if got := runConcurrentCandidates(t, mu, n, 5*time.Millisecond); got != n {
		t.Fatalf("%d/%d concurrent requests succeeded with the lock held; want all %d", got, n, n)
	}
}

// Sanity check that the above is actually proving something: WITHOUT a
// shared lock (mu=nil — withDynamicTokenLock then runs every sequence
// unlocked), the same concurrent load against the same single-use-token
// server does NOT reliably succeed — confirming the lock is what closes the
// race, not an artifact of the test server or low concurrency.
func TestWithoutDynamicTokenLockConcurrentRequestsRace(t *testing.T) {
	const n = 8
	if got := runConcurrentCandidates(t, nil, n, 5*time.Millisecond); got >= n {
		t.Fatalf("expected the unlocked run to lose at least one request to the race (got all %d succeed) — "+
			"either the race window is too narrow for this environment or withDynamicTokenLock silently always locks", got)
	}
}

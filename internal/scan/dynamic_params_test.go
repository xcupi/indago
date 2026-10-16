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
	"strings"
	"sync"
	"testing"

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
}

func (s *csrfServer) server(t *testing.T) *httptest.Server {
	t.Helper()
	s.token = "token-0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
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

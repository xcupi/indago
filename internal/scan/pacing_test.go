package scan

// White-box tests for pacing at the scope-enforcing engine: every request the
// scan's HTTP side sends (discovery fetches, redirect hops, raw test requests)
// takes a permit from the scan's one limiter, after the scope check.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/ratelimit"
	"github.com/indago/indago/internal/verification"
)

type arrivalRecorder struct {
	mu sync.Mutex
	at []time.Time
}

func (a *arrivalRecorder) add() {
	a.mu.Lock()
	a.at = append(a.at, time.Now())
	a.mu.Unlock()
}

func (a *arrivalRecorder) gaps() []time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []time.Duration
	for i := 1; i < len(a.at); i++ {
		out = append(out, a.at[i].Sub(a.at[i-1]))
	}
	return out
}

func minDur(ds []time.Duration) time.Duration {
	m := time.Duration(1<<63 - 1)
	for _, d := range ds {
		if d < m {
			m = d
		}
	}
	return m
}

func pacedTestServer(t *testing.T, rec *arrivalRecorder) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		rec.add()
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		rec.add()
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func loopbackScope() domain.Scope {
	return domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
}

// Discovery fetches and raw test requests go through the same paced engine.
func TestScopedEnginePacesEveryRequest(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	eng := newScopedEngine(noFollowClient(t), loopbackScope()).WithRateLimiter(ratelimit.New(10)) // 100ms
	for i := 0; i < 4; i++ {
		if _, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if g := minDur(rec.gaps()); g < 90*time.Millisecond {
		t.Fatalf("min gap between requests = %v, want >= 90ms at 10 rps (gaps %v)", g, rec.gaps())
	}
}

// Each redirect hop is a request and takes its own permit.
func TestScopedEnginePacesRedirectHops(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	eng := newScopedEngine(noFollowClient(t), loopbackScope()).WithRateLimiter(ratelimit.New(10))
	resp, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/hop"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.FinalURL != srv.URL+"/ok" {
		t.Fatalf("final url = %q", resp.FinalURL)
	}
	// /hop arrival, then /ok arrival (the redirect hop): one permit each.
	if len(rec.at) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(rec.at))
	}
	if g := rec.at[1].Sub(rec.at[0]); g < 90*time.Millisecond {
		t.Fatalf("redirect hop gap = %v, want >= 90ms", g)
	}
}

// The scope gate runs BEFORE pacing: an out-of-scope request is refused
// immediately and must not consume a permit that an in-scope request needs.
func TestScopedEngineScopeCheckedBeforePacing(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	eng := newScopedEngine(noFollowClient(t), domain.Scope{IncludeHosts: []string{"other.invalid"}}).
		WithRateLimiter(ratelimit.New(2)) // 500ms interval
	for i := 0; i < 5; i++ {
		if _, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"}); err == nil {
			t.Fatal("out-of-scope request was sent")
		}
	}
	if len(rec.at) != 0 {
		t.Fatalf("out-of-scope requests reached the server: %d", len(rec.at))
	}
}

// rps=0 is unlimited: no delay between requests.
func TestScopedEngineUnlimitedWhenRateZero(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	eng := newScopedEngine(noFollowClient(t), loopbackScope()).WithRateLimiter(ratelimit.New(0))
	start := time.Now()
	for i := 0; i < 20; i++ {
		if _, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20 requests at rps=0 took %v", d)
	}
	if g := minDur(rec.gaps()); g > 90*time.Millisecond && len(rec.gaps()) > 0 {
		// Loose bound: unlimited must not add a fixed 100ms pacing gap.
		t.Fatalf("rps=0 introduced a %v gap", g)
	}
}

// SetRate on the shared limiter reaches the engine after the call.
func TestScopedEngineHonoursSetRateAfterStart(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	l := ratelimit.New(0)
	eng := newScopedEngine(noFollowClient(t), loopbackScope()).WithRateLimiter(l)
	for i := 0; i < 2; i++ {
		if _, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"}); err != nil {
			t.Fatal(err)
		}
	}
	l.SetRate(10)
	mark := len(rec.at)
	for i := 0; i < 4; i++ {
		if _, err := eng.Do(context.Background(), &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"}); err != nil {
			t.Fatal(err)
		}
	}
	post := rec.at[mark:]
	for i := 1; i < len(post); i++ {
		if g := post[i].Sub(post[i-1]); g < 90*time.Millisecond {
			t.Fatalf("after SetRate(10), gap %d = %v, want >= 90ms", i, g)
		}
	}
}

// Browser verification navigations take the scan's shared limiter.
func TestVerifyPassesRateLimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	f := env.pendingFinding(ep, ip)

	fv := &fakeVerifier{result: confirmedResult(verification.SignalPageError)}
	lim := ratelimit.New(2)
	vx := newVerifyExecutor(env.st, nil, fv, env.ev, domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/s"}}, ExecutorConfig{}, execLog(), nil, nil, nil, lim)
	job := env.verifyJobFor(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, basicCandidate(), f.ID)
	if err := vx.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if got := fv.lastInput().Limiter; got != lim {
		t.Fatalf("verification input limiter = %p, want the scan's limiter %p", got, lim)
	}
}

// A request's timeout bounds its own network time, not its wait for a permit.
// Here the second request waits ~500ms for its permit (2 rps) under a 100ms
// request timeout; it must still succeed, not be classified as a TIMEOUT for a
// request that was never sent.
func TestPacingWaitDoesNotConsumeRequestTimeout(t *testing.T) {
	rec := &arrivalRecorder{}
	srv := pacedTestServer(t, rec)
	eng := newScopedEngine(noFollowClient(t), loopbackScope()).WithRateLimiter(ratelimit.New(2))
	ex := newExecutor(nil, eng, nil, nil, ExecutorConfig{RequestTimeout: 100 * time.Millisecond}, execLog(), nil, nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, outcome, err, _ := ex.send(ctx, &httpengine.Request{Method: "GET", URL: srv.URL + "/ok"})
		if outcome != domain.OutcomeSuccess {
			t.Fatalf("request %d outcome = %s (err %v); the permit wait must not count against RequestTimeout", i, outcome, err)
		}
	}
}

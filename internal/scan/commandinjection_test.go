package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

var commandExpr = regexp.MustCompile(`indago([0-9]+)\$\(\((\d+)\*(\d+)\)\)`)

func TestCommandInjectionConfirmsTwoIndependentMarkers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("cmd")
		if m := commandExpr.FindStringSubmatch(value); m != nil {
			a, _ := strconv.Atoi(m[2])
			b, _ := strconv.Atoi(m[3])
			fmt.Fprintf(w, "result indago%s%d", m[1], a*b)
			return
		}
		fmt.Fprint(w, "stock available")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/stock?cmd=1", domain.MethodGET)
	focus := env.param(ep, "cmd", domain.LocationQuery, "1")
	ip := env.injection(ep, focus)
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnCommandInjection || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed command injection", findings)
	}
	if !strings.Contains(findings[0].Title, "cmd") {
		t.Fatalf("finding title = %q, want parameter name", findings[0].Title)
	}
}

func TestCommandInjectionRefreshParamsFromParentForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/feedback" {
			fmt.Fprint(w, `<form action="/feedback/submit" method="POST"><input name="csrf" value="fresh-token"><input name="email"></form>`)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	env := newScanEnv(t)
	action := env.endpoint(srv.URL+"/feedback/submit", domain.MethodPOST)
	page := env.endpoint(srv.URL+"/feedback", domain.MethodGET)
	csrf := env.param(action, "csrf", domain.LocationForm, "stale-token")
	focus := env.param(action, "email", domain.LocationForm, "x@example.com")
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	got := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)
	var fresh string
	for _, p := range got {
		if p.ID == csrf.ID {
			fresh = p.Example
		}
	}
	_ = page
	if fresh != "fresh-token" {
		t.Fatalf("csrf = %q, want fresh token", fresh)
	}
}

func TestCommandInjectionRefreshParamsCachesParentForm(t *testing.T) {
	var otherHits, formHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/other":
			otherHits.Add(1)
			fmt.Fprint(w, `<p>unrelated</p>`)
		case "/feedback":
			n := formHits.Add(1)
			fmt.Fprintf(w, `<form action="/feedback/submit" method="POST"><input name="csrf" value="token-%d"><input name="email"></form>`, n)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	_ = env.endpoint(srv.URL+"/other", domain.MethodGET)
	_ = env.endpoint(srv.URL+"/feedback", domain.MethodGET)
	action := env.endpoint(srv.URL+"/feedback/submit", domain.MethodPOST)
	csrf := env.param(action, "csrf", domain.LocationForm, "stale")
	focus := env.param(action, "email", domain.LocationForm, "x@example.com")

	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	got1 := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)
	otherAfterFirst := otherHits.Load()
	got2 := ex.refreshParams(context.Background(), action, []*domain.Parameter{csrf, focus}, focus)

	if otherAfterFirst > 1 || otherHits.Load() != otherAfterFirst {
		t.Fatalf("otherHits = (%d -> %d), want <= 1 and unchanged on second call", otherAfterFirst, otherHits.Load())
	}
	if formHits.Load() != 2 {
		t.Fatalf("formHits = %d, want 2 (parent form should still rotate)", formHits.Load())
	}
	if got1[0].Example != "token-1" || got2[0].Example != "token-2" {
		t.Fatalf("tokens = (%q, %q), want (token-1, token-2)", got1[0].Example, got2[0].Example)
	}
}

func TestCommandInjectionRefreshParamsSkipsTimedOutAndMissingSources(t *testing.T) {
	var slowHits, unrelatedHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			slowHits.Add(1)
			time.Sleep(150 * time.Millisecond)
			fmt.Fprint(w, "slow")
		case "/unrelated":
			unrelatedHits.Add(1)
			fmt.Fprint(w, "plain")
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	_ = env.endpoint(srv.URL+"/slow", domain.MethodGET)
	_ = env.endpoint(srv.URL+"/unrelated", domain.MethodGET)
	ep1 := env.endpoint(srv.URL+"/api/task1", domain.MethodPOST)
	ep2 := env.endpoint(srv.URL+"/api/task2", domain.MethodPOST)
	tok1 := env.param(ep1, "token", domain.LocationForm, "abc")
	focus1 := env.param(ep1, "target", domain.LocationForm, "1")
	tok2 := env.param(ep2, "token", domain.LocationForm, "abc")
	focus2 := env.param(ep2, "target", domain.LocationForm, "1")

	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{RequestTimeout: 40 * time.Millisecond}, execLog(), nil)
	_ = ex.refreshParams(context.Background(), ep1, []*domain.Parameter{tok1, focus1}, focus1)
	_ = ex.refreshParams(context.Background(), ep1, []*domain.Parameter{tok1, focus1}, focus1)
	_ = ex.refreshParams(context.Background(), ep2, []*domain.Parameter{tok2, focus2}, focus2)

	if slowHits.Load() != 1 {
		t.Fatalf("slowHits = %d, want 1 (timed-out page must not be retried)", slowHits.Load())
	}
	if unrelatedHits.Load() != 2 {
		t.Fatalf("unrelatedHits = %d, want 2 (once for ep1, once for ep2; ep1 second call negatively cached)", unrelatedHits.Load())
	}
}

// A baseline the target refuses before evaluating the parameter must not be
// followed by the bounded payload set: the gate, not the payload, decides the
// response, and recording that as "no output" would read as a negative result
// for a sink that was never reached.
func TestCommandInjectionSkipsProbesWhenBaselineIsDenied(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"status":403,"error":"Forbidden","message":"safety acknowledgement required"}`)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/CommandInjection/task2/run", domain.MethodPOST)
	focus := env.param(ep, "base", domain.LocationForm, "")
	ip := env.injection(ep, focus)
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 (baseline only; a denied baseline must not be probed)", got)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	var got *domain.TestCase
	for _, tc := range cases {
		if tc.VulnClass == domain.VulnCommandInjection {
			got = tc
		}
	}
	if got == nil {
		t.Fatal("no command-injection test case recorded")
	}
	if got.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped (a gated baseline is not a completed test)", got.Status)
	}
	if got.HTTPStatus != http.StatusForbidden {
		t.Fatalf("http_status = %d, want 403", got.HTTPStatus)
	}
	if !strings.Contains(got.Note, "baseline was denied") || !strings.Contains(got.Note, "HTTP 403") {
		t.Fatalf("note = %q, want the gate and status", got.Note)
	}
	if len(got.EvidenceIDs) == 0 {
		t.Fatal("baseline evidence was not attached to the skipped case")
	}
}

// 400 is deliberately NOT a gate: targets commonly reject the baseline's shape
// but process a payload, so the engine must still probe.
func TestCommandInjectionProbesWhenBaselineIsABadRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "bad request")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/search", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "1")
	ip := env.injection(ep, focus)
	ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{AllowStateChanging: true}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}

	if hits.Load() < 2 {
		t.Fatalf("requests = %d, want more than the baseline (a 400 baseline must still be probed)", hits.Load())
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if tc.VulnClass == domain.VulnCommandInjection && tc.Status != domain.TestCaseCompleted {
			t.Fatalf("status = %q, want completed for a 400 baseline", tc.Status)
		}
	}
}

func TestCommandInjectionBaselineGateStatuses(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		if gate, gated := commandInjectionGateFor(status); !gated || gate.Note != "baseline was denied" {
			t.Errorf("status %d = (%+v, %v), want a denied gate", status, gate, gated)
		}
	}
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone} {
		if gate, gated := commandInjectionGateFor(status); !gated || gate.Note != "baseline was unavailable" {
			t.Errorf("status %d = (%+v, %v), want an unavailable gate", status, gate, gated)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError, http.StatusTooManyRequests} {
		if gate, gated := commandInjectionGateFor(status); gated {
			t.Errorf("status %d = gated (%+v), want probed", status, gate)
		}
	}
}

// The output-redirection confirmation writes a marker file into a directory the
// target serves, so it is a persistent side effect and must be gated behind
// AllowStateChanging && !SkipWriteEndpoints. The enabled case is the control:
// it proves the gate, not an early return, is what keeps the requests off the
// wire in the two suppressed cases.
func TestCommandInjectionOutputRedirectionRequiresStateChangingOptIn(t *testing.T) {
	var hits atomic.Int32
	var expected atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(strings.ToLower(r.URL.Path), "image") {
			value, _ := expected.Load().(string)
			fmt.Fprint(w, value)
			return
		}
		// The write payload computes indago<N>$((17*23)); remember what the
		// read of the file it names must return.
		if m := commandExpr.FindStringSubmatch(r.URL.Query().Get("cmd")); m != nil {
			a, _ := strconv.Atoi(m[2])
			b, _ := strconv.Atoi(m[3])
			expected.Store(fmt.Sprintf("indago%s%d", m[1], a*b))
		}
		fmt.Fprint(w, "stock available")
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/product?cmd=1", domain.MethodGET)
	focus := env.param(ep, "cmd", domain.LocationQuery, "1")
	reader := env.endpoint(srv.URL+"/images/show?file=x.jpg", domain.MethodGET)
	env.param(reader, "file", domain.LocationQuery, "x.jpg")

	cases := []struct {
		name    string
		cfg     ExecutorConfig
		enabled bool
	}{
		{"AllowStateChanging off", ExecutorConfig{}, false},
		{"SkipWriteEndpoints on", ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: true}, false},
		{"both opt-ins on", ExecutorConfig{AllowStateChanging: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			expected.Store("")
			ex := newCommandInjectionExecutor(env.st, scopedClient(t, openScope()), env.ev, tc.cfg, execLog(), nil)
			if got := ex.outputRedirectionEnabled(); got != tc.enabled {
				t.Fatalf("outputRedirectionEnabled = %v, want %v", got, tc.enabled)
			}
			job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobCommandInjection}
			d := commandInjectionDetail{}
			got := ex.tryOutputRedirection(context.Background(), job, ep, focus, "1", &d)

			if tc.enabled {
				if !got || hits.Load() == 0 {
					t.Fatalf("tryOutputRedirection = %v with %d requests, want it to run and confirm when both opt-ins are on", got, hits.Load())
				}
				return
			}
			if got {
				t.Fatal("tryOutputRedirection confirmed, want false")
			}
			if hits.Load() != 0 {
				t.Fatalf("requests = %d, want 0: the file-creating probe must not reach the target", hits.Load())
			}
		})
	}
}

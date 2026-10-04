package scan

// Candidate-execution tests: sending one planned candidate per job into its
// injection point, parameter preservation, enqueue/dedup/ordering from a
// reflection job, the state-changing guard, cancellation, persistence/evidence,
// and concurrency — using the real HTTP engine against httptest servers.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// marker returns the injection point's deterministic probe token — the benign
// sentinel a candidate value embeds so re-analysis can find it reflected.
func marker(scanID, ipID domain.ID) string {
	return detection.NewProbe(scanID, ipID).Token
}

// candJob builds a candidate test job carrying cand in its payload.
func (e *execEnv) candJob(target domain.JobTarget, cand detection.Candidate) *domain.TestJob {
	e.t.Helper()
	payload, err := json.Marshal(candidateJob{Candidate: cand})
	if err != nil {
		e.t.Fatal(err)
	}
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: e.scanID, Type: domain.JobTest,
		Target: target, Payload: payload, Attempts: 1, MaxAttempts: 3,
	}
}

func detailReport(t *testing.T, tc *domain.TestCase) *detection.ReflectionReport {
	t.Helper()
	rep, err := detection.ParseReflection(tc.Detail)
	if err != nil {
		t.Fatalf("parse detail: %v", err)
	}
	if rep == nil {
		t.Fatal("test case has no detail report")
	}
	return rep
}

// --- query / form / JSON injection + parameter preservation ---

func TestCandidateInjectionAcrossLocations(t *testing.T) {
	cases := []struct {
		name   string
		method domain.HTTPMethod
		loc    domain.ParamLocation
		allow  bool
	}{
		{"GET query", domain.MethodGET, domain.LocationQuery, false},
		{"POST form", domain.MethodPOST, domain.LocationForm, true},
		{"POST JSON", domain.MethodPOST, domain.LocationJSON, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sawFocus, sawOther []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vals := readParams(r, tc.loc, "q", "page")
				focus, other := vals[0], vals[1]
				mu.Lock()
				sawFocus = append(sawFocus, focus)
				sawOther = append(sawOther, other)
				mu.Unlock()
				// Echo the focus value into an HTML page so re-analysis sees reflection.
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, "<div>"+focus+"</div>")
			}))
			defer srv.Close()

			env := newExecEnv(t)
			ep := env.endpoint(srv.URL+"/s", tc.method)
			focus := env.param(ep, "q", tc.loc, "hello")
			env.param(ep, "page", tc.loc, "2")
			ip := env.injection(ep, focus)

			m := marker(env.scanID, ip.ID)
			value := `"><svg onload=` + m + ">"
			cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Value: value, Priority: 90, DedupKey: "k"}
			job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)

			if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{AllowStateChanging: tc.allow}).Handle(context.Background(), job); err != nil {
				t.Fatalf("handle: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()
			// Two requests: baseline (focus at observed value) and mutated (candidate).
			var sawCandidate, sawObserved bool
			for _, v := range sawFocus {
				switch v {
				case value:
					sawCandidate = true
				case "hello":
					sawObserved = true
				}
			}
			if !sawCandidate {
				t.Fatalf("server never received the candidate value in the focus parameter; saw %q", sawFocus)
			}
			if !sawObserved {
				t.Fatalf("baseline should send the focus parameter at its observed value; saw %q", sawFocus)
			}
			// The other parameter is ALWAYS at its observed value, never the candidate.
			for _, v := range sawOther {
				if v != "2" {
					t.Fatalf("non-focus parameter was altered: %q (want 2); the candidate must touch only its injection point", v)
				}
			}

			out := env.only()
			if out.VulnClass != domain.VulnReflectedXSS || out.Outcome != domain.OutcomeSuccess {
				t.Fatalf("result: vuln=%s outcome=%s", out.VulnClass, out.Outcome)
			}
			rep := detailReport(t, out)
			if rep.Candidate == nil || rep.Candidate.Source != detection.SourceBuiltin || rep.Candidate.Value != value {
				t.Fatalf("detail candidate provenance missing/wrong: %+v", rep.Candidate)
			}
			if rep.Plan != nil {
				t.Fatal("a candidate job must not re-plan candidates")
			}
			if !rep.Reflected || !strings.Contains(out.Note, "reflected at") {
				t.Fatalf("expected a reflected candidate; reflected=%v note=%q", rep.Reflected, out.Note)
			}
		})
	}
}

// readParams extracts several parameter values from one request, reading the
// body at most once (a JSON body cannot be read twice).
func readParams(r *http.Request, loc domain.ParamLocation, names ...string) []string {
	out := make([]string, len(names))
	switch loc {
	case domain.LocationQuery:
		for i, n := range names {
			out[i] = r.URL.Query().Get(n)
		}
	case domain.LocationForm:
		_ = r.ParseForm()
		for i, n := range names {
			out[i] = r.PostFormValue(n)
		}
	case domain.LocationJSON:
		var m map[string]string
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		for i, n := range names {
			out[i] = m[n]
		}
	}
	return out
}

// --- enqueue: one child per candidate, deduplicated, in priority order ---

func TestReflectionEnqueuesCandidatesDeterministically(t *testing.T) {
	// Reflect the marker at TWO html-text sites. The planner makes the same
	// html_text candidates for both and deduplicates them, so there must be ONE
	// child job per unique candidate — never one per site.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+v+"</p><div>"+v+"</div>")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)

	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{})
	parent := env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID})
	if err := ex.Handle(context.Background(), parent); err != nil {
		t.Fatalf("reflection handle: %v", err)
	}

	// The reflection test case recorded a plan; its candidate count must equal the
	// number of enqueued children.
	rep := detailReport(t, env.only())
	if rep.Plan == nil || len(rep.Plan.Candidates) == 0 {
		t.Fatal("reflection produced no plan")
	}
	want := len(rep.Plan.Candidates)

	// Drain the queue: one child per unique candidate, leased in priority order.
	var leased []*domain.TestJob
	for {
		j, err := q.Lease(context.Background(), "t", env.scanID, []domain.JobType{domain.JobTest}, time.Minute)
		if err != nil {
			break
		}
		leased = append(leased, j)
	}
	if len(leased) != want {
		t.Fatalf("enqueued %d candidate jobs, want %d (one per unique candidate)", len(leased), want)
	}

	seen := map[string]bool{}
	lastPriority := int(^uint(0) >> 1) // max int
	for i, j := range leased {
		cand, ok, err := parseCandidateJob(j)
		if err != nil || !ok {
			t.Fatalf("child %d is not a candidate job: ok=%v err=%v", i, ok, err)
		}
		if j.Target.InjectionPointID != ip.ID || j.Target.EndpointID != ep.ID {
			t.Fatalf("child %d lost provenance: %+v", i, j.Target)
		}
		if j.Priority > lastPriority {
			t.Fatalf("candidate jobs not leased in priority order: %d after %d", j.Priority, lastPriority)
		}
		lastPriority = j.Priority
		if seen[cand.Value] {
			t.Fatalf("duplicate candidate enqueued: %q", cand.Value)
		}
		seen[cand.Value] = true
	}
	// The highest-priority candidate is the <svg onload> breakout.
	if first, _, _ := parseCandidateJob(leased[0]); !strings.Contains(first.Value, "svg onload="+m) {
		t.Fatalf("highest-priority candidate = %q, want the svg-onload breakout", first.Value)
	}
}

// Running a candidate job itself enqueues no further candidates (no recursion).
func TestCandidateJobDoesNotRecurse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)

	q := queue.NewMemory()
	ex := env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{})
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if st, _ := q.Stats(context.Background(), env.scanID); st.Total() != 0 {
		t.Fatalf("a candidate job must not enqueue more jobs; queue total = %d", st.Total())
	}
}

// --- builtin vs llm source stays distinguishable through execution ---

func TestCandidateSourcePreserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>")
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)

	cand := detection.Candidate{Source: detection.SourceLLM, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 50, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	rep := detailReport(t, env.only())
	if rep.Candidate == nil || rep.Candidate.Source != detection.SourceLLM {
		t.Fatalf("candidate source not preserved: %+v", rep.Candidate)
	}
}

// --- not reflected vs reflected ---

func TestCandidateNotReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>static, no echo</p>") // candidate never reflected
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)

	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	out := env.only()
	if out.Outcome != domain.OutcomeSuccess || !strings.HasSuffix(out.Note, "not reflected") {
		t.Fatalf("expected a successful, not-reflected candidate; outcome=%s note=%q", out.Outcome, out.Note)
	}
	if rep := detailReport(t, out); rep.Reflected {
		t.Fatal("report marked reflected although the server did not echo the candidate")
	}
}

// --- state-changing guard ---

func TestCandidateStateChangingGuard(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	focus := env.param(ep, "q", domain.LocationForm, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)

	// Off: the candidate is NOT sent.
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatalf("skipped job must succeed: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("a candidate breakout was sent to a state-changing endpoint with AllowStateChanging off")
	}
	if out := env.only(); out.Status != domain.TestCaseSkipped || !strings.Contains(out.Note, "AllowStateChanging") {
		t.Fatalf("skip record: status=%s note=%q", out.Status, out.Note)
	}

	// On: it runs (baseline + mutated POST).
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{AllowStateChanging: true}).Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("with AllowStateChanging on, the candidate should be sent")
	}
}

// --- cancellation ---

func TestCandidateCancellationPersists(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/hang", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: "<svg onload=" + m + ">", Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(ctx, job) }()
	<-started
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the candidate request")
	}
	if out := env.only(); out.Outcome != domain.OutcomeCancelled || out.Status != domain.TestCaseCancelled {
		t.Fatalf("cancelled candidate must still persist: %+v", out)
	}
}

// --- persistence + evidence ---

func TestCandidatePersistsEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+r.URL.Query().Get("q")+"</p>")
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)
	value := "<svg onload=" + m + ">"
	cand := detection.Candidate{Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value, Priority: 90, DedupKey: "k"}
	job := env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)

	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	out := env.only()
	// Baseline request+response (shared) and the candidate request+response.
	if len(out.EvidenceIDs) != 4 {
		t.Fatalf("expected 4 evidence refs (baseline + candidate req/resp), got %v", out.EvidenceIDs)
	}
	var sawCandidateReq bool
	for _, id := range out.EvidenceIDs {
		row, text := env.evidenceBlob(id)
		if row.Kind == domain.EvidenceRequest && strings.Contains(text, m) {
			// The candidate request carries the marker token (brackets url-encoded,
			// the alphanumeric token verbatim); the baseline request does not.
			sawCandidateReq = true
		}
	}
	if !sawCandidateReq {
		t.Fatal("no stored request evidence carried the candidate marker")
	}
	rep := detailReport(t, out)
	if rep.Evidence.MutatedRequest == "" || rep.Evidence.BaselineRequest == "" {
		t.Fatalf("report evidence refs incomplete: %+v", rep.Evidence)
	}
}

// --- concurrency ---

func TestCandidateConcurrentExecution(t *testing.T) {
	var inFlight, peak atomic.Int64
	var mu sync.Mutex
	values := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		v := r.URL.Query().Get("q")
		mu.Lock()
		values[v]++
		mu.Unlock()
		inFlight.Add(-1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>"+v+"</p>")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/s", domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hi")
	ip := env.injection(ep, focus)
	m := marker(env.scanID, ip.ID)

	q := queue.NewMemory()
	const n, limit = 8, 3
	for i := 0; i < n; i++ {
		cand := detection.Candidate{
			Source: detection.SourceBuiltin, Category: detection.CatHTMLText,
			Value: fmt.Sprintf("<svg data-i=%d onload=%s>", i, m), Priority: 90 - i, DedupKey: fmt.Sprintf("k%d", i),
		}
		if err := q.Enqueue(context.Background(), env.candJob(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, cand)); err != nil {
			t.Fatal(err)
		}
	}
	poolOver(t, q, env.executorQ(scopedClient(t, openScope()), q, ExecutorConfig{}), limit)

	waitUntil(t, 5*time.Second, "all candidate jobs", func() bool {
		st, _ := q.Stats(context.Background(), env.scanID)
		return st.Succeeded == n
	})
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if len(cases) != n {
		t.Fatalf("expected %d candidate test cases, got %d", n, len(cases))
	}
	// Each distinct candidate value was sent exactly once (no duplicate requests).
	mu.Lock()
	defer mu.Unlock()
	distinct := 0
	for v, c := range values {
		if strings.Contains(v, "onload="+m) {
			distinct++
			if c != 1 {
				t.Fatalf("candidate value %q sent %d times; candidates must not be duplicated", v, c)
			}
		}
	}
	if distinct != n {
		t.Fatalf("distinct candidate values sent = %d, want %d", distinct, n)
	}
	if p := peak.Load(); p > limit || p < 2 {
		t.Fatalf("peak concurrency = %d; want between 2 and %d", p, limit)
	}
}

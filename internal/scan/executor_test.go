package scan

// Executor unit tests: request construction, resolution, outcomes, evidence, and
// scope, using the real HTTP engine against httptest servers.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/worker"
)

func execLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// execEnv is a scan's persisted discovery results plus an executor over them.
type execEnv struct {
	t      *testing.T
	st     *memory.Store
	scanID domain.ID
	ev     evidence.Store
}

func newExecEnv(t *testing.T) *execEnv {
	t.Helper()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &execEnv{t: t, st: memory.New(), scanID: domain.NewID(), ev: ev}
}

func (e *execEnv) endpoint(url string, method domain.HTTPMethod) *domain.Endpoint {
	e.t.Helper()
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: e.scanID, URL: url, Method: method, Source: domain.SourceCrawler, CreatedAt: time.Now()}
	if err := e.st.Endpoints().Create(context.Background(), ep); err != nil {
		e.t.Fatal(err)
	}
	return ep
}

func (e *execEnv) param(ep *domain.Endpoint, name string, loc domain.ParamLocation, example string) *domain.Parameter {
	e.t.Helper()
	p := &domain.Parameter{ID: domain.NewID(), ScanID: e.scanID, EndpointID: ep.ID, Name: name, Location: loc, Example: example, Source: domain.SourceForm, CreatedAt: time.Now()}
	if err := e.st.Parameters().Create(context.Background(), p); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *execEnv) injection(ep *domain.Endpoint, p *domain.Parameter) *domain.InjectionPoint {
	e.t.Helper()
	ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: e.scanID, EndpointID: ep.ID, ParameterID: p.ID, Location: p.Location, CreatedAt: time.Now()}
	if err := e.st.InjectionPoints().Create(context.Background(), ip); err != nil {
		e.t.Fatal(err)
	}
	return ip
}

func (e *execEnv) job(target domain.JobTarget) *domain.TestJob {
	return &domain.TestJob{ID: domain.NewID(), ScanID: e.scanID, Type: domain.JobTest, Target: target, Attempts: 1, MaxAttempts: 3}
}

func (e *execEnv) executor(eng httpengine.Engine, cfg ExecutorConfig) *executor {
	return newExecutor(e.st, eng, e.ev, nil, cfg, execLog(), nil)
}

// executorQ is like executor but with a live queue, so reflection jobs enqueue
// their candidate children.
func (e *execEnv) executorQ(eng httpengine.Engine, q queue.Queue, cfg ExecutorConfig) *executor {
	return newExecutor(e.st, eng, e.ev, q, cfg, execLog(), nil)
}

// only returns the single test case recorded for the scan.
func (e *execEnv) only() *domain.TestCase {
	e.t.Helper()
	cases, err := e.st.TestCases().ListByScan(context.Background(), e.scanID)
	if err != nil || len(cases) != 1 {
		e.t.Fatalf("expected exactly 1 test case, got %d (err %v)", len(cases), err)
	}
	return cases[0]
}

func (e *execEnv) evidenceBlob(id domain.ID) (domain.Evidence, string) {
	e.t.Helper()
	row, err := e.st.Evidence().Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	rc, err := e.ev.Open(row.BlobPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return *row, string(b)
}

func openScope() domain.Scope { return domain.Scope{IncludeHosts: []string{"127.0.0.1"}} }

func scopedClient(t *testing.T, scope domain.Scope) httpengine.Engine {
	return newScopedEngine(noFollowClient(t), scope)
}

// --- request construction ---

func TestBuildRequest(t *testing.T) {
	ep := func(url string, m domain.HTTPMethod) *domain.Endpoint { return &domain.Endpoint{URL: url, Method: m} }
	p := func(name string, loc domain.ParamLocation, ex string) *domain.Parameter {
		return &domain.Parameter{Name: name, Location: loc, Example: ex}
	}

	t.Run("query parameters keep observed values and add known ones", func(t *testing.T) {
		req, err := buildRequest(ep("http://h/s?q=hello", domain.MethodGET), []*domain.Parameter{
			p("q", domain.LocationQuery, "ignored-because-url-has-it"), p("page", domain.LocationQuery, "2"),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if req.URL != "http://h/s?page=2&q=hello" || req.Method != "GET" || len(req.Body) != 0 {
			t.Fatalf("got %s %s body=%q", req.Method, req.URL, req.Body)
		}
	})

	t.Run("POST form body, deterministic order", func(t *testing.T) {
		ps := []*domain.Parameter{p("zeta", domain.LocationForm, "z"), p("alpha", domain.LocationForm, "a b")}
		r1, _ := buildRequest(ep("http://h/post", domain.MethodPOST), ps, nil)
		r2, _ := buildRequest(ep("http://h/post", domain.MethodPOST), []*domain.Parameter{ps[1], ps[0]}, nil)
		if string(r1.Body) != "alpha=a+b&zeta=z" || r1.ContentType != "application/x-www-form-urlencoded" {
			t.Fatalf("form body = %q (%s)", r1.Body, r1.ContentType)
		}
		if string(r1.Body) != string(r2.Body) {
			t.Fatal("request bytes must not depend on parameter order")
		}
	})

	t.Run("POST JSON body", func(t *testing.T) {
		r, _ := buildRequest(ep("http://h/api", domain.MethodPOST), []*domain.Parameter{
			p("b", domain.LocationJSON, "2"), p("a", domain.LocationJSON, "1")}, nil)
		if string(r.Body) != `{"a":"1","b":"2"}` || r.ContentType != "application/json" {
			t.Fatalf("json body = %q (%s)", r.Body, r.ContentType)
		}
	})

	t.Run("GET never carries a body", func(t *testing.T) {
		r, _ := buildRequest(ep("http://h/x", domain.MethodGET), []*domain.Parameter{p("f", domain.LocationForm, "v")}, nil)
		if len(r.Body) != 0 || r.URL != "http://h/x" {
			t.Fatalf("GET got body/params: %s %q", r.URL, r.Body)
		}
	})

	t.Run("bad URL", func(t *testing.T) {
		if _, err := buildRequest(ep("http://[::1", domain.MethodGET), nil, nil); err == nil {
			t.Fatal("expected an error for an unparseable URL")
		}
	})
}

// --- success + evidence ---

func TestExecuteBaselineSuccessPersistsResultAndEvidence(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(http.StatusTeapot) // any HTTP status is a successful EXECUTION
		_, _ = io.WriteString(w, "short and stout")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/pot?id=7", domain.MethodGET)
	env.param(ep, "id", domain.LocationQuery, "7")
	env.param(ep, "mode", domain.LocationQuery, "full")

	// Endpoint-level job: the baseline path (injection-point jobs take the
	// reflection path, covered in reflection_test.go).
	job := env.job(domain.JobTarget{EndpointID: ep.ID})
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if gotQuery != "id=7&mode=full" {
		t.Fatalf("server saw query %q; the baseline sends every known parameter at its observed value", gotQuery)
	}

	tc := env.only()
	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess || tc.HTTPStatus != 418 {
		t.Fatalf("result: status=%s outcome=%s http=%d", tc.Status, tc.Outcome, tc.HTTPStatus)
	}
	if tc.JobID != job.ID || tc.Attempt != 1 || !tc.InjectionPointID.Empty() || tc.Method != "GET" || tc.URL != srv.URL+"/pot?id=7&mode=full" {
		t.Fatalf("identity fields wrong: %+v", tc)
	}
	if tc.StartedAt == nil || tc.FinishedAt == nil || tc.FinishedAt.Before(*tc.StartedAt) || tc.DurationMS < 0 {
		t.Fatalf("timing: %v %v %d", tc.StartedAt, tc.FinishedAt, tc.DurationMS)
	}
	if tc.Note != "baseline" {
		t.Fatalf("note = %q, want baseline", tc.Note)
	}

	// Evidence: one request and one response, referenced from the test case.
	if len(tc.EvidenceIDs) != 2 {
		t.Fatalf("evidence refs = %v", tc.EvidenceIDs)
	}
	reqRow, reqText := env.evidenceBlob(tc.EvidenceIDs[0])
	respRow, respText := env.evidenceBlob(tc.EvidenceIDs[1])
	if reqRow.Kind != domain.EvidenceRequest || respRow.Kind != domain.EvidenceResponse {
		t.Fatalf("kinds: %s %s", reqRow.Kind, respRow.Kind)
	}
	if !strings.HasPrefix(reqText, "GET /pot?id=7&mode=full HTTP/1.1\r\nHost: ") || !strings.Contains(reqText, "User-Agent: Indago") {
		t.Fatalf("request evidence:\n%s", reqText)
	}
	if !strings.HasPrefix(respText, "HTTP/1.1 418 I'm a teapot\r\n") || !strings.Contains(respText, "X-Reply: yes") || !strings.HasSuffix(respText, "\r\n\r\nshort and stout") {
		t.Fatalf("response evidence:\n%s", respText)
	}
	for _, row := range []domain.Evidence{reqRow, respRow} {
		if row.SHA256 == "" || row.Size == 0 || row.ScanID != env.scanID || !strings.Contains(row.Note, "test_case="+string(tc.ID)) {
			t.Fatalf("evidence row incomplete: %+v", row)
		}
	}
}

func TestExecuteWithoutEvidenceStoreStillRecordsOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)

	ex := newExecutor(env.st, scopedClient(t, openScope()), nil, nil, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID})); err != nil {
		t.Fatal(err)
	}
	if tc := env.only(); tc.Outcome != domain.OutcomeSuccess || len(tc.EvidenceIDs) != 0 {
		t.Fatalf("outcome=%s evidence=%v", tc.Outcome, tc.EvidenceIDs)
	}
}

// --- state-changing methods ---

func TestStateChangingMethodsSkippedUnlessAllowed(t *testing.T) {
	var hits atomic.Int64
	var gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		gotBody, gotCT = string(b), r.Header.Get("Content-Type")
	}))
	defer srv.Close()

	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/submit", domain.MethodPOST)
	p := env.param(ep, "msg", domain.LocationForm, "hi there")
	job := env.job(domain.JobTarget{EndpointID: ep.ID, InjectionPointID: env.injection(ep, p).ID})

	// Default: skipped, no request, job succeeds.
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), job); err != nil {
		t.Fatalf("a skipped job must succeed, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("a POST was sent although AllowStateChanging is off")
	}
	tc := env.only()
	if tc.Status != domain.TestCaseSkipped || tc.Outcome != "" || !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip record: status=%s outcome=%q note=%q", tc.Status, tc.Outcome, tc.Note)
	}

	// Opt-in: the reflection test now runs — a POST baseline (observed value) and a
	// POST mutated request (marker in the form field).
	var mu sync.Mutex
	var bodies []string
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		gotCT = r.Header.Get("Content-Type")
		mu.Unlock()
	})
	if err := env.executor(scopedClient(t, openScope()), ExecutorConfig{AllowStateChanging: true}).Handle(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("expected baseline+mutated POSTs, hits=%d ct=%q", hits.Load(), gotCT)
	}
	mu.Lock()
	defer mu.Unlock()
	var sawBaseline, sawMarker bool
	for _, b := range bodies {
		if b == "msg=hi+there" {
			sawBaseline = true
		} else if strings.Contains(b, "msg=ind") {
			sawMarker = true // the mutated body carries the marker in msg only
		}
	}
	if !sawBaseline || !sawMarker {
		t.Fatalf("bodies missing baseline/mutated: %q", bodies)
	}
	_ = gotBody
}

// --- outcomes ---

func TestOutcomeTimeoutIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/slow", domain.MethodGET)

	ex := env.executor(scopedClient(t, openScope()), ExecutorConfig{RequestTimeout: 60 * time.Millisecond})
	start := time.Now()
	err := ex.Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID}))
	if err == nil || errors.Is(err, worker.ErrPermanent) {
		t.Fatalf("a timeout must be a retryable error, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the request timeout was not enforced (took %s)", time.Since(start))
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeTimeout || tc.Status != domain.TestCaseFailed || tc.HTTPStatus != 0 || tc.Error == "" {
		t.Fatalf("timeout record: %+v", tc)
	}
	// The request was sent, so its evidence is kept; there is no response.
	if len(tc.EvidenceIDs) != 1 {
		t.Fatalf("a timed-out request should keep its request evidence only, got %v", tc.EvidenceIDs)
	}
	if row, _ := env.evidenceBlob(tc.EvidenceIDs[0]); row.Kind != domain.EvidenceRequest {
		t.Fatalf("kind = %s", row.Kind)
	}
}

func TestOutcomeCancelledPersistsDespiteCanceledContext(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/hang", domain.MethodGET)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(ctx, env.job(domain.JobTarget{EndpointID: ep.ID}))
	}()
	<-started
	cancel()

	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the in-flight request")
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeCancelled || tc.Status != domain.TestCaseCancelled || tc.FinishedAt == nil {
		t.Fatalf("the cancelled attempt must still be persisted: %+v", tc)
	}
}

func TestJobContextAlreadyCanceledSendsNothing(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(ctx, env.job(domain.JobTarget{EndpointID: ep.ID}))
	if !errors.Is(err, context.Canceled) || hits.Load() != 0 {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
	if tc := env.only(); tc.Outcome != domain.OutcomeCancelled {
		t.Fatalf("outcome = %s", tc.Outcome)
	}
}

func TestOutcomeErrorTransportIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more: connection refused

	env := newExecEnv(t)
	ep := env.endpoint(url+"/", domain.MethodGET)
	err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID}))
	if err == nil || errors.Is(err, worker.ErrPermanent) {
		t.Fatalf("a connection failure must be retryable, got %v", err)
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeError || tc.Status != domain.TestCaseFailed || tc.Error == "" {
		t.Fatalf("error record: %+v", tc)
	}
}

func TestPermanentErrors(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	t.Run("out of scope: never sent, not retried", func(t *testing.T) {
		env := newExecEnv(t)
		ep := env.endpoint(srv.URL+"/outside/data", domain.MethodGET)
		scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}
		err := env.executor(scopedClient(t, scope), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID}))
		if !errors.Is(err, worker.ErrPermanent) || !errors.Is(err, ErrOutOfScope) {
			t.Fatalf("expected a permanent out-of-scope error, got %v", err)
		}
		if hits.Load() != 0 {
			t.Fatal("an out-of-scope request reached the server")
		}
		if tc := env.only(); tc.Outcome != domain.OutcomeError || !strings.Contains(tc.Error, "out of scope") {
			t.Fatalf("record: %+v", tc)
		}
	})

	t.Run("job without a target", func(t *testing.T) {
		env := newExecEnv(t)
		err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{}))
		if !errors.Is(err, worker.ErrPermanent) {
			t.Fatalf("got %v", err)
		}
		if tc := env.only(); tc.Outcome != domain.OutcomeError {
			t.Fatalf("outcome = %s", tc.Outcome)
		}
	})

	t.Run("unknown endpoint", func(t *testing.T) {
		env := newExecEnv(t)
		err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{EndpointID: domain.NewID()}))
		if !errors.Is(err, worker.ErrPermanent) || !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("endpoint of another scan", func(t *testing.T) {
		env, other := newExecEnv(t), newExecEnv(t)
		ep := other.endpoint(srv.URL+"/", domain.MethodGET)
		// Make the foreign endpoint visible to env's store to prove the scan check.
		if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
			t.Fatal(err)
		}
		err := env.executor(scopedClient(t, openScope()), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID}))
		if !errors.Is(err, worker.ErrPermanent) || hits.Load() != 0 {
			t.Fatalf("a job must not execute another scan's endpoint: err=%v hits=%d", err, hits.Load())
		}
	})

	t.Run("stub engine", func(t *testing.T) {
		env := newExecEnv(t)
		ep := env.endpoint(srv.URL+"/", domain.MethodGET)
		err := env.executor(newScopedEngine(httpengine.Stub{}, openScope()), ExecutorConfig{}).Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID}))
		if !errors.Is(err, worker.ErrPermanent) {
			t.Fatalf("an unimplemented engine cannot succeed on retry: %v", err)
		}
	})
}

// --- evidence failure ---

type failingEvidence struct{}

func (failingEvidence) Put(domain.ID, domain.EvidenceKind, string, []byte) (evidence.Ref, error) {
	return evidence.Ref{}, errors.New("disk full")
}
func (failingEvidence) Open(string) (io.ReadCloser, error) { return nil, os.ErrNotExist }
func (failingEvidence) AbsPath(string) string              { return "" }

func TestEvidenceFailureKeepsOutcomeAndFlagsIt(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	env := newExecEnv(t)
	ep := env.endpoint(srv.URL+"/", domain.MethodGET)

	ex := newExecutor(env.st, scopedClient(t, openScope()), failingEvidence{}, nil, ExecutorConfig{}, execLog(), nil)
	if err := ex.Handle(context.Background(), env.job(domain.JobTarget{EndpointID: ep.ID})); err != nil {
		t.Fatalf("the executed request succeeded; evidence trouble must not fail or retry the job: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d (a retry would resend the request)", hits.Load())
	}
	tc := env.only()
	if tc.Outcome != domain.OutcomeSuccess || !strings.Contains(tc.Note, "evidence incomplete") || len(tc.EvidenceIDs) != 0 {
		t.Fatalf("record: outcome=%s note=%q evidence=%v", tc.Outcome, tc.Note, tc.EvidenceIDs)
	}
}

// --- through the worker pool: retry mapping, concurrency, pause/resume ---

func poolOver(t *testing.T, q queue.Queue, ex *executor, size int) *worker.Pool {
	t.Helper()
	p := worker.New(q, map[domain.JobType]worker.Handler{domain.JobTest: ex}, worker.Config{
		Groups:   []worker.GroupSpec{{Name: "http", Types: []domain.JobType{domain.JobTest}, Size: size}},
		IdlePoll: 5 * time.Millisecond,
	}, execLog())
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	return p
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPoolJobStatesFollowOutcomes(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()

	env := newExecEnv(t)
	q := queue.NewMemory()
	okEp := env.endpoint(ok.URL+"/", domain.MethodGET)
	slowEp := env.endpoint(slow.URL+"/", domain.MethodGET)
	outEp := env.endpoint("http://not-in-scope.invalid/", domain.MethodGET)

	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
	ex := env.executor(scopedClient(t, scope), ExecutorConfig{RequestTimeout: 60 * time.Millisecond})
	for _, e := range []*domain.Endpoint{okEp, slowEp, outEp} {
		if err := q.Enqueue(context.Background(), &domain.TestJob{ScanID: env.scanID, Type: domain.JobTest, MaxAttempts: 3, Target: domain.JobTarget{EndpointID: e.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	poolOver(t, q, ex, 3)

	// success → succeeded; out of scope → dead (permanent); timeout → requeued for retry.
	waitUntil(t, 3*time.Second, "job states to settle", func() bool {
		st, _ := q.Stats(context.Background(), env.scanID)
		return st.Succeeded == 1 && st.Dead == 1 && st.Queued == 1
	})
	cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	got := map[domain.TestOutcome]int{}
	for _, tc := range cases {
		got[tc.Outcome]++
	}
	if got[domain.OutcomeSuccess] != 1 || got[domain.OutcomeTimeout] != 1 || got[domain.OutcomeError] != 1 {
		t.Fatalf("outcomes = %v", got)
	}
}

func TestPoolRespectsConcurrencyLimit(t *testing.T) {
	var inFlight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
	}))
	defer srv.Close()

	env := newExecEnv(t)
	q := queue.NewMemory()
	const jobs, limit = 12, 3
	for i := 0; i < jobs; i++ {
		ep := env.endpoint(srv.URL+"/p"+string(rune('a'+i)), domain.MethodGET)
		_ = q.Enqueue(context.Background(), &domain.TestJob{ScanID: env.scanID, Type: domain.JobTest, MaxAttempts: 1, Target: domain.JobTarget{EndpointID: ep.ID}})
	}
	poolOver(t, q, env.executor(scopedClient(t, openScope()), ExecutorConfig{}), limit)

	waitUntil(t, 5*time.Second, "all jobs", func() bool {
		st, _ := q.Stats(context.Background(), env.scanID)
		return st.Succeeded == jobs
	})
	if p := peak.Load(); p > limit || p < 2 {
		t.Fatalf("peak concurrent requests = %d; want between 2 and the limit %d", p, limit)
	}
}

func TestPoolPauseResumeGatesExecution(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	env := newExecEnv(t)
	q := queue.NewMemory()
	pool := poolOver(t, q, env.executor(scopedClient(t, openScope()), ExecutorConfig{}), 2)

	pool.Pause()
	for i := 0; i < 4; i++ {
		ep := env.endpoint(srv.URL+"/p"+string(rune('a'+i)), domain.MethodGET)
		_ = q.Enqueue(context.Background(), &domain.TestJob{ScanID: env.scanID, Type: domain.JobTest, MaxAttempts: 1, Target: domain.JobTarget{EndpointID: ep.ID}})
	}
	time.Sleep(150 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("%d request(s) were sent while paused", hits.Load())
	}
	if cases, _ := env.st.TestCases().ListByScan(context.Background(), env.scanID); len(cases) != 0 {
		t.Fatalf("test cases were recorded while paused: %d", len(cases))
	}

	pool.Resume()
	waitUntil(t, 3*time.Second, "execution after resume", func() bool { return hits.Load() == 4 })
}

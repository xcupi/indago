//go:build browser_integration

package scan

// Regression tests for the DOM-XSS payload-verification error seam:
// probeDOMXSSCandidate must return a verification navigation/provenance error
// so the existing worker/queue MaxAttempts+backoff path owns the retry. These
// drive the REAL worker pool and in-memory queue around the real
// domXSSExecutor and real Chromium; only the loopback target is a fixture.
//
// Phase distinction for the hash-source fixture: the browser never sends the
// URL fragment to the server, so the fixture cannot read the canary/payload
// value from the request. Instead the canary response issues a single-use
// nonce cookie scoped to the probe path; the NEXT document request carrying
// that cookie is the payload navigation. Requests without the cookie (favicon,
// images, crawler traffic) never advance the phase or consume the failure
// budget, and a Chromium retry of a failed payload request carries the same
// nonce, so it stays in the failed phase instead of looking like a new attempt.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/worker"
)

const domRetryCookie = "indago_dom_retry_phase"

type domRetryPageMode int

const (
	domRetryVulnerable domRetryPageMode = iota
	domRetrySafe
	domRetryForged
)

// domRetryLab serves one hash-source page and can fail the payload navigation
// a bounded number of times. budget < 0 means "fail every context"; budget > 0
// fails that many payload phases (each new browser context is one phase pair);
// budget == 0 never fails.
type domRetryLab struct {
	mode   domRetryPageMode
	budget int
	block  bool

	mu             sync.Mutex
	nextNonce      int
	seen           map[string]bool
	failed         map[string]bool
	canaryLoads    int
	payloadLoads   int
	payloadFails   int
	hijacks        int
	payloadStarted chan struct{}
	startedOnce    sync.Once
	release        chan struct{}
}

func newDOMRetryLab(t *testing.T, mode domRetryPageMode, budget int) *domRetryLab {
	t.Helper()
	lab := &domRetryLab{
		mode: mode, budget: budget,
		seen: map[string]bool{}, failed: map[string]bool{},
		payloadStarted: make(chan struct{}), release: make(chan struct{}),
	}
	return lab
}

func (l *domRetryLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/case" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	c, err := r.Cookie(domRetryCookie)
	if err != nil || c.Value == "" {
		l.mu.Lock()
		l.nextNonce++
		nonce := fmt.Sprintf("phase-%d", l.nextNonce)
		l.canaryLoads++
		l.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name: domRetryCookie, Value: nonce, Path: "/case",
			MaxAge: 120, SameSite: http.SameSiteLaxMode,
		})
		l.servePage(w)
		return
	}
	l.servePayload(w, r, c.Value)
}

func (l *domRetryLab) servePayload(w http.ResponseWriter, r *http.Request, nonce string) {
	l.mu.Lock()
	first := !l.seen[nonce]
	fail := l.failed[nonce]
	if first {
		l.seen[nonce] = true
		if l.budget != 0 {
			fail = true
			l.failed[nonce] = true
			if l.budget > 0 {
				l.budget--
			}
		}
	}
	l.payloadLoads++
	if fail {
		l.payloadFails++
		l.hijacks++
		l.mu.Unlock()
		hijackAndClose(w)
		return
	}
	block := l.block && first
	l.mu.Unlock()

	if block {
		l.startedOnce.Do(func() { close(l.payloadStarted) })
		select {
		case <-l.release:
		case <-r.Context().Done():
			return
		case <-time.After(20 * time.Second):
			// Never hang an owned test process; a fixture that reaches this
			// branch simply serves the page and the assertion reports why.
		}
	}
	l.servePage(w)
}

func (l *domRetryLab) servePage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	switch l.mode {
	case domRetrySafe:
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>document.getElementById('sink').textContent=decodeURIComponent(location.hash.slice(1));</script>`)
	case domRetryForged:
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const raw=decodeURIComponent(location.hash.slice(1));document.getElementById('sink').innerHTML=raw.replaceAll('<','&lt;');const m=raw.match(/onerror=([^ >]+)/);if(m)console.error('ReferenceError: '+m[1]+' is not defined');</script>`)
	default:
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>document.getElementById('sink').innerHTML=decodeURIComponent(location.hash.slice(1));</script>`)
	}
}

func (l *domRetryLab) counts() (canary, payload, failed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.canaryLoads, l.payloadLoads, l.payloadFails
}

func hijackAndClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

// domRetryRun owns one real worker pool around one JobDOMXSS.
type domRetryRun struct {
	t      *testing.T
	q      *queue.Memory
	pool   *worker.Pool
	cancel context.CancelFunc
	job    *domain.TestJob
	errCh  chan error
	once   sync.Once
}

func startDOMXSSWorkerRun(t *testing.T, env *scanEnv, mgr *browser.Manager, ep *domain.Endpoint, source detection.DOMXSSSource, maxAttempts int) *domRetryRun {
	t.Helper()
	q := queue.NewMemory()
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, ep.URL), execLog(), &sync.Mutex{})
	errCh := make(chan error, 4)
	h := worker.HandlerFunc(func(ctx context.Context, job *domain.TestJob) error {
		err := ex.Handle(ctx, job)
		errCh <- err
		return err
	})
	p := worker.New(q, map[domain.JobType]worker.Handler{domain.JobDOMXSS: h}, worker.Config{
		ScanID:   env.scanID,
		Groups:   []worker.GroupSpec{{Name: "browser", Types: []domain.JobType{domain.JobDOMXSS}, Size: 1}},
		IdlePoll: 10 * time.Millisecond, LeaseDuration: 30 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}, execLog())
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start worker pool: %v", err)
	}
	payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID, Source: source})
	if err != nil {
		cancel()
		p.Stop()
		t.Fatalf("marshal dom-xss job: %v", err)
	}
	now := time.Now()
	job := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDOMXSS, State: domain.JobQueued,
		Priority: 50, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
		Payload: payload, MaxAttempts: maxAttempts, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if err := q.Enqueue(ctx, job); err != nil {
		cancel()
		p.Stop()
		t.Fatalf("enqueue dom-xss job: %v", err)
	}
	r := &domRetryRun{t: t, q: q, pool: p, cancel: cancel, job: job, errCh: errCh}
	t.Cleanup(r.stop)
	return r
}

func (r *domRetryRun) stop() {
	r.once.Do(func() {
		r.cancel()
		r.pool.Stop()
	})
}

func (r *domRetryRun) waitTerminal(timeout time.Duration) *domain.TestJob {
	r.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		jobs, err := r.q.Jobs(context.Background(), r.job.ScanID)
		if err != nil {
			r.t.Fatalf("read jobs: %v", err)
		}
		for _, j := range jobs {
			if j.ID != r.job.ID {
				continue
			}
			if j.State.IsTerminal() {
				return j
			}
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("job %s did not reach a terminal state within %s (last state above)", r.job.ID, timeout)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (r *domRetryRun) waitHandlerError(timeout time.Duration) error {
	r.t.Helper()
	select {
	case err := <-r.errCh:
		return err
	case <-time.After(timeout):
		return errors.New("handler did not return within " + timeout.String())
	}
}

func domRetryFindings(t *testing.T, env *scanEnv, ep *domain.Endpoint) []*domain.Finding {
	t.Helper()
	return sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
}

func domRetryJobCases(t *testing.T, env *scanEnv, jobID domain.ID) []*domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	out := make([]*domain.TestCase, 0, len(cases))
	for _, tc := range cases {
		if tc.JobID == jobID {
			out = append(out, tc)
		}
	}
	return out
}

func domRetryFindingByParam(t *testing.T, findings []*domain.Finding, param string) *domain.Finding {
	t.Helper()
	for _, f := range findings {
		if decodeFindingDetail(f.Detail).ParameterName == param {
			return f
		}
	}
	return nil
}

func domRetryFailedVerifications(cases []*domain.TestCase, label string) int {
	n := 0
	for _, tc := range cases {
		if strings.Contains(tc.Note, "verification navigation") && strings.Contains(tc.Note, label) &&
			(tc.Status == domain.TestCaseFailed || tc.Outcome == domain.OutcomeError || tc.Outcome == domain.OutcomeTimeout) {
			n++
		}
	}
	return n
}

func newDOMRetryEndpoint(t *testing.T, env *scanEnv, labURL, path string) *domain.Endpoint {
	t.Helper()
	return env.endpoint(labURL+path, domain.MethodGET)
}

// A transient payload-navigation failure must reach the worker's existing
// bounded retry path and recover to a genuinely Confirmed finding on the
// second attempt. The first attempt's failed TestCase stays in the audit
// history; it must not be retried into a permanent downgrade.
func TestDOMXSSWorkerRetriesTransientVerificationFailure(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	env := newScanEnv(t)

	t.Run("transient-recovers", func(t *testing.T) {
		lab := newDOMRetryLab(t, domRetryVulnerable, 1)
		srv := httptest.NewServer(lab)
		defer srv.Close()
		ep := newDOMRetryEndpoint(t, env, srv.URL, "/case")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceHash, 2)
		job := run.waitTerminal(30 * time.Second)
		run.stop()

		if job.State != domain.JobSucceeded || job.Attempts != 2 {
			t.Fatalf("a transient payload failure must be retried once and then succeed: state=%s attempts=%d last_error=%q", job.State, job.Attempts, job.LastError)
		}
		canary, payload, failed := lab.counts()
		if failed == 0 || canary < 2 || payload < 2 {
			t.Fatalf("fixture must observe canary then failed payload then a recovered attempt: canary=%d payload=%d failed=%d", canary, payload, failed)
		}
		findings := domRetryFindings(t, env, ep)
		if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
			t.Fatalf("recovered verification must produce exactly one Confirmed finding: %+v", findings)
		}
		// The failed first verification remains legitimate audit history.
		if n := domRetryFailedVerifications(domRetryJobCases(t, env, run.job.ID), "location.hash"); n != 1 {
			t.Fatalf("the first attempt's failed verification TestCase must remain once, got %d", n)
		}
	})

	t.Run("persistent-exhausted", func(t *testing.T) {
		lab := newDOMRetryLab(t, domRetryVulnerable, -1)
		srv := httptest.NewServer(lab)
		defer srv.Close()
		ep := newDOMRetryEndpoint(t, env, srv.URL, "/case")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceHash, 2)
		job := run.waitTerminal(30 * time.Second)
		run.stop()

		if job.State != domain.JobDead || job.Attempts != 2 {
			t.Fatalf("persistent verification failure must exhaust the existing bounded retries and die: state=%s attempts=%d last_error=%q", job.State, job.Attempts, job.LastError)
		}
		findings := domRetryFindings(t, env, ep)
		if len(findings) != 1 || findings[0].Verdict == domain.VerdictConfirmed {
			t.Fatalf("exhausted verification must not confirm: %+v", findings)
		}
		if findings[0].Verdict != domain.VerdictPending && findings[0].Verdict != domain.VerdictInconclusive {
			t.Fatalf("exhausted verification must leave the finding pending/inconclusive, got %s", findings[0].Verdict)
		}
		if n := domRetryFailedVerifications(domRetryJobCases(t, env, run.job.ID), "location.hash"); n != 2 {
			t.Fatalf("both attempts must leave a failed verification TestCase, got %d", n)
		}
	})

	t.Run("safe-control", func(t *testing.T) {
		lab := newDOMRetryLab(t, domRetrySafe, 0)
		srv := httptest.NewServer(lab)
		defer srv.Close()
		ep := newDOMRetryEndpoint(t, env, srv.URL, "/case")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceHash, 2)
		job := run.waitTerminal(30 * time.Second)
		run.stop()

		if job.State != domain.JobSucceeded {
			t.Fatalf("a safely-encoded page must complete normally: state=%s last_error=%q", job.State, job.LastError)
		}
		if findings := domRetryFindings(t, env, ep); len(findings) != 0 {
			t.Fatalf("a network success on a safe page is not a finding: %+v", findings)
		}
	})

	t.Run("forged-console-not-confirmed", func(t *testing.T) {
		lab := newDOMRetryLab(t, domRetryForged, 0)
		srv := httptest.NewServer(lab)
		defer srv.Close()
		ep := newDOMRetryEndpoint(t, env, srv.URL, "/case")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceHash, 2)
		job := run.waitTerminal(30 * time.Second)
		run.stop()

		if job.State != domain.JobSucceeded {
			t.Fatalf("a forged page that never executes the marker must not fail the job: state=%s", job.State)
		}
		findings := domRetryFindings(t, env, ep)
		for _, f := range findings {
			if f.Verdict == domain.VerdictConfirmed {
				t.Fatalf("page-authored console text produced a Confirmed finding: %q", f.Summary)
			}
		}
	})
}

// domSelectorLab is a query-source fixture: the server CAN see canary vs
// payload in the query string, so selector "a" fails at the payload phase and
// selector "b" succeeds without any phase cookie.
type domSelectorLab struct {
	mu      sync.Mutex
	hijacks int
}

func (l *domSelectorLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/multi" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if b := r.URL.Query().Get("b"); strings.Contains(b, "onerror") {
		l.mu.Lock()
		l.hijacks++
		l.mu.Unlock()
		hijackAndClose(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const q=new URLSearchParams(location.search);document.getElementById('sink').innerHTML=q.get('a')||q.get('b')||'';</script>`)
}

// A retry re-runs the whole per-source job. That must not duplicate the
// already-Confirmed selector's finding/evidence, and must not downgrade it
// when a different selector exhausts its retries.
func TestDOMXSSWorkerCancellationAndConfirmedDurability(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	t.Run("cancellation-is-not-a-silent-success", func(t *testing.T) {
		env := newScanEnv(t)
		lab := newDOMRetryLab(t, domRetryVulnerable, 0)
		lab.block = true
		srv := httptest.NewServer(lab)
		defer func() { close(lab.release); srv.Close() }()
		ep := newDOMRetryEndpoint(t, env, srv.URL, "/case")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceHash, 2)
		select {
		case <-lab.payloadStarted:
		case <-time.After(15 * time.Second):
			t.Fatal("fixture never observed the payload navigation")
		}
		run.cancel()
		err := run.waitHandlerError(20 * time.Second)
		run.stop()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a canceled verification must surface as context.Canceled, got %v", err)
		}
		canceled := 0
		for _, tc := range domRetryJobCases(t, env, run.job.ID) {
			if strings.Contains(tc.Note, "verification navigation") && tc.Status == domain.TestCaseCancelled && tc.Outcome == domain.OutcomeCancelled {
				canceled++
			}
		}
		if canceled != 1 {
			t.Fatalf("cancellation must be recorded as a canceled verification TestCase, got %d", canceled)
		}
		findings := domRetryFindings(t, env, ep)
		for _, f := range findings {
			if f.Verdict == domain.VerdictConfirmed {
				t.Fatalf("a canceled payload navigation must not confirm a finding: %q", f.Summary)
			}
		}
	})

	t.Run("confirmed-selector-survives-other-selector-exhaustion", func(t *testing.T) {
		env := newScanEnv(t)
		lab := &domSelectorLab{}
		srv := httptest.NewServer(lab)
		defer srv.Close()
		ep := env.endpoint(srv.URL+"/multi", domain.MethodGET)
		env.param(ep, "a", domain.LocationQuery, "x")
		env.param(ep, "b", domain.LocationQuery, "x")

		run := startDOMXSSWorkerRun(t, env, mgr, ep, detection.DOMSourceQuery, 2)
		job := run.waitTerminal(30 * time.Second)
		run.stop()

		if job.State != domain.JobDead || job.Attempts != 2 {
			t.Fatalf("selector b's persistent payload failure must exhaust retries: state=%s attempts=%d last_error=%q", job.State, job.Attempts, job.LastError)
		}
		findings := domRetryFindings(t, env, ep)
		if len(findings) != 2 {
			t.Fatalf("retrying the job must not duplicate findings: got %d, want one per selector", len(findings))
		}
		aFinding := domRetryFindingByParam(t, findings, "a")
		bFinding := domRetryFindingByParam(t, findings, "b")
		if aFinding == nil || bFinding == nil {
			t.Fatalf("expected findings for both selectors: %+v", findings)
		}
		if aFinding.Verdict != domain.VerdictConfirmed {
			t.Fatalf("the previously Confirmed selector must not downgrade when another selector fails: %s", aFinding.Verdict)
		}
		if bFinding.Verdict == domain.VerdictConfirmed {
			t.Fatalf("selector b never executed its marker and must not confirm: %s", bFinding.Verdict)
		}
		seen := map[domain.ID]bool{}
		for _, id := range aFinding.EvidenceIDs {
			if seen[id] {
				t.Fatalf("duplicate evidence reference after retry: %s", id)
			}
			seen[id] = true
		}
		if len(seen) == 0 {
			t.Fatal("the Confirmed selector must keep its verification evidence")
		}
		// Both attempts' verification cases stay as audit history.
		if n := domRetryFailedVerifications(domRetryJobCases(t, env, run.job.ID), `parameter "b"`); n != 2 {
			t.Fatalf("selector b must keep one failed verification TestCase per attempt, got %d", n)
		}
	})
}

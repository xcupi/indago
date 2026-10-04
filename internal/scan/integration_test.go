package scan_test

// Integration tests: a real Controller, real discovery, the real HTTP engine,
// and a live httptest site. They verify seed → discovery → persisted
// endpoint/parameter → queued TestJob, pause/resume, cancel, completion policy,
// stop policy, and scope enforcement end to end.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/worker"
)

// --- site ---

// site wraps an httptest server and records every path requested.
type site struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func newSite(t *testing.T, register func(mux *http.ServeMux, base func() string)) *site {
	t.Helper()
	s := &site{hits: map[string]int{}}
	mux := http.NewServeMux()
	register(mux, func() string { return s.URL })
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *site) hitCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *site) pathsWithPrefix(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.hits {
		if len(p) >= len(prefix) && p[:len(prefix)] == prefix {
			out = append(out, p)
		}
	}
	return out
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, body)
}

// standardSite is a small linked site exercising links, GET/POST forms,
// query params, sitemap and robots.
func standardSite(t *testing.T) *site {
	return newSite(t, func(mux *http.ServeMux, base func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/a">a</a> <a href="/search?q=1">s</a>
				<form action="/find" method="get"><input name="term"></form>
				<form action="/submit" method="post"><input name="body"></form>`)
		})
		mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, `<a href="/c">c</a>`) })
		mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<form action="/deep" method="get"><input name="deepparam"></form>`)
		})
		for _, p := range []string{"/search", "/find", "/submit", "/deep", "/secret", "/sm-page"} {
			mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		}
		mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0"?><urlset><url><loc>%s/sm-page</loc></url></urlset>`, base())
		})
		mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "User-agent: *\nDisallow: /secret\nSitemap: %s/sitemap.xml\n", base())
		})
	})
}

// --- fixture helpers ---

func newEngine(t *testing.T) httpengine.Engine {
	t.Helper()
	cfg := httpengine.DefaultConfig()
	cfg.FollowRedirects = false // the scan controller follows redirects itself
	cfg.Timeout = 5 * time.Second
	c, err := httpengine.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// newCtrl builds a controller over st/q using the real HTTP engine.
func newCtrl(t *testing.T, st store.Store, q queue.Queue, opts scan.Options) *scan.Controller {
	t.Helper()
	if opts.HTTP == nil {
		opts.HTTP = newEngine(t)
	}
	if opts.IdlePoll == 0 {
		opts.IdlePoll = 10 * time.Millisecond
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 20 * time.Millisecond
	}
	c := scan.NewController(st, q, quiet(), "test", opts)
	t.Cleanup(c.Shutdown)
	return c
}

// seedProject creates a project, scope, and target for baseURL.
func seedProject(t *testing.T, st store.Store, baseURL string, scope domain.Scope) (proj, tgt domain.ID) {
	t.Helper()
	ctx := context.Background()
	p := &domain.Project{ID: domain.NewID(), Name: "p"}
	if err := st.Projects().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	scope.ID, scope.ProjectID = domain.NewID(), p.ID
	if err := st.Scopes().Create(ctx, &scope); err != nil {
		t.Fatal(err)
	}
	tg := &domain.Target{ID: domain.NewID(), ProjectID: p.ID, Name: "t", BaseURL: baseURL}
	if err := st.Targets().Create(ctx, tg); err != nil {
		t.Fatal(err)
	}
	return p.ID, tg.ID
}

func hostScope() domain.Scope { return domain.Scope{IncludeHosts: []string{"127.0.0.1"}} }

// workersCfg returns a custom config with the given HTTP worker count and no
// request-rate limit.
func workersCfg(httpWorkers int) *domain.ScanConfig {
	return &domain.ScanConfig{DiscoveryConcurrency: 2, HTTPConcurrency: httpWorkers, BrowserConcurrency: 0}
}

func createScan(t *testing.T, c *scan.Controller, proj, tgt domain.ID, cfg *domain.ScanConfig, stop domain.StopPolicy) *domain.Scan {
	t.Helper()
	p := scan.CreateScanParams{ProjectID: proj, TargetID: tgt, Name: "it", Profile: domain.ProfileBalanced, Stop: stop}
	if cfg != nil {
		p.Profile, p.Config = domain.ProfileCustom, cfg
	}
	sc, err := c.CreateScan(context.Background(), p)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	return sc
}

// waitStatus polls Status until cond holds, failing with the last status.
func waitStatus(t *testing.T, c *scan.Controller, id domain.ID, d time.Duration, cond func(*scan.Status) bool) *scan.Status {
	t.Helper()
	deadline := time.Now().Add(d)
	var last *scan.Status
	for time.Now().Before(deadline) {
		st, err := c.Status(context.Background(), id)
		if err == nil {
			last = st
			if cond(st) {
				return st
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if last == nil {
		t.Fatalf("status never available within %s", d)
	}
	t.Fatalf("condition not met within %s; last: scan=%s discovery=%s endpoints=%d jobs=%+v",
		d, last.Scan.State, last.Discovery.State, last.Discovery.Endpoints, last.Jobs)
	return nil
}

func isCompleted(st *scan.Status) bool { return st.Scan.State == domain.ScanCompleted }

// recordingHandlers records every test job's target URL, then succeeds.
func recordingHandlers() (map[domain.JobType]worker.Handler, func() []string) {
	var mu sync.Mutex
	var urls []string
	h := map[domain.JobType]worker.Handler{
		domain.JobTest: worker.HandlerFunc(func(_ context.Context, j *domain.TestJob) error {
			mu.Lock()
			urls = append(urls, j.Target.URL)
			mu.Unlock()
			return nil
		}),
	}
	return h, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), urls...)
	}
}

// --- tests ---

// seed → discovery → persisted endpoint/parameter → queued TestJob, and the
// scan does NOT complete while jobs remain queued.
func TestSeedToDiscoveryToQueuedJobs(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	// No HTTP workers: every enqueued job stays queued, so we can observe them.
	sc := createScan(t, ctrl, proj, tgt, workersCfg(0), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	got := waitStatus(t, ctrl, sc.ID, 5*time.Second, func(st *scan.Status) bool {
		return st.Discovery.State == domain.DiscoveryComplete
	})

	// Persisted endpoints with provenance.
	if got.Discovery.Endpoints < 8 {
		t.Fatalf("expected the site's endpoints persisted, got %d", got.Discovery.Endpoints)
	}
	for _, src := range []domain.DiscoverySource{domain.SourceUserProvided, domain.SourceCrawler, domain.SourceForm, domain.SourceSitemap, domain.SourceRobots} {
		if got.Discovery.EndpointsBySource[src] == 0 {
			t.Errorf("no endpoint with provenance %q: %v", src, got.Discovery.EndpointsBySource)
		}
	}

	// Persisted parameters (query, GET form, POST form, deep form).
	params, _ := st.Parameters().ListByScan(ctx, sc.ID)
	names := map[string]domain.ParamLocation{}
	for _, p := range params {
		names[p.Name] = p.Location
	}
	for name, loc := range map[string]domain.ParamLocation{
		"q": domain.LocationQuery, "term": domain.LocationQuery,
		"body": domain.LocationForm, "deepparam": domain.LocationQuery,
	} {
		if names[name] != loc {
			t.Errorf("parameter %q: location %q, want %q (have %v)", name, names[name], loc, names)
		}
	}

	// Every endpoint and every injection point produced a QUEUED TestJob.
	if want := got.Discovery.Endpoints + got.Discovery.InjectionPoints; got.Jobs.Queued != want {
		t.Fatalf("queued jobs = %d, want endpoints+injection points = %d", got.Jobs.Queued, want)
	}
	if got.Jobs.Succeeded != 0 {
		t.Fatalf("no worker should have run, got %+v", got.Jobs)
	}

	// Completion waits for queued jobs: discovery is done but the scan runs on.
	time.Sleep(150 * time.Millisecond)
	cur, _ := ctrl.Status(ctx, sc.ID)
	if cur.Scan.State != domain.ScanRunning || !cur.Running {
		t.Fatalf("scan must keep running while jobs are queued, state=%s running=%v", cur.Scan.State, cur.Running)
	}

	// Persisted stats are refreshed by the monitor.
	waitStatus(t, ctrl, sc.ID, 3*time.Second, func(st *scan.Status) bool {
		return st.Scan.Stats.EndpointsDiscovered == st.Discovery.Endpoints &&
			st.Scan.Stats.JobsQueued == st.Jobs.Queued
	})

	// Give the scan workers (runtime reconfiguration): jobs drain, scan completes.
	cfg := *workersCfg(4)
	if err := ctrl.Reconfigure(ctx, sc.ID, cfg); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 5*time.Second, isCompleted)
	if done.Jobs.Pending() != 0 || done.Scan.EndedAt == nil || ctrl.IsRunning(sc.ID) {
		t.Fatalf("completed scan inconsistent: jobs=%+v ended=%v running=%v", done.Jobs, done.Scan.EndedAt, ctrl.IsRunning(sc.ID))
	}
}

// A scan completes on its own once discovery has finished and the queue is
// drained, and every discovered endpoint's job was actually handled.
func TestScanCompletesAfterDiscoveryAndJobs(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, handled := recordingHandlers()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 8*time.Second, isCompleted)

	if done.Scan.Discovery != domain.DiscoveryComplete {
		t.Fatalf("persisted discovery state = %q", done.Scan.Discovery)
	}
	total := done.Discovery.Endpoints + done.Discovery.InjectionPoints
	if done.Jobs.Total() != total || done.Jobs.Succeeded != total {
		t.Fatalf("jobs=%+v, want %d succeeded", done.Jobs, total)
	}
	if len(handled()) != total {
		t.Fatalf("handler ran %d times, want %d", len(handled()), total)
	}
	if done.Scan.StartedAt == nil || done.Scan.EndedAt == nil {
		t.Fatal("start/end timestamps not persisted")
	}
	if done.Scan.Stats.EndpointsDiscovered != done.Discovery.Endpoints || done.Scan.Stats.JobsCompleted != total {
		t.Fatalf("final stats not persisted: %+v", done.Scan.Stats)
	}
}

// Testing proceeds while discovery is still running, and the scan must not
// complete until discovery finishes even though the queue is momentarily empty.
func TestTestingRunsWhileDiscoveryInFlight(t *testing.T) {
	ctx := context.Background()
	rootHit := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			once.Do(func() { close(rootHit) })
			select { // discovery's crawl of the root is slow
			case <-release:
			case <-r.Context().Done():
				return
			}
			writeHTML(w, `<a href="/next">n</a>`)
		})
		mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, handled := recordingHandlers()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	<-rootHit

	// The seed endpoint is registered immediately and its job is processed while
	// the crawl is still blocked: testing does not wait for discovery.
	waitFor(t, 3*time.Second, func() bool { return len(handled()) >= 1 })
	st1, _ := ctrl.Status(ctx, sc.ID)
	if st1.Discovery.State == domain.DiscoveryComplete {
		t.Fatal("discovery should still be running")
	}

	// Queue is drained but discovery is active: the scan must NOT complete.
	time.Sleep(200 * time.Millisecond)
	if cur, _ := ctrl.Status(ctx, sc.ID); cur.Scan.State != domain.ScanRunning {
		t.Fatalf("scan completed while discovery was active (state=%s)", cur.Scan.State)
	}

	close(release)
	waitStatus(t, ctrl, sc.ID, 5*time.Second, isCompleted)
	if s.hitCount("/next") == 0 {
		t.Fatal("link discovered after release was never crawled")
	}
}

// Pause/resume are routed to BOTH the worker pool and discovery.
func TestPauseResumeRoutedToDiscoveryAndWorkers(t *testing.T) {
	ctx := context.Background()
	rootHit := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			once.Do(func() { close(rootHit) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			writeHTML(w, `<a href="/p1">1</a> <a href="/p2">2</a>`)
		})
		mux.HandleFunc("/p1", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		mux.HandleFunc("/p2", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, handled := recordingHandlers()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	<-rootHit // the root fetch is in flight

	if err := ctrl.Pause(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Pause(ctx, sc.ID); err != nil { // idempotent
		t.Fatalf("second pause: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let any in-flight job settle
	handledAtPause := len(handled())

	close(release) // the in-flight root fetch now completes
	time.Sleep(300 * time.Millisecond)

	if got := s.hitCount("/p1") + s.hitCount("/p2"); got != 0 {
		t.Fatalf("discovery started new fetches while paused (p1/p2 hits=%d)", got)
	}
	if n := len(handled()); n != handledAtPause {
		t.Fatalf("workers processed jobs while paused: %d -> %d", handledAtPause, n)
	}
	paused, _ := ctrl.Status(ctx, sc.ID)
	if paused.Scan.State != domain.ScanPaused || !paused.Discovery.Paused {
		t.Fatalf("expected paused scan, got state=%s", paused.Scan.State)
	}
	// Results of the in-flight fetch were still persisted, and their jobs wait.
	if paused.Jobs.Queued == 0 {
		t.Fatal("jobs for the in-flight results should be queued while paused")
	}

	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 8*time.Second, isCompleted)
	if s.hitCount("/p1") == 0 || s.hitCount("/p2") == 0 {
		t.Fatalf("discovery did not resume: p1=%d p2=%d", s.hitCount("/p1"), s.hitCount("/p2"))
	}
}

// Cancel stops discovery mid-request and the pool, cancels jobs, and records
// terminal state; nothing is persisted afterwards.
func TestCancelStopsEverything(t *testing.T) {
	ctx := context.Background()
	rootHit := make(chan struct{})
	var once sync.Once
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(rootHit) })
			select { // block until the client goes away
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		})
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	<-rootHit
	waitFor(t, 3*time.Second, func() bool {
		stt, _ := ctrl.Status(ctx, sc.ID)
		return stt.Jobs.Pending() > 0
	})

	start := time.Now()
	if err := ctrl.Cancel(ctx, sc.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("cancel took %s; it must interrupt in-flight discovery promptly", d)
	}

	got, _ := ctrl.Status(ctx, sc.ID)
	if got.Scan.State != domain.ScanCanceled || got.Scan.Discovery != domain.DiscoveryCanceled {
		t.Fatalf("state=%s discovery=%s", got.Scan.State, got.Scan.Discovery)
	}
	if got.Scan.EndedAt == nil || got.Running || ctrl.IsRunning(sc.ID) {
		t.Fatalf("cancel left the scan live: ended=%v running=%v", got.Scan.EndedAt, got.Running)
	}
	if got.Jobs.Pending() != 0 {
		t.Fatalf("jobs still pending after cancel: %+v", got.Jobs)
	}

	// Nothing more is persisted after cancel returns (goroutines really exited).
	eps, _ := st.Endpoints().ListByScan(ctx, sc.ID)
	time.Sleep(150 * time.Millisecond)
	after, _ := st.Endpoints().ListByScan(ctx, sc.ID)
	if len(after) != len(eps) {
		t.Fatalf("endpoints changed after cancel: %d -> %d", len(eps), len(after))
	}
	if err := ctrl.Cancel(ctx, sc.ID); err != nil { // idempotent
		t.Fatalf("second cancel: %v", err)
	}
}

// Scope is enforced on every outbound request and redirect: nothing outside the
// scope is ever requested or persisted.
func TestScopeEnforcedDuringDiscovery(t *testing.T) {
	ctx := context.Background()
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
			writeHTML(w, `<a href="/app/in">in</a> <a href="/outside/secret">out</a>
				<a href="/app/redir">redir</a> <form action="/outside/form" method="post"><input name="x"></form>`)
		})
		mux.HandleFunc("/app/in", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		mux.HandleFunc("/app/redir", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/outside/landing", http.StatusFound)
		})
		mux.HandleFunc("/outside/", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "SECRET") })
		mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "Disallow: /outside/x\n") })
	})
	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}}
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL+"/app/", scope)
	ctrl := newCtrl(t, st, q, scan.Options{})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 8*time.Second, isCompleted)

	if out := s.pathsWithPrefix("/outside"); len(out) != 0 {
		t.Fatalf("out-of-scope paths were requested: %v", out)
	}
	if s.hitCount("/robots.txt") != 0 {
		t.Fatal("/robots.txt is outside the path scope and must not be fetched")
	}
	eps, _ := st.Endpoints().ListByScan(ctx, sc.ID)
	for _, e := range eps {
		if d := scope.Permits(e.URL); !d.Allowed {
			t.Fatalf("out-of-scope endpoint persisted: %s (%s)", e.URL, d.Reason)
		}
	}
	if s.hitCount("/app/in") == 0 {
		t.Fatal("in-scope page should have been crawled")
	}
}

func TestCreateScanValidatesSeeds(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1/app/", domain.Scope{IncludeHosts: []string{"127.0.0.1"}, IncludePathPrefixes: []string{"/app"}})
	ctrl := newCtrl(t, st, q, scan.Options{})

	_, err := ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: proj, TargetID: tgt, SeedURLs: []string{"http://127.0.0.1:1/outside"}})
	if !errors.Is(err, scan.ErrOutOfScope) {
		t.Fatalf("out-of-scope seed: expected ErrOutOfScope, got %v", err)
	}
	_, err = ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: proj, TargetID: tgt, SeedURLs: []string{"ftp://127.0.0.1/app"}})
	if !errors.Is(err, scan.ErrInvalidSeed) {
		t.Fatalf("invalid seed: expected ErrInvalidSeed, got %v", err)
	}
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: proj, TargetID: tgt, SeedURLs: []string{" http://127.0.0.1:1/app/x?b=2&a=1 ", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.SeedURLs) != 1 || sc.SeedURLs[0] != "http://127.0.0.1:1/app/x?a=1&b=2" {
		t.Fatalf("seeds should be stored canonical, got %v", sc.SeedURLs)
	}
	if sc.Discovery != domain.DiscoveryPending {
		t.Fatalf("new scan discovery state = %q", sc.Discovery)
	}
}

// Stop policy: stop after the first confirmed finding.
func TestStopPolicyFirstConfirmedStopsScan(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{Mode: domain.StopFirstConfirmed})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Jobs.Pending() > 0 })
	time.Sleep(100 * time.Millisecond)
	if cur, _ := ctrl.Status(ctx, sc.ID); cur.Scan.State != domain.ScanRunning {
		t.Fatalf("scan should be running before any finding, got %s", cur.Scan.State)
	}

	addFinding(t, st, sc, domain.VerdictConfirmed)

	done := waitStatus(t, ctrl, sc.ID, 5*time.Second, isCompleted)
	if done.Jobs.Pending() != 0 || done.Findings.Confirmed != 1 {
		t.Fatalf("stop policy should cancel remaining jobs: jobs=%+v findings=%+v", done.Jobs, done.Findings)
	}
}

// Stop policy: pause and ask, then don't immediately re-pause after resume.
func TestStopPolicyPauseAndAsk(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{Mode: domain.StopPauseAndAsk})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	addFinding(t, st, sc, domain.VerdictConfirmed)
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanPaused })

	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if cur, _ := ctrl.Status(ctx, sc.ID); cur.Scan.State != domain.ScanRunning {
		t.Fatalf("scan re-paused for the same finding after resume: %s", cur.Scan.State)
	}

	addFinding(t, st, sc, domain.VerdictConfirmed) // a NEW finding asks again
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanPaused })
}

func addFinding(t *testing.T, st store.Store, sc *domain.Scan, v domain.Verdict) {
	t.Helper()
	now := time.Now()
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: sc.ID, ProjectID: sc.ProjectID, VulnClass: domain.VulnReflectedXSS,
		Verdict: v, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title: "test finding", CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Findings().Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
}

// Start/Resume are rejected after Shutdown; Shutdown leaves persisted state
// untouched so a restart can recover.
func TestShutdownRejectsNewWorkAndKeepsState(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl := scan.NewController(st, q, quiet(), "test", scan.Options{HTTP: newEngine(t), Handlers: handlers, IdlePoll: 10 * time.Millisecond, PollInterval: 20 * time.Millisecond})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})
	other := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Jobs.Pending() > 0 })

	ctrl.Shutdown()
	ctrl.Shutdown() // idempotent

	if ctrl.IsRunning(sc.ID) {
		t.Fatal("execution still tracked after Shutdown")
	}
	got, _ := ctrl.Status(ctx, sc.ID)
	if got.Scan.State != domain.ScanRunning {
		t.Fatalf("Shutdown must not change persisted scan state, got %s", got.Scan.State)
	}
	if err := ctrl.Start(ctx, other.ID); err != scan.ErrShutdown {
		t.Fatalf("Start after Shutdown: expected ErrShutdown, got %v", err)
	}
	if err := ctrl.Resume(ctx, sc.ID); err != scan.ErrShutdown {
		t.Fatalf("Resume after Shutdown: expected ErrShutdown, got %v", err)
	}
}

// Concurrent control calls against a live scan must be safe (run with -race).
func TestConcurrentControlCallsAreSafe(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl := newCtrl(t, st, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var ops atomic.Int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				switch (i + n) % 4 {
				case 0:
					_ = ctrl.Pause(ctx, sc.ID)
				case 1:
					_ = ctrl.Resume(ctx, sc.ID)
				case 2:
					_ = ctrl.Reconfigure(ctx, sc.ID, *workersCfg(1 + n%4))
				default:
					_, _ = ctrl.Status(ctx, sc.ID)
				}
				ops.Add(1)
			}
		}(i)
	}
	wg.Wait()
	_ = ctrl.Resume(ctx, sc.ID)
	if err := ctrl.Cancel(ctx, sc.ID); err != nil {
		t.Fatalf("cancel after concurrent control: %v", err)
	}
	final, _ := ctrl.Status(ctx, sc.ID)
	if final.Scan.State != domain.ScanCanceled {
		t.Fatalf("final state = %s", final.Scan.State)
	}
}

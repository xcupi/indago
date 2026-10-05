package discovery_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
	c := discovery.NewCollector(st, q, scanID, scope, cfg, quiet())
	return c, st, q, scanID
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
	if stats.Queued != 1 { // one endpoint-level job
		t.Fatalf("expected 1 queued job, got %+v", stats)
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
	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	if len(ips) != 2 {
		t.Fatalf("expected 2 injection points, got %d", len(ips))
	}
	// 1 endpoint job + 2 injection-point jobs.
	stats, _ := q.Stats(ctx, scanID)
	if stats.Queued != 3 {
		t.Fatalf("expected 3 queued jobs, got %+v", stats)
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
	if len(params) != 1 || params[0].Name != "comment" || params[0].Location != domain.LocationForm {
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

	first := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
	if _, err := first.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/s?q=1", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	if err := first.AddParameter(ctx, discovery.ParamCandidate{EndpointURL: "http://example.com/post", EndpointMethod: domain.MethodPOST, Name: "body", Location: domain.LocationForm, Source: domain.SourceForm}); err != nil {
		t.Fatal(err)
	}
	before, _ := q.Stats(ctx, scanID)
	e1, p1, _ := first.Counts()

	// "Restart": brand-new collector, same store and queue.
	second := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
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

	first := discovery.NewCollector(st, failingEnqueue{q}, scanID, scope, discovery.DefaultConfig(), quiet())
	if _, err := first.AddEndpoint(ctx, discovery.EndpointCandidate{URL: "http://example.com/s?q=1", Method: domain.MethodGET, Source: domain.SourceCrawler}); err != nil {
		t.Fatal(err)
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	if len(ips) != 1 {
		t.Fatalf("setup: want 1 persisted injection point, got %d", len(ips))
	}
	if st, _ := q.Stats(ctx, scanID); st.Total() != 0 {
		t.Fatalf("setup: interrupted run must have enqueued nothing, got %+v", st)
	}

	second := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
	for i := 0; i < 2; i++ { // second pass proves idempotence
		if err := second.Hydrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eps, _ := st.Endpoints().ListByScan(ctx, scanID)
	got := jobTargets(t, q, scanID)
	want := map[string]int{"endpoint:" + string(eps[0].ID): 1, string(ips[0].ID): 1}
	if len(got) != len(want) || got["endpoint:"+string(eps[0].ID)] != 1 || got[string(ips[0].ID)] != 1 {
		t.Fatalf("reconciled jobs = %v, want exactly %v", got, want)
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

	c := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
	if err := c.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	if len(params) != 1 || params[0].Name != "q" || params[0].Example != "1" || params[0].Source != domain.SourceCrawler {
		t.Fatalf("missing query parameter not registered: %+v", params)
	}
	if len(ips) != 1 || ips[0].ParameterID != params[0].ID {
		t.Fatalf("missing injection point not registered: %+v", ips)
	}
	got := jobTargets(t, q, scanID)
	if got[string(ips[0].ID)] != 1 || got["endpoint:"+string(ep.ID)] != 1 || len(got) != 2 {
		t.Fatalf("jobs = %v, want one endpoint job and one injection-point job", got)
	}
}

// A parameter persisted without its injection point gets one (and its job).
func TestCollectorHydrateCreatesMissingInjectionPoint(t *testing.T) {
	st := memory.New()
	q := queue.NewMemory()
	scanID := domain.NewID()
	scope := domain.Scope{IncludeHosts: []string{"example.com"}}
	ctx := context.Background()

	first := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
	if err := first.AddParameter(ctx, discovery.ParamCandidate{EndpointURL: "http://example.com/post", EndpointMethod: domain.MethodPOST, Name: "body", Location: domain.LocationForm, Source: domain.SourceForm}); err != nil {
		t.Fatal(err)
	}
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	// Simulate the interruption: a second parameter row with no injection point.
	orphan := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: params[0].EndpointID, Name: "extra", Location: domain.LocationForm, Source: domain.SourceForm}
	if err := st.Parameters().Create(ctx, orphan); err != nil {
		t.Fatal(err)
	}

	second := discovery.NewCollector(st, q, scanID, scope, discovery.DefaultConfig(), quiet())
	if err := second.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Hydrate(ctx); err != nil {
		t.Fatal(err)
	}
	ips, _ := st.InjectionPoints().ListByScan(ctx, scanID)
	if len(ips) != 2 {
		t.Fatalf("want 2 injection points (1 original + 1 reconciled), got %d", len(ips))
	}
	got := jobTargets(t, q, scanID)
	for _, ip := range ips {
		if got[string(ip.ID)] != 1 {
			t.Fatalf("injection point %s has %d jobs, want 1 (jobs=%v)", ip.ID, got[string(ip.ID)], got)
		}
	}
}

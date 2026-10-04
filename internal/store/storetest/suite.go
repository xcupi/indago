// Package storetest provides a reusable conformance suite that any store.Store
// implementation must pass. Both the in-memory and SQLite stores run it, which
// guarantees they behave identically.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

// Factory constructs a fresh, migrated Store and a cleanup function.
type Factory func(t *testing.T) (store.Store, func())

// Run executes the full conformance suite against the store produced by f.
func Run(t *testing.T, f Factory) {
	t.Helper()
	t.Run("ProjectCRUD", func(t *testing.T) { testProjectCRUD(t, f) })
	t.Run("NotFound", func(t *testing.T) { testNotFound(t, f) })
	t.Run("ScanByProject", func(t *testing.T) { testScanByProject(t, f) })
	t.Run("EndpointsParamsInjection", func(t *testing.T) { testDiscoveryChain(t, f) })
	t.Run("JobStates", func(t *testing.T) { testJobStates(t, f) })
	t.Run("FindingEvidence", func(t *testing.T) { testFindingEvidence(t, f) })
	t.Run("SessionByScan", func(t *testing.T) { testSessionByScan(t, f) })
	t.Run("Isolation", func(t *testing.T) { testIsolation(t, f) })
	t.Run("ScanDiscoveryFields", func(t *testing.T) { testScanDiscoveryFields(t, f) })
	t.Run("TestCaseResults", func(t *testing.T) { testTestCaseResults(t, f) })
}

// testTestCaseResults verifies a TestCase's execution result round-trips through
// create and update, with evidence references isolated from caller mutation.
func testTestCaseResults(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	scanID, jobID := domain.NewID(), domain.NewID()
	now := time.Now().UTC().Truncate(time.Millisecond)

	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: scanID, JobID: jobID, Attempt: 2,
		Status: domain.TestCaseRunning, Method: "POST", URL: "https://x.example/f",
		StartedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	must(t, s.TestCases().Create(ctx, tc))

	ev1, ev2 := domain.NewID(), domain.NewID()
	fin := now.Add(150 * time.Millisecond)
	tc.Status, tc.Outcome = domain.TestCaseCompleted, domain.OutcomeSuccess
	tc.HTTPStatus, tc.DurationMS = 200, 150
	tc.EvidenceIDs = []domain.ID{ev1, ev2}
	tc.Detail = []byte(`{"reflected":true,"count":2}`)
	tc.FinishedAt, tc.UpdatedAt = &fin, fin
	must(t, s.TestCases().Update(ctx, tc))

	got, err := s.TestCases().Get(ctx, tc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != domain.OutcomeSuccess || got.HTTPStatus != 200 || got.DurationMS != 150 || got.Attempt != 2 ||
		got.Method != "POST" || got.URL != "https://x.example/f" || got.Status != domain.TestCaseCompleted {
		t.Fatalf("result not persisted: %+v", got)
	}
	if len(got.EvidenceIDs) != 2 || got.EvidenceIDs[0] != ev1 || got.EvidenceIDs[1] != ev2 {
		t.Fatalf("evidence refs: %v", got.EvidenceIDs)
	}
	if got.StartedAt == nil || got.FinishedAt == nil || !got.FinishedAt.Equal(fin) {
		t.Fatalf("timestamps: started=%v finished=%v", got.StartedAt, got.FinishedAt)
	}
	if string(got.Detail) != `{"reflected":true,"count":2}` {
		t.Fatalf("detail not persisted: %q", got.Detail)
	}

	got.Detail[0] = 'X' // must not alias stored state
	got.EvidenceIDs[0] = domain.NewID()
	again, _ := s.TestCases().Get(ctx, tc.ID)
	if again.EvidenceIDs[0] != ev1 {
		t.Fatal("evidence IDs aliased through the returned pointer")
	}
	if string(again.Detail) != `{"reflected":true,"count":2}` {
		t.Fatal("detail aliased through the returned pointer")
	}

	// A failed attempt keeps its error text and has no evidence.
	bad := &domain.TestCase{ID: domain.NewID(), ScanID: scanID, JobID: jobID, Attempt: 1, Status: domain.TestCaseFailed,
		Outcome: domain.OutcomeTimeout, Error: "deadline exceeded", CreatedAt: now, UpdatedAt: now}
	must(t, s.TestCases().Create(ctx, bad))
	list, _ := s.TestCases().ListByScan(ctx, scanID)
	if len(list) != 2 {
		t.Fatalf("expected 2 test cases (one per attempt), got %d", len(list))
	}
	gb, _ := s.TestCases().Get(ctx, bad.ID)
	if gb.Outcome != domain.OutcomeTimeout || gb.Error != "deadline exceeded" || len(gb.EvidenceIDs) != 0 {
		t.Fatalf("failed attempt: %+v", gb)
	}
}

// testScanDiscoveryFields verifies the seed URLs and discovery state round-trip,
// default correctly, and are isolated from caller mutation.
func testScanDiscoveryFields(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()

	sc := &domain.Scan{
		ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
		SeedURLs:  []string{"https://a.example/", "https://a.example/x"},
		Discovery: domain.DiscoveryRunning,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	must(t, s.Scans().Create(ctx, sc))

	got, err := s.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SeedURLs) != 2 || got.SeedURLs[1] != "https://a.example/x" || got.Discovery != domain.DiscoveryRunning {
		t.Fatalf("round-trip lost fields: seeds=%v discovery=%q", got.SeedURLs, got.Discovery)
	}

	// Mutating the returned slice must not corrupt stored state.
	got.SeedURLs[0] = "https://evil.example/"
	again, _ := s.Scans().Get(ctx, sc.ID)
	if again.SeedURLs[0] != "https://a.example/" {
		t.Fatalf("seed URLs aliased through returned pointer: %v", again.SeedURLs)
	}

	// Update persists the discovery state.
	again.Discovery = domain.DiscoveryComplete
	must(t, s.Scans().Update(ctx, again))
	final, _ := s.Scans().Get(ctx, sc.ID)
	if final.Discovery != domain.DiscoveryComplete {
		t.Fatalf("discovery state not persisted: %q", final.Discovery)
	}

	// An unset discovery state defaults to pending in durable stores; the memory
	// store may keep it empty, so accept either.
	bare := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	must(t, s.Scans().Create(ctx, bare))
	gb, _ := s.Scans().Get(ctx, bare.ID)
	if gb.Discovery != domain.DiscoveryPending && gb.Discovery != "" {
		t.Fatalf("unexpected default discovery state: %q", gb.Discovery)
	}
	if len(gb.SeedURLs) != 0 {
		t.Fatalf("expected no seeds, got %v", gb.SeedURLs)
	}
}

func testProjectCRUD(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()

	p := &domain.Project{ID: domain.NewID(), Name: "Acme", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.Projects().Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := s.Projects().Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Acme" {
		t.Fatalf("name = %q", got.Name)
	}

	got.Name = "Acme Corp"
	if err := s.Projects().Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	reread, _ := s.Projects().Get(ctx, p.ID)
	if reread.Name != "Acme Corp" {
		t.Fatalf("update not persisted: %q", reread.Name)
	}

	list, err := s.Projects().List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d (%v)", len(list), err)
	}

	if err := s.Projects().Delete(ctx, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Projects().Get(ctx, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func testNotFound(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	if _, err := s.Projects().Get(ctx, domain.NewID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.Scans().Update(ctx, &domain.Scan{ID: domain.NewID()}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing scan: expected ErrNotFound, got %v", err)
	}
}

func testScanByProject(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()

	p := &domain.Project{ID: domain.NewID(), Name: "P"}
	must(t, s.Projects().Create(ctx, p))

	for i := 0; i < 3; i++ {
		sc := &domain.Scan{
			ID: domain.NewID(), ProjectID: p.ID, Name: "scan",
			State: domain.ScanCreated, Profile: domain.ProfileBalanced,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		must(t, s.Scans().Create(ctx, sc))
	}
	// A scan in another project must not leak.
	other := &domain.Scan{ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated}
	must(t, s.Scans().Create(ctx, other))

	list, err := s.Scans().ListByProject(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 scans, got %d", len(list))
	}
}

func testDiscoveryChain(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	scanID := domain.NewID()

	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: scanID, URL: "https://x/a", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: time.Now()}
	must(t, s.Endpoints().Create(ctx, ep))

	pm := &domain.Parameter{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, Name: "q", Location: domain.LocationQuery, Source: domain.SourceParamDiscovery, CreatedAt: time.Now()}
	must(t, s.Parameters().Create(ctx, pm))

	ip := &domain.InjectionPoint{ID: domain.NewID(), ScanID: scanID, EndpointID: ep.ID, ParameterID: pm.ID, Location: domain.LocationQuery, CreatedAt: time.Now()}
	must(t, s.InjectionPoints().Create(ctx, ip))

	eps, _ := s.Endpoints().ListByScan(ctx, scanID)
	pmsByEp, _ := s.Parameters().ListByEndpoint(ctx, ep.ID)
	ips, _ := s.InjectionPoints().ListByScan(ctx, scanID)
	if len(eps) != 1 || len(pmsByEp) != 1 || len(ips) != 1 {
		t.Fatalf("discovery chain counts: ep=%d param=%d ip=%d", len(eps), len(pmsByEp), len(ips))
	}
}

func testJobStates(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	scanID := domain.NewID()

	j := &domain.TestJob{
		ID: domain.NewID(), ScanID: scanID, Type: domain.JobTest, State: domain.JobQueued,
		Target: domain.JobTarget{URL: "https://x/a"}, MaxAttempts: 3,
		Payload: []byte(`{"k":"v"}`), AvailableAt: time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	must(t, s.Jobs().Create(ctx, j))

	queued, _ := s.Jobs().ListByState(ctx, scanID, domain.JobQueued)
	if len(queued) != 1 {
		t.Fatalf("expected 1 queued job, got %d", len(queued))
	}

	j.State = domain.JobRunning
	must(t, s.Jobs().Update(ctx, j))
	queued, _ = s.Jobs().ListByState(ctx, scanID, domain.JobQueued)
	running, _ := s.Jobs().ListByState(ctx, scanID, domain.JobRunning)
	if len(queued) != 0 || len(running) != 1 {
		t.Fatalf("after transition: queued=%d running=%d", len(queued), len(running))
	}
	if string(running[0].Payload) != `{"k":"v"}` {
		t.Fatalf("payload round-trip failed: %q", running[0].Payload)
	}
}

func testFindingEvidence(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	scanID, projID := domain.NewID(), domain.NewID()

	find := &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, ProjectID: projID,
		VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictPending,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceMedium,
		Title: "candidate", ParameterID: domain.NewID(),
		Provenance: domain.Provenance{Engine: "reflected-xss", ToolVersion: "test", DiscoverySource: domain.SourceCrawler},
		CreatedAt:  time.Now(), UpdatedAt: time.Now(),
	}
	must(t, s.Findings().Create(ctx, find))

	ev := &domain.Evidence{
		ID: domain.NewID(), ScanID: scanID, FindingID: find.ID,
		Kind: domain.EvidenceResponse, BlobPath: "resp/1.bin", Size: 10, SHA256: "abc", CreatedAt: time.Now(),
	}
	must(t, s.Evidence().Create(ctx, ev))

	find.Verdict = domain.VerdictConfirmed
	find.EvidenceIDs = []domain.ID{ev.ID}
	find.Detail = []byte(`{"dedup_key":"k","occurrences":2}`)
	must(t, s.Findings().Update(ctx, find))

	got, _ := s.Findings().Get(ctx, find.ID)
	if got.Verdict != domain.VerdictConfirmed || len(got.EvidenceIDs) != 1 {
		t.Fatalf("finding update: verdict=%s evidence=%d", got.Verdict, len(got.EvidenceIDs))
	}
	if got.ParameterID != find.ParameterID || got.Provenance.DiscoverySource != domain.SourceCrawler {
		t.Fatalf("finding provenance round-trip: parameter=%q discovery_source=%q", got.ParameterID, got.Provenance.DiscoverySource)
	}
	if string(got.Detail) != `{"dedup_key":"k","occurrences":2}` {
		t.Fatalf("finding detail round-trip: %q", got.Detail)
	}
	byFinding, _ := s.Evidence().ListByFinding(ctx, find.ID)
	if len(byFinding) != 1 {
		t.Fatalf("evidence by finding = %d", len(byFinding))
	}
}

func testSessionByScan(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()
	scanID := domain.NewID()
	sess := &domain.Session{ID: domain.NewID(), ScanID: scanID, Mode: domain.AuthAnonymous, State: domain.SessionActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	must(t, s.Sessions().Create(ctx, sess))
	got, err := s.Sessions().GetByScan(ctx, scanID)
	if err != nil || got.ID != sess.ID {
		t.Fatalf("GetByScan: %v", err)
	}
}

// testIsolation verifies that mutating a returned entity does not corrupt stored
// state (deep-copy semantics).
func testIsolation(t *testing.T, f Factory) {
	s, done := f(t)
	defer done()
	ctx := context.Background()

	sc := &domain.Scope{ID: domain.NewID(), ProjectID: domain.NewID(), IncludeHosts: []string{"a.com"}}
	must(t, s.Scopes().Create(ctx, sc))

	got, _ := s.Scopes().Get(ctx, sc.ID)
	got.IncludeHosts[0] = "evil.com" // mutate the returned slice
	got.IncludeHosts = append(got.IncludeHosts, "more.com")

	reread, _ := s.Scopes().Get(ctx, sc.ID)
	if len(reread.IncludeHosts) != 1 || reread.IncludeHosts[0] != "a.com" {
		t.Fatalf("stored scope was mutated through returned pointer: %v", reread.IncludeHosts)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

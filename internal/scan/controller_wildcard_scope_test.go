package scan_test

// Controller-level coverage for a wildcard-only scope (subdomain_only_hosts and
// no include hosts), the shape a bug-bounty wildcard asset imports into.
//
// The controller used to treat "no include hosts" as an empty scope, so an
// imported wildcard program failed at CreateScan/Start/Resume even though
// Scope.Permits authorized its subdomains. These tests pin the three entry
// points (create, start, resume) plus the two negatives that must keep failing
// closed: a target at the wildcard apex, and a scope that authorizes nothing.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// setupScopeFixture is setupWith with an explicit scope and target URL, so a
// test can describe a wildcard-only scope and a target under it.
func setupScopeFixture(t *testing.T, scope domain.Scope, targetURL string, opts scan.Options) fixture {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	q := queue.NewMemory()
	if opts.IdlePoll == 0 {
		opts.IdlePoll = 10 * time.Millisecond
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 20 * time.Millisecond
	}
	ctrl := scan.NewController(st, q, quiet(), "test", opts)
	t.Cleanup(ctrl.Shutdown)

	proj := &domain.Project{ID: domain.NewID(), Name: "p"}
	if err := st.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "t", BaseURL: targetURL}
	if err := st.Targets().Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	scope.ID = domain.NewID()
	scope.ProjectID = proj.ID
	if err := st.Scopes().Create(ctx, &scope); err != nil {
		t.Fatal(err)
	}
	return fixture{store: st, queue: q, ctrl: ctrl, proj: proj.ID, tgt: tgt.ID}
}

func wildcardScope() domain.Scope {
	return domain.Scope{SubdomainOnlyHosts: []string{"example.com"}}
}

func TestCreateScanWildcardOnlyScope(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		target string
	}{
		{"direct subdomain", "https://app.example.com/"},
		{"deeper subdomain", "https://a.b.example.com/"},
		{"subdomain with a path", "https://app.example.com/portal/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupScopeFixture(t, wildcardScope(), c.target, scan.Options{})
			sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
				ProjectID: f.proj, TargetID: f.tgt, Name: c.name,
			})
			if err != nil {
				t.Fatalf("CreateScan(%s) under a wildcard-only scope: %v", c.target, err)
			}
			if sc.State != domain.ScanCreated {
				t.Fatalf("state = %s, want created", sc.State)
			}
		})
	}
}

// A wildcard asset does not authorize its apex, so a target at the apex must be
// refused — and refused as out-of-scope, not as an "empty scope".
func TestCreateScanWildcardOnlyScopeDeniesApex(t *testing.T) {
	f := setupScopeFixture(t, wildcardScope(), "https://example.com/", scan.Options{})
	_, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Name: "apex",
	})
	if !errors.Is(err, scan.ErrOutOfScope) {
		t.Fatalf("apex target under *.example.com: got %v, want ErrOutOfScope", err)
	}
	if errors.Is(err, scan.ErrScopeEmpty) {
		t.Fatal("apex refusal was reported as an empty scope")
	}
}

// The wildcard list must not become a loophole for a scope that authorizes
// nothing: only exclusions, or both lists empty, still fail closed.
func TestCreateScanScopeAuthorizingNothingStillFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, scope := range map[string]domain.Scope{
		"both lists empty":   {},
		"exclusions only":    {ExcludeHosts: []string{"example.com"}},
		"path prefixes only": {IncludePathPrefixes: []string{"/app"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := setupScopeFixture(t, scope, "https://app.example.com/", scan.Options{})
			_, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
				ProjectID: f.proj, TargetID: f.tgt, Name: name,
			})
			if !errors.Is(err, scan.ErrScopeEmpty) {
				t.Fatalf("got %v, want ErrScopeEmpty", err)
			}
		})
	}
}

// Start re-checks scope (defense in depth). A wildcard-only scope must pass;
// the scan has to reach the worker pipeline rather than bounce off loadScope.
func TestStartWildcardOnlyScope(t *testing.T) {
	ctx := context.Background()
	handlers, release := holdJobs()
	defer release()
	f := setupScopeFixture(t, wildcardScope(), "https://app.example.com/", scan.Options{Handlers: handlers})

	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Name: "start-wildcard",
		Profile: domain.ProfileConservative, AuthMode: domain.AuthAnonymous,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("Start under a wildcard-only scope: %v", err)
	}
	if !f.ctrl.IsRunning(sc.ID) {
		t.Fatal("scan should be running")
	}
	sess, _ := f.store.Sessions().GetByScan(ctx, sc.ID)
	if sess == nil || sess.State != domain.SessionActive {
		t.Fatalf("session = %+v, want an active session", sess)
	}
	// The seed really entered the pipeline: discovery registered it and the
	// pipeline produced work, all under the wildcard scope.
	waitFor(t, 2*time.Second, func() bool {
		st, _ := f.ctrl.Stats(ctx, sc.ID)
		return st.Running+st.Queued >= 1
	})
}

// Start must still refuse a scope that was emptied after the scan was created.
func TestStartEmptyScopeFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := setupScopeFixture(t, domain.Scope{IncludeHosts: []string{"app.example.com"}}, "https://app.example.com/", scan.Options{})
	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: f.proj, TargetID: f.tgt})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := clearStoredScope(t, f, ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.ctrl.Start(ctx, sc.ID); !errors.Is(err, scan.ErrScopeEmpty) {
		t.Fatalf("Start with an emptied scope: got %v, want ErrScopeEmpty", err)
	}
	got, _ := f.store.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanCreated {
		t.Fatalf("state = %s, want the scan to stay created", got.State)
	}
}

// Resume without a live execution (the after-restart path) loads the scope
// again. A persisted paused scan with a wildcard-only scope must resume.
func TestResumeWildcardOnlyScopeAfterRestart(t *testing.T) {
	ctx := context.Background()
	handlers, release := holdJobs()
	defer release()
	f := setupScopeFixture(t, wildcardScope(), "https://app.example.com/", scan.Options{Handlers: handlers})

	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Name: "resume-wildcard",
		Profile: domain.ProfileConservative, AuthMode: domain.AuthAnonymous,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pauseOnDisk(t, f, ctx, sc.ID)

	if err := f.ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatalf("Resume under a wildcard-only scope: %v", err)
	}
	if !f.ctrl.IsRunning(sc.ID) {
		t.Fatal("restored scan should be running")
	}
	got, _ := f.store.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanRunning {
		t.Fatalf("state = %s, want running", got.State)
	}
}

// Resume must keep failing closed when the scope was emptied while the scan was
// paused, and must leave the scan paused so the operator can fix the scope.
func TestResumeEmptyScopeFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := setupScopeFixture(t, domain.Scope{IncludeHosts: []string{"app.example.com"}}, "https://app.example.com/", scan.Options{})
	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: f.proj, TargetID: f.tgt})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pauseOnDisk(t, f, ctx, sc.ID)
	if err := clearStoredScope(t, f, ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrScopeEmpty) {
		t.Fatalf("Resume with an emptied scope: got %v, want ErrScopeEmpty", err)
	}
	got, _ := f.store.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanPaused {
		t.Fatalf("state = %s, want the scan to stay paused", got.State)
	}
}

// pauseOnDisk moves a scan to paused through the store, which is the state a
// restart leaves behind (no live execution for Resume to reuse).
func pauseOnDisk(t *testing.T, f fixture, ctx context.Context, id domain.ID) {
	t.Helper()
	sc, err := f.store.Scans().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	sc.State = domain.ScanPaused
	if err := f.store.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
}

// clearStoredScope replaces the project's scope with one that authorizes
// nothing, keeping the row (so the failure is ErrScopeEmpty, not
// ErrScopeRequired).
func clearStoredScope(t *testing.T, f fixture, ctx context.Context) error {
	t.Helper()
	sc, err := f.store.Scopes().GetByProject(ctx, f.proj)
	if err != nil {
		return err
	}
	sc.IncludeHosts = nil
	sc.SubdomainOnlyHosts = nil
	return f.store.Scopes().Update(ctx, sc)
}

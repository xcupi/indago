package scan_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fixture struct {
	store store.Store
	queue *queue.Memory
	ctrl  *scan.Controller
	proj  domain.ID
	tgt   domain.ID
}

func setup(t *testing.T, withScope bool, hosts []string) fixture {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	q := queue.NewMemory()
	ctrl := scan.NewController(st, q, quiet(), "test", scan.Options{IdlePoll: 10 * time.Millisecond})

	proj := &domain.Project{ID: domain.NewID(), Name: "p"}
	if err := st.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "t", BaseURL: "https://example.com/"}
	if err := st.Targets().Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	if withScope {
		sc := &domain.Scope{ID: domain.NewID(), ProjectID: proj.ID, IncludeHosts: hosts}
		if err := st.Scopes().Create(ctx, sc); err != nil {
			t.Fatal(err)
		}
	}
	return fixture{store: st, queue: q, ctrl: ctrl, proj: proj.ID, tgt: tgt.ID}
}

func TestCreateScanRequiresScope(t *testing.T) {
	f := setup(t, false, nil)
	_, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
	})
	if !errors.Is(err, scan.ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestCreateScanEmptyScopeFailsClosed(t *testing.T) {
	f := setup(t, true, []string{}) // scope row exists but has no hosts
	_, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
	})
	if !errors.Is(err, scan.ErrScopeEmpty) {
		t.Fatalf("expected ErrScopeEmpty, got %v", err)
	}
}

func TestCreateScanOutOfScope(t *testing.T) {
	f := setup(t, true, []string{"other.com"})
	_, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
	})
	if !errors.Is(err, scan.ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope, got %v", err)
	}
}

func TestScanLifecycle(t *testing.T) {
	ctx := context.Background()
	f := setup(t, true, []string{"example.com"})

	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Name: "run1",
		Profile: domain.ProfileConservative, AuthMode: domain.AuthAnonymous,
		Stop: domain.StopPolicy{Mode: domain.StopContinueAll},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sc.State != domain.ScanCreated {
		t.Fatalf("state = %s", sc.State)
	}

	if err := f.ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !f.ctrl.IsRunning(sc.ID) {
		t.Fatal("scan should be running")
	}

	// Session should now be active.
	sess, _ := f.store.Sessions().GetByScan(ctx, sc.ID)
	if sess.State != domain.SessionActive {
		t.Fatalf("session state = %s", sess.State)
	}

	// Seed a job; the no-op handler should complete it.
	if err := f.queue.Enqueue(ctx, &domain.TestJob{ScanID: sc.ID, Type: domain.JobTest, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool {
		st, _ := f.ctrl.Stats(ctx, sc.ID)
		return st.Succeeded == 1
	})

	// Pause / resume.
	if err := f.ctrl.Pause(ctx, sc.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	got, _ := f.store.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanPaused {
		t.Fatalf("paused state = %s", got.State)
	}
	if err := f.ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}

	// Runtime reconfiguration.
	if err := f.ctrl.Reconfigure(ctx, sc.ID, domain.ScanConfig{
		DiscoveryConcurrency: 1, HTTPConcurrency: 3, BrowserConcurrency: 1, RequestsPerSecond: 5,
	}); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	got, _ = f.store.Scans().Get(ctx, sc.ID)
	if got.Config.HTTPConcurrency != 3 || got.Profile != domain.ProfileCustom {
		t.Fatalf("reconfigure not persisted: %+v profile=%s", got.Config, got.Profile)
	}

	// Cancel.
	if err := f.ctrl.Cancel(ctx, sc.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	got, _ = f.store.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanCanceled {
		t.Fatalf("canceled state = %s", got.State)
	}
	if f.ctrl.IsRunning(sc.ID) {
		t.Fatal("scan should not be running after cancel")
	}
}

func TestStartRejectsNonCreated(t *testing.T) {
	ctx := context.Background()
	f := setup(t, true, []string{"example.com"})
	sc, _ := f.ctrl.CreateScan(ctx, scan.CreateScanParams{ProjectID: f.proj, TargetID: f.tgt})
	if err := f.ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	defer f.ctrl.Shutdown()
	// Second start must fail (already running, not Created).
	if err := f.ctrl.Start(ctx, sc.ID); !errors.Is(err, scan.ErrBadState) {
		t.Fatalf("expected ErrBadState, got %v", err)
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

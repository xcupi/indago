package scan_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

// TestScanWithNoRunnableJobsReachesTerminalState is the terminal-state
// guarantee: once discovery has finished and the only jobs left are of a type
// this execution can never run — no registered handler, no worker group that
// names it — the scan must not sit in `running` forever waiting for a queue
// that can never drain. It must fail (with a reason an operator can act on) and
// tear the execution down.
func TestScanWithNoRunnableJobsReachesTerminalState(t *testing.T) {
	ctx := context.Background()
	f := setupWith(t, true, []string{"example.com"}, scan.Options{
		PollInterval: 20 * time.Millisecond,
		IdlePoll:     10 * time.Millisecond,
	})

	sc, err := f.ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: f.proj,
		TargetID:  f.tgt,
		Name:      "no-runnable-jobs",
		Profile:   domain.ProfileBalanced,
		Stop:      domain.StopPolicy{Mode: domain.StopContinueAll},
		AuthMode:  domain.AuthAnonymous,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A job type the execution's pool neither handles nor serves. Enqueued
	// before Start so the monitor can never observe a transiently empty queue
	// and complete the scan first.
	orphan := &domain.TestJob{ScanID: sc.ID, Type: domain.JobType("orphan"), MaxAttempts: 2}
	if err := f.queue.Enqueue(ctx, orphan); err != nil {
		t.Fatalf("enqueue orphan job: %v", err)
	}

	if err := f.ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		got, err := f.store.Scans().Get(ctx, sc.ID)
		return err == nil && got.State.IsTerminal()
	})

	got, err := f.store.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanFailed {
		t.Fatalf("scan state = %s, want failed (jobs queued but no worker can run them)", got.State)
	}
	if !strings.Contains(got.Error, "no worker group") {
		t.Fatalf("failure reason = %q, want it to explain the unrunnable queue", got.Error)
	}
	if f.ctrl.IsRunning(sc.ID) {
		t.Fatal("execution was left running after the scan reached a terminal state")
	}
}

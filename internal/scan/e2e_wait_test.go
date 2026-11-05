package scan_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
)

// The authenticated flow scans the whole corpus: a finite workload of ~230 jobs
// (about 110 HTTP tests, 40 verifications and 85 DOM-XSS probes), the last of
// which are real browser navigations serialized through one browser pool. It
// takes ~21-25s locally under -race and was measured finishing within a few
// jobs of 60s on the ~3x slower hosted runner (queue empty, nothing dead), so a
// bare 60s wall-clock deadline measured the runner, not the product. A stuck
// scan is still caught: waitCompletedWhileProgressing fails immediately on any
// dead or failed job and after authedScanStallWindow with no job finishing; the
// overall cap only bounds a scan that keeps finishing jobs slowly.
const (
	authedScanMaxDuration = 180 * time.Second
	authedScanStallWindow = 30 * time.Second
)

// waitCompletedWhileProgressing waits for the scan to complete, failing fast on
// a dead/failed job, failing when no job has finished for stall, and failing at
// max regardless. It never treats a slow-but-advancing scan as stuck, and never
// treats a stalled one as slow.
func waitCompletedWhileProgressing(t testing.TB, status func() (*scan.Status, error), max, stall time.Duration) *scan.Status {
	t.Helper()
	start := time.Now()
	lastProgress := start
	lastDone := -1
	var last *scan.Status
	for time.Since(start) < max {
		st, err := status()
		if err == nil {
			last = st
			// Job failures are checked BEFORE completion: a scan can reach
			// "completed" with dead/failed/canceled jobs, and that is not
			// successful coverage (a canceled job never ran its test).
			if st.Jobs.Dead > 0 || st.Jobs.Failed > 0 || st.Jobs.Canceled > 0 {
				t.Fatalf("dead/failed/canceled job after %s; scan=%s jobs=%+v", time.Since(start).Round(time.Second), st.Scan.State, st.Jobs)
			}
			if st.Scan.State == domain.ScanCanceled || st.Scan.State == domain.ScanFailed {
				t.Fatalf("scan ended %s after %s; jobs=%+v", st.Scan.State, time.Since(start).Round(time.Second), st.Jobs)
			}
			if st.Scan.State == domain.ScanCompleted {
				return st
			}
			if done := st.Jobs.Succeeded + st.Jobs.Failed + st.Jobs.Dead + st.Jobs.Canceled; done != lastDone {
				lastDone, lastProgress = done, time.Now()
			}
			if time.Since(lastProgress) > stall {
				t.Fatalf("no job finished for %s (stalled at %d finished); scan=%s discovery=%s jobs=%+v", stall, lastDone, st.Scan.State, st.Discovery.State, st.Jobs)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if last == nil {
		t.Fatalf("status never available within %s", max)
	}
	t.Fatalf("still progressing but not complete within %s; scan=%s discovery=%s jobs=%+v", max, last.Scan.State, last.Discovery.State, last.Jobs)
	return nil
}

// recordingTB captures Fatalf so the wait policy can be tested for failure.
type recordingTB struct {
	testing.TB
	failed string
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.failed = format
	panic(errFatal)
}

var errFatal = errors.New("fatal")

func runWait(t *testing.T, status func() (*scan.Status, error), max, stall time.Duration) (failed string, st *scan.Status) {
	t.Helper()
	rec := &recordingTB{TB: t}
	defer func() {
		if r := recover(); r != nil && r != errFatal {
			panic(r)
		}
		failed = rec.failed
	}()
	st = waitCompletedWhileProgressing(rec, status, max, stall)
	return "", st
}

func jobsStatus(state domain.ScanState, j queue.Stats) *scan.Status {
	return &scan.Status{Scan: &domain.Scan{State: state}, Jobs: j}
}

// A slow scan that keeps finishing jobs must pass even past the stall window; a
// stalled one must fail at the stall window, not at the overall cap; a dead job
// fails immediately.
func TestWaitCompletedWhileProgressingDiscriminatesSlowFromStuck(t *testing.T) {
	t.Run("slow but advancing completes", func(t *testing.T) {
		start := time.Now()
		status := func() (*scan.Status, error) {
			n := int(time.Since(start) / (20 * time.Millisecond))
			if n >= 10 {
				return jobsStatus(domain.ScanCompleted, queue.Stats{Succeeded: 10}), nil
			}
			return jobsStatus(domain.ScanRunning, queue.Stats{Succeeded: n, Running: 1}), nil
		}
		if failed, st := runWait(t, status, 5*time.Second, 100*time.Millisecond); failed != "" || st == nil {
			t.Fatalf("an advancing scan must not be failed: %q", failed)
		}
	})
	t.Run("stalled fails at the stall window", func(t *testing.T) {
		status := func() (*scan.Status, error) {
			return jobsStatus(domain.ScanRunning, queue.Stats{Succeeded: 229, Running: 4}), nil
		}
		begin := time.Now()
		failed, _ := runWait(t, status, 10*time.Second, 150*time.Millisecond)
		if !strings.Contains(failed, "no job finished") {
			t.Fatalf("a stalled scan must fail as stalled, got %q", failed)
		}
		if time.Since(begin) > 3*time.Second {
			t.Fatalf("a stalled scan must fail at the stall window, took %s", time.Since(begin))
		}
	})
	t.Run("dead job fails immediately", func(t *testing.T) {
		status := func() (*scan.Status, error) {
			return jobsStatus(domain.ScanRunning, queue.Stats{Succeeded: 5, Dead: 1}), nil
		}
		if failed, _ := runWait(t, status, 10*time.Second, 5*time.Second); !strings.Contains(failed, "dead/failed/canceled") {
			t.Fatalf("a dead job must fail the wait, got %q", failed)
		}
	})
	// A scan can reach "completed" while jobs died, failed or were canceled;
	// none of those is successful authenticated coverage.
	for name, jobs := range map[string]queue.Stats{
		"completed with a dead job":     {Succeeded: 228, Dead: 1},
		"completed with a failed job":   {Succeeded: 228, Failed: 1},
		"completed with a canceled job": {Succeeded: 228, Canceled: 1},
	} {
		jobs := jobs
		t.Run(name+" is rejected", func(t *testing.T) {
			status := func() (*scan.Status, error) { return jobsStatus(domain.ScanCompleted, jobs), nil }
			if failed, _ := runWait(t, status, 5*time.Second, time.Second); !strings.Contains(failed, "dead/failed/canceled") {
				t.Fatalf("%s must not be accepted, got %q", name, failed)
			}
		})
	}
	for _, state := range []domain.ScanState{domain.ScanCanceled, domain.ScanFailed} {
		state := state
		t.Run("terminal "+string(state)+" scan is rejected promptly", func(t *testing.T) {
			status := func() (*scan.Status, error) {
				return jobsStatus(state, queue.Stats{Succeeded: 100, Queued: 5}), nil
			}
			begin := time.Now()
			if failed, _ := runWait(t, status, 10*time.Second, 5*time.Second); !strings.Contains(failed, "scan ended") {
				t.Fatalf("a %s scan must be rejected, got %q", state, failed)
			}
			if time.Since(begin) > 2*time.Second {
				t.Fatalf("a terminal %s scan must be rejected promptly, took %s", state, time.Since(begin))
			}
		})
	}
	t.Run("clean completion is accepted", func(t *testing.T) {
		status := func() (*scan.Status, error) {
			return jobsStatus(domain.ScanCompleted, queue.Stats{Succeeded: 233}), nil
		}
		if failed, st := runWait(t, status, 5*time.Second, time.Second); failed != "" || st == nil {
			t.Fatalf("a clean completed scan must be accepted: %q", failed)
		}
	})
	t.Run("progressing past the cap still fails", func(t *testing.T) {
		n := 0
		status := func() (*scan.Status, error) {
			n++
			return jobsStatus(domain.ScanRunning, queue.Stats{Succeeded: n, Running: 1}), nil
		}
		if failed, _ := runWait(t, status, 200*time.Millisecond, time.Second); !strings.Contains(failed, "still progressing") {
			t.Fatalf("the overall cap must still bound the wait, got %q", failed)
		}
	})
}

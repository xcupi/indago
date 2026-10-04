package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/indago/indago/internal/domain"
)

// Recover requeues jobs left leased/running by a previous process. Call it once
// at startup, before RecoverScans and before any scan is resumed: no worker can
// legitimately hold a lease at process start.
//
// It also closes out test cases the dead process left in the "running" state
// (marked cancelled: interrupted by restart); their jobs are requeued and will
// record a fresh test case when they run again.
func (c *Controller) Recover(ctx context.Context) (int, error) {
	n, err := c.queue.Recover(ctx)
	if err != nil {
		return n, err
	}
	if err := c.interruptStaleTestCases(ctx); err != nil {
		c.log.Warn("could not close out interrupted test cases", "err", err)
	}
	return n, nil
}

// interruptStaleTestCases marks every running test case cancelled. Only valid at
// startup, when no execution can legitimately be mid-request.
func (c *Controller) interruptStaleTestCases(ctx context.Context) error {
	scans, err := c.store.Scans().List(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, sc := range scans {
		cases, err := c.store.TestCases().ListByScan(ctx, sc.ID)
		if err != nil {
			return err
		}
		for _, tc := range cases {
			if tc.Status != domain.TestCaseRunning {
				continue
			}
			tc.Status, tc.Outcome = domain.TestCaseCancelled, domain.OutcomeCancelled
			tc.Error = "interrupted by restart"
			tc.FinishedAt, tc.UpdatedAt = &now, now
			if err := c.store.TestCases().Update(ctx, tc); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecoverScans reconciles persisted scan state after a restart and returns how
// many scans it changed.
//
// Policy — a restart never sends traffic on its own:
//
//   - RUNNING scans were interrupted; they are restored as PAUSED. The operator
//     resumes them, and Resume rebuilds the worker pool and discovery (discovery
//     deduplicates against what it already persisted, so nothing is repeated).
//   - CANCELING scans were mid-cancel; the cancel is completed.
//   - CREATED, PAUSED, AWAITING_AUTH, and terminal scans are left as they are.
//
// Call Recover (jobs) first, then RecoverScans, then start serving.
func (c *Controller) RecoverScans(ctx context.Context) (int, error) {
	scans, err := c.store.Scans().List(ctx)
	if err != nil {
		return 0, fmt.Errorf("scan: recover: list scans: %w", err)
	}
	changed := 0
	for _, sc := range scans {
		if c.IsRunning(sc.ID) {
			continue // owned by a live execution
		}
		switch sc.State {
		case domain.ScanRunning:
			if _, err := c.mutate(ctx, sc.ID, func(s *domain.Scan) error {
				if s.State != domain.ScanRunning {
					return errSkipWrite
				}
				return transition(s, domain.ScanPaused)
			}); err != nil {
				return changed, fmt.Errorf("scan: recover %s: %w", sc.ID, err)
			}
			c.log.Info("scan interrupted by restart; restored as paused (resume to continue)",
				"scan", sc.ID, "discovery", sc.Discovery)
			changed++
		case domain.ScanCanceling:
			if err := c.finalizeCancel(ctx, sc.ID); err != nil {
				return changed, fmt.Errorf("scan: recover %s: finish cancel: %w", sc.ID, err)
			}
			changed++
		}
	}
	return changed, nil
}

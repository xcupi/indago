package scan_test

// Session expiration: domain.Session documents that the scanner never
// silently re-authenticates — on expiry the scan moves to AwaitingAuth and
// Resume re-establishes the session. These tests drive that through a real
// Controller (the state machine, auth.Authenticator, and SessionRepo were all
// already wired for this; only the monitor-side check and Resume's
// re-authentication call were missing).

import (
	"context"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestSessionExpiryPausesScanAwaitingAuth(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanRunning })

	// Force the established session to have already expired (anonymous
	// sessions never set one on their own) and let the monitor discover it.
	sess, err := st.Sessions().GetByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != domain.SessionActive {
		t.Fatalf("session should be active once the scan is running, got %s", sess.State)
	}
	past := time.Now().Add(-time.Hour)
	sess.ExpiresAt = &past
	if err := st.Sessions().Update(ctx, sess); err != nil {
		t.Fatal(err)
	}

	waitStatus(t, ctrl, sc.ID, 3*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanAwaitingAuth })

	expired, err := st.Sessions().GetByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != domain.SessionExpired {
		t.Fatalf("session state = %s, want expired", expired.State)
	}

	// No further target-facing work happens while awaiting auth.
	hitsAtPause := s.hitCount("/")
	time.Sleep(150 * time.Millisecond)
	if s.hitCount("/") != hitsAtPause {
		t.Fatal("work continued against the target while awaiting re-authentication")
	}

	// Resume re-establishes the session (anonymous: trivially succeeds, clears
	// ExpiresAt and Expired) and the scan returns to Running.
	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 3*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanRunning })

	reestablished, err := st.Sessions().GetByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reestablished.State != domain.SessionActive || reestablished.ExpiresAt != nil {
		t.Fatalf("session not re-established: state=%s expires=%v", reestablished.State, reestablished.ExpiresAt)
	}

	waitStatus(t, ctrl, sc.ID, 8*time.Second, isCompleted)
}

// A session that is already expired when the operator restores a persisted
// (no live execution) AwaitingAuth scan must also be re-established by Resume.
func TestSessionExpiryReestablishedOnRestoredResume(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanRunning })

	sess, _ := st.Sessions().GetByScan(ctx, sc.ID)
	past := time.Now().Add(-time.Hour)
	sess.ExpiresAt = &past
	if err := st.Sessions().Update(ctx, sess); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 3*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanAwaitingAuth })

	// Shutdown drops the live execution without changing persisted state, as it
	// does for a plain Paused scan; Resume then takes the "restore" path.
	ctrl.Shutdown()
	ctrl2 := newCtrl(t, st, q, scan.Options{})
	if err := ctrl2.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl2, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanRunning })

	reestablished, _ := st.Sessions().GetByScan(ctx, sc.ID)
	if reestablished.State != domain.SessionActive || reestablished.ExpiresAt != nil {
		t.Fatalf("session not re-established after restore: state=%s expires=%v", reestablished.State, reestablished.ExpiresAt)
	}
}

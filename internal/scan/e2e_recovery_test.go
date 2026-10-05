package scan_test

// Real-browser crash/restart recovery: a JobVerify job interrupted mid-
// navigation must be requeued and, after a restart with a fresh browser
// Manager, actually complete and confirm the finding — not get stuck, and not
// leave the finding permanently Pending.

import (
	"context"
	"html"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/scan"
)

// gatedCorpus reflects into an executable HTML-text position, but blocks the
// response to any request that does NOT carry the HTTP engine's own User-Agent
// — i.e. it blocks the BROWSER's navigation (verification) while letting the
// plain HTTP-level baseline/candidate steps through immediately, so a scan can
// be "crashed" with a verify job provably stuck mid-navigation.
//
// verifying receives one value each time a browser navigation carrying a
// candidate (anything but the page's own q=hi link) is parked at the gate.
// That — not merely "some job is running" — is the precondition for the
// crash: a weaker check let the crash land during discovery instead, which is
// a different scenario (covered deterministically by
// TestRestartTestsInjectionPointWhoseJobWasLostToShutdown).
func newGatedCorpus(t *testing.T) (s *site, release func(), verifying <-chan struct{}) {
	gate := make(chan struct{})
	parked := make(chan struct{}, 64)
	var once sync.Once
	s = newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/confirmed?q=hi">confirmed</a>`)
		})
		mux.HandleFunc("/confirmed", func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("User-Agent"), "Indago") {
				if r.URL.Query().Get("q") != "hi" {
					select {
					case parked <- struct{}{}:
					default:
					}
				}
				select { // a real browser navigating: hold it
				case <-gate:
				case <-r.Context().Done():
					return
				}
			}
			writeHTML(w, "<div>"+html.EscapeString(r.URL.Query().Get("q"))+"</div><div>"+r.URL.Query().Get("q")+"</div>")
		})
	})
	return s, func() { once.Do(func() { close(gate) }) }, parked
}

func TestE2E_RestartRecoversInterruptedVerification(t *testing.T) {
	ctx := context.Background()
	s, release, verifying := newGatedCorpus(t)
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	mgr1 := newBrowserManagerOrSkip(t, 1)

	ctrl1 := newCtrl(t, db, q, scan.Options{Browser: mgr1, Evidence: ev})
	sc := createScan(t, ctrl1, proj, tgt, workersCfgWithBrowser(4, 1), domain.StopPolicy{})
	if err := ctrl1.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	// Wait until verification's real browser navigation is parked at the gate,
	// i.e. the verify job is provably mid-navigation.
	select {
	case <-verifying:
	case <-time.After(15 * time.Second):
		t.Fatal("verification never navigated to the candidate")
	}

	// "Crash": stop everything (this cancels the in-flight navigation too),
	// leave persisted state as it is, and close the database.
	ctrl1.Shutdown()
	mgr1.Close()
	pre, err := ctrl1.Status(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pre.Jobs.Leased+pre.Jobs.Running == 0 {
		t.Fatalf("test setup: expected an active verify job at crash time, got %+v", pre.Jobs)
	}
	if pre.Findings.Pending != 1 {
		t.Fatalf("test setup: expected the reflected candidate's Pending finding at crash time, got %+v", pre.Findings)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	release() // the server stops gating once a fresh attempt arrives

	// --- restart: fresh database handle, fresh browser Manager, new Controller ---
	db2, q2 := openSQLite(t, dbPath)
	defer db2.Close()
	mgr2 := newBrowserManagerOrSkip(t, 1)
	defer mgr2.Close()
	ctrl2 := newCtrl(t, db2, q2, scan.Options{Browser: mgr2, Evidence: ev})

	if _, err := ctrl2.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl2.RecoverScans(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ctrl2.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl2, sc.ID, 20*time.Second, isCompleted)

	findings, err := db2.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding (no duplicates from the crash), got %d: %+v", len(findings), findings)
	}
	if findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed after the restart completes verification", findings[0].Verdict)
	}
	if findings[0].Provenance.VerifiedAt == nil {
		t.Fatal("verified_at not set")
	}
	if stats := mgr2.Stats(); stats.OpenContexts != 0 {
		t.Fatalf("browser contexts leaked after restart: %d still open", stats.OpenContexts)
	}
	_ = done
}

// Repeated crash/restart while verification is mid-navigation: the verify job
// is interrupted three times in a row, each time by a full "crash" (controller
// shutdown, browser Manager closed, database closed) and a restart with fresh
// instances. It must neither get stuck nor duplicate the finding, and the
// finding must end Confirmed with its evidence intact and no browser context
// leaked by any of the four Managers.
func TestE2E_RepeatedCrashRestartDuringVerification(t *testing.T) {
	const crashes = 3
	ctx := context.Background()
	s, release, verifying := newGatedCorpus(t)
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	mgr := newBrowserManagerOrSkip(t, 1)
	ctrl := newCtrl(t, db, q, scan.Options{Browser: mgr, Evidence: ev})
	sc := createScan(t, ctrl, proj, tgt, workersCfgWithBrowser(4, 1), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	for i := 0; i <= crashes; i++ {
		if i == crashes {
			release() // final run: let verification through
		} else {
			select {
			case <-verifying:
			case <-time.After(30 * time.Second):
				t.Fatalf("crash %d: verification never navigated to the candidate", i+1)
			}
			ctrl.Shutdown()
			if err := mgr.Close(); err != nil {
				t.Fatal(err)
			}
			if stats := mgr.Stats(); stats.OpenContexts != 0 {
				t.Fatalf("crash %d: %d browser contexts left open by Close", i+1, stats.OpenContexts)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, q = openSQLite(t, dbPath)
			mgr = newBrowserManagerOrSkip(t, 1)
			ctrl = newCtrl(t, db, q, scan.Options{Browser: mgr, Evidence: ev})
			if _, err := ctrl.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := ctrl.RecoverScans(ctx); err != nil {
				t.Fatal(err)
			}
			if err := ctrl.Resume(ctx, sc.ID); err != nil {
				t.Fatalf("crash %d: resume: %v", i+1, err)
			}
		}
	}
	defer db.Close()
	defer mgr.Close()
	waitStatus(t, ctrl, sc.ID, 30*time.Second, isCompleted)

	findings := assertScanIntegrity(t, db, ev, q, sc.ID, 1)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed || findings[0].Provenance.VerifiedAt == nil {
		t.Fatalf("want one confirmed, verified finding after %d crashes, got %+v", crashes, findings)
	}
	if stats := mgr.Stats(); stats.OpenContexts != 0 {
		t.Fatalf("browser contexts leaked after the final run: %d still open", stats.OpenContexts)
	}
}

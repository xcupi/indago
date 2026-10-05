package scan_test

// Restart/recovery tests. They use a real SQLite file and a genuine "restart":
// shut the first controller down, close the database, reopen the same file, and
// build a brand-new controller over it.

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/sqlite"
)

func openSQLite(t *testing.T, path string) (*sqlite.DB, *queue.SQLite) {
	t.Helper()
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db, queue.NewSQLite(db.SQL())
}

// recoverySite has a slow page (/slow) so discovery is provably in flight when
// the process "crashes"; /slow links to /after, which only a resumed discovery
// can find.
type recoverySite struct {
	*site
	releaseSlow func()
}

func newRecoverySite(t *testing.T) *recoverySite {
	gate := make(chan struct{})
	var once sync.Once
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/a">a</a> <a href="/slow">slow</a>
				<form action="/f" method="get"><input name="fld"></form>`)
		})
		mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		mux.HandleFunc("/f", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
		mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-gate:
				writeHTML(w, `<a href="/after">after</a>`)
			case <-r.Context().Done():
			}
		})
		mux.HandleFunc("/after", func(w http.ResponseWriter, r *http.Request) { writeHTML(w, "ok") })
	})
	return &recoverySite{site: s, releaseSlow: func() { once.Do(func() { close(gate) }) }}
}

// interrupt starts a scan on a SQLite database, waits until discovery is in
// flight with jobs leased, then shuts the process down WITHOUT changing scan
// state. It returns the database path and the scan identity.
func interrupt(t *testing.T, s *recoverySite) (dbPath string, scanID domain.ID) {
	t.Helper()
	ctx := context.Background()
	dbPath = filepath.Join(t.TempDir(), "indago.db")

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	handlers, release := holdJobs() // jobs lease and block: "in flight" at crash time
	defer release()
	ctrl1 := newCtrl(t, db, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl1, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl1.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl1, sc.ID, 5*time.Second, func(st *scan.Status) bool {
		return st.Discovery.State == domain.DiscoveryRunning &&
			st.Discovery.Endpoints >= 3 && st.Jobs.Running >= 1
	})

	// "Crash": stop everything, leave persisted state exactly as it is.
	ctrl1.Shutdown()
	pre, err := ctrl1.Status(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pre.Scan.State != domain.ScanRunning || pre.Scan.Discovery != domain.DiscoveryRunning {
		t.Fatalf("Shutdown must leave state untouched: scan=%s discovery=%s", pre.Scan.State, pre.Scan.Discovery)
	}
	if active := pre.Jobs.Leased + pre.Jobs.Running; active == 0 {
		t.Fatalf("test setup: expected jobs left active by the crash, got %+v", pre.Jobs)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath, sc.ID
}

func TestRestartRecoversAndResumesScan(t *testing.T) {
	ctx := context.Background()
	s := newRecoverySite(t)
	dbPath, scanID := interrupt(t, s)
	s.releaseSlow() // after the restart /slow responds normally

	// --- restart: reopen the same file, brand-new controller, default handlers ---
	db, q := openSQLite(t, dbPath)
	defer db.Close()
	ctrl := newCtrl(t, db, q, scan.Options{})

	// Jobs left active by the crash are requeued.
	n, err := ctrl.Recover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected active jobs to be requeued, got %d", n)
	}
	// The interrupted scan is restored as PAUSED — a restart never sends traffic.
	changed, err := ctrl.RecoverScans(ctx)
	if err != nil || changed != 1 {
		t.Fatalf("RecoverScans: changed=%d err=%v", changed, err)
	}

	// Status is accurate straight after restart, before anything is resumed.
	restored, err := ctrl.Status(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Scan.State != domain.ScanPaused || restored.Running {
		t.Fatalf("restored scan: state=%s running=%v, want paused/not running", restored.Scan.State, restored.Running)
	}
	if restored.Discovery.State != domain.DiscoveryRunning {
		t.Fatalf("discovery state should still say 'running' (unfinished), got %q", restored.Discovery.State)
	}
	if restored.Jobs.Running+restored.Jobs.Leased != 0 || restored.Jobs.Queued == 0 {
		t.Fatalf("jobs should be queued, none active: %+v", restored.Jobs)
	}
	hitsBefore := s.hitCount("/")
	time.Sleep(150 * time.Millisecond)
	if s.hitCount("/") != hitsBefore {
		t.Fatal("a restored scan must not send traffic until resumed")
	}
	if err := ctrl.Pause(ctx, scanID); err != nil { // idempotent on a restored scan
		t.Fatalf("pause on restored scan: %v", err)
	}
	endpointsBefore := restored.Discovery.Endpoints

	// Resume rebuilds the execution and finishes the work.
	if err := ctrl.Resume(ctx, scanID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	done := waitStatus(t, ctrl, scanID, 10*time.Second, isCompleted)

	// Discovery picked up where it left off: /after is only reachable via /slow.
	eps, _ := db.Endpoints().ListByScan(ctx, scanID)
	seen := map[string]int{}
	for _, e := range eps {
		seen[e.Fingerprint]++
	}
	for fp, c := range seen {
		if c != 1 {
			t.Fatalf("duplicate endpoint after restart: %q x%d", fp, c)
		}
	}
	if len(eps) <= endpointsBefore {
		t.Fatalf("resumed discovery found nothing new: %d -> %d", endpointsBefore, len(eps))
	}
	foundAfter := false
	for _, e := range eps {
		if len(e.URL) >= 6 && e.URL[len(e.URL)-6:] == "/after" {
			foundAfter = true
		}
	}
	if !foundAfter {
		t.Fatal("resumed discovery did not reach /after")
	}

	// No duplicated jobs: exactly one per endpoint and per injection point, and
	// every one completed (including those requeued by recovery).
	want := done.Discovery.Endpoints + done.Discovery.InjectionPoints
	if done.Jobs.Total() != want || done.Jobs.Succeeded != want {
		t.Fatalf("jobs=%+v, want %d total and succeeded (no duplicates, none lost)", done.Jobs, want)
	}
	if done.Scan.Discovery != domain.DiscoveryComplete {
		t.Fatalf("discovery state = %q", done.Scan.Discovery)
	}
}

func TestRestartedScanCanBeCanceled(t *testing.T) {
	ctx := context.Background()
	s := newRecoverySite(t)
	dbPath, scanID := interrupt(t, s)
	s.releaseSlow()

	db, q := openSQLite(t, dbPath)
	defer db.Close()
	ctrl := newCtrl(t, db, q, scan.Options{})
	if _, err := ctrl.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl.RecoverScans(ctx); err != nil {
		t.Fatal(err)
	}

	// A restored scan has no live execution; Cancel must still work.
	if err := ctrl.Cancel(ctx, scanID); err != nil {
		t.Fatalf("cancel restored scan: %v", err)
	}
	got, _ := ctrl.Status(ctx, scanID)
	if got.Scan.State != domain.ScanCanceled || got.Scan.Discovery != domain.DiscoveryCanceled {
		t.Fatalf("state=%s discovery=%s", got.Scan.State, got.Scan.Discovery)
	}
	if got.Jobs.Pending() != 0 {
		t.Fatalf("jobs still pending after cancel: %+v", got.Jobs)
	}
	if err := ctrl.Resume(ctx, scanID); err != scan.ErrNotRunning {
		t.Fatalf("a canceled scan must not be resumable, got %v", err)
	}
}

// A scan whose discovery already finished must NOT crawl again after a restart:
// only its remaining jobs are processed.
func TestRestartSkipsCompletedDiscovery(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	dbPath := filepath.Join(t.TempDir(), "indago.db")

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl1 := newCtrl(t, db, q, scan.Options{Handlers: handlers})
	sc := createScan(t, ctrl1, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl1.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl1, sc.ID, 5*time.Second, func(st *scan.Status) bool {
		return st.Discovery.State == domain.DiscoveryComplete && st.Jobs.Running >= 1
	})
	ctrl1.Shutdown()
	_ = db.Close()

	// /robots.txt is fetched only by discovery (the executor requests endpoints),
	// so its hit count is the signal for "discovery ran again".
	hitsAtCrash := s.hitCount("/robots.txt")

	db2, q2 := openSQLite(t, dbPath)
	defer db2.Close()
	ctrl2 := newCtrl(t, db2, q2, scan.Options{})
	if _, err := ctrl2.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl2.RecoverScans(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ctrl2.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl2, sc.ID, 8*time.Second, isCompleted)

	if s.hitCount("/robots.txt") != hitsAtCrash {
		t.Fatalf("discovery re-ran after restart (robots.txt hits %d -> %d)", hitsAtCrash, s.hitCount("/robots.txt"))
	}
	if done.Jobs.Succeeded != done.Jobs.Total() || done.Jobs.Total() == 0 {
		t.Fatalf("remaining jobs not all processed: %+v", done.Jobs)
	}
}

// A scan that crashed mid-cancel has its cancel completed on restart.
// pause_and_ask's "don't immediately re-pause for a finding already shown"
// bookkeeping must survive a restart — a fresh Controller/execution after a
// crash must not forget it and re-ask the operator about findings they
// already saw before the crash.
func TestPauseAndAskStatePersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	dbPath := filepath.Join(t.TempDir(), "indago.db")

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	handlers, release := holdJobs()
	defer release()
	ctrl1 := newCtrl(t, db, q, scan.Options{Handlers: handlers})

	sc := createScan(t, ctrl1, proj, tgt, workersCfg(2), domain.StopPolicy{Mode: domain.StopPauseAndAsk})
	if err := ctrl1.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	addFinding(t, db, sc, domain.VerdictConfirmed)
	waitStatus(t, ctrl1, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanPaused })

	persisted, err := db.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Stats.AskedAtConfirmed != 1 {
		t.Fatalf("asked_at_confirmed = %d, want 1 (persisted before any restart)", persisted.Stats.AskedAtConfirmed)
	}

	// "Restart": shut the first controller down and close the database, then
	// reopen a fresh one exactly like a real crash/restart would.
	ctrl1.Shutdown()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2, q2 := openSQLite(t, dbPath)
	defer db2.Close()
	handlers2, release2 := holdJobs()
	defer release2()
	ctrl2 := newCtrl(t, db2, q2, scan.Options{Handlers: handlers2})

	if err := ctrl2.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if cur, _ := ctrl2.Status(ctx, sc.ID); cur.Scan.State != domain.ScanRunning {
		t.Fatalf("scan re-paused after restart for a finding the operator already saw: %s", cur.Scan.State)
	}

	// A genuinely NEW confirmed finding must still ask again.
	addFinding(t, db2, sc, domain.VerdictConfirmed)
	waitStatus(t, ctrl2, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanPaused })
}

func TestRecoverScansFinishesInterruptedCancel(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	db, q := openSQLite(t, dbPath)
	defer db.Close()
	proj, tgt := seedProject(t, db, "http://127.0.0.1:1/", hostScope())
	ctrl := newCtrl(t, db, q, scan.Options{})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})
	// Simulate a crash after the 'canceling' transition: force the persisted
	// state and leave a queued job behind.
	sc.State = domain.ScanCanceling
	if err := db.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, &domain.TestJob{ScanID: sc.ID, Type: domain.JobTest, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}

	changed, err := ctrl.RecoverScans(ctx)
	if err != nil || changed != 1 {
		t.Fatalf("RecoverScans: changed=%d err=%v", changed, err)
	}
	got, _ := ctrl.Status(ctx, sc.ID)
	if got.Scan.State != domain.ScanCanceled || got.Jobs.Pending() != 0 {
		t.Fatalf("state=%s jobs=%+v", got.Scan.State, got.Jobs)
	}
}

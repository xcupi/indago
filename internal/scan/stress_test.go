package scan_test

// Release-gate stress tests (no browser needed; see e2e_recovery_test.go for
// the real-Chromium crash/restart-during-verification stress). Each drives a
// real Controller, executor, and SQLite/in-memory store through many
// lifecycle transitions and then checks the invariants that matter for a
// release: every discovered injection point is tested, no duplicate findings,
// every evidence reference resolves, nothing is left pending, and canceled
// scans stay canceled.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

// reflectingSite serves n pages, each reflecting its own query parameter
// unencoded into HTML text, and counts every request. Normally "/" links to
// all of them; with chain set, "/" links only to the first and each page links
// to the next, so discovery itself stays in flight for most of the scan (and a
// crash can land between any two of its registration writes).
func reflectingSite(t *testing.T, n int, hits *atomic.Int64, chain bool) *site {
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.URL.Path == "/" {
				var b strings.Builder
				for i := 0; i < n && (i == 0 || !chain); i++ {
					fmt.Fprintf(&b, `<a href="/p%d?v%d=x">p</a> `, i, i)
				}
				writeHTML(w, b.String())
				return
			}
			var i int
			if _, err := fmt.Sscanf(r.URL.Path, "/p%d", &i); err != nil || i < 0 || i >= n {
				http.NotFound(w, r)
				return
			}
			time.Sleep(2 * time.Millisecond) // keep work in flight long enough to be interrupted
			next := ""
			if chain && i+1 < n {
				next = fmt.Sprintf(`<a href="/p%d?v%d=x">next</a>`, i+1, i+1)
			}
			writeHTML(w, "<div>"+r.URL.Query().Get(fmt.Sprintf("v%d", i))+"</div>"+next)
		})
	})
}

// assertScanIntegrity checks the release invariants for a finished scan.
// wantInjectionPoints is the total registered (query/form/JSON/header/
// cookie/path) injection points; wantReflecting is how many of those are
// expected to actually reflect and so produce a Finding — the default
// Header injection points this skill's fixtures register are deliberately
// never reflected by these test sites (none of them echo a header back),
// so the two counts now differ on purpose.
func assertScanIntegrity(t *testing.T, st store.Store, ev evidence.Store, q queue.Queue, scanID domain.ID, wantInjectionPoints, wantReflecting int) []*domain.Finding {
	t.Helper()
	ctx := context.Background()

	ips, err := st.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != wantInjectionPoints {
		details := make([]string, 0, len(ips))
		for _, ip := range ips {
			ep, endpointErr := st.Endpoints().Get(ctx, ip.EndpointID)
			param, paramErr := st.Parameters().Get(ctx, ip.ParameterID)
			if endpointErr == nil && paramErr == nil {
				details = append(details, fmt.Sprintf("%s %s %s:%s", ep.Method, ep.URL, param.Location, param.Name))
			}
		}
		t.Fatalf("injection points = %d, want %d: %s", len(ips), wantInjectionPoints, strings.Join(details, "; "))
	}
	tested := map[domain.ID]bool{}
	cases, err := st.TestCases().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if tc.Status == domain.TestCaseRunning {
			t.Fatalf("test case %s left running after completion", tc.ID)
		}
		if tc.Outcome == domain.OutcomeSuccess && !tc.InjectionPointID.Empty() {
			tested[tc.InjectionPointID] = true
		}
	}
	for _, ip := range ips {
		if !tested[ip.ID] {
			t.Fatalf("injection point %s was never successfully tested", ip.ID)
		}
	}

	stats, err := q.Stats(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pending() != 0 {
		t.Fatalf("jobs still pending after completion: %+v", stats)
	}

	findings, err := st.Findings().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	byIP := map[domain.ID]bool{}
	for _, f := range findings {
		var d struct {
			DedupKey string `json:"dedup_key"`
		}
		if err := json.Unmarshal(f.Detail, &d); err != nil || d.DedupKey == "" {
			t.Fatalf("finding %s has no dedup key: %v", f.ID, err)
		}
		if keys[d.DedupKey] {
			t.Fatalf("duplicate finding for correlation key %q", d.DedupKey)
		}
		keys[d.DedupKey] = true
		byIP[f.InjectionPointID] = true
		if ev != nil {
			for _, id := range f.EvidenceIDs {
				row, err := st.Evidence().Get(ctx, id)
				if err != nil {
					t.Fatalf("finding %s: evidence row %s missing: %v", f.ID, id, err)
				}
				rc, err := ev.Open(row.BlobPath)
				if err != nil {
					t.Fatalf("finding %s: evidence blob %s unreadable: %v", f.ID, row.BlobPath, err)
				}
				rc.Close()
			}
		}
	}
	if len(byIP) != wantReflecting {
		t.Fatalf("findings cover %d injection points, want %d", len(byIP), wantReflecting)
	}
	// Every test case's evidence must resolve too, not just the findings'.
	for _, tc := range cases {
		for _, id := range tc.EvidenceIDs {
			row, err := st.Evidence().Get(ctx, id)
			if err != nil {
				t.Fatalf("test case %s: evidence row %s missing: %v", tc.ID, id, err)
			}
			if ev != nil {
				rc, err := ev.Open(row.BlobPath)
				if err != nil {
					t.Fatalf("test case %s: evidence blob %s unreadable: %v", tc.ID, row.BlobPath, err)
				}
				rc.Close()
			}
		}
	}
	return findings
}

// Repeated crash/restart at different points of a scan (discovery, baseline,
// reflection, candidate execution, finding correlation) must still end with
// every injection point tested, exactly one finding per site, no pending jobs,
// and every evidence reference intact. Crash points are driven by the target's
// request count, so each cycle lands deeper into the scan.
func TestStress_RepeatedCrashRestartRecoversEveryInjectionPoint(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	const pages = 12
	const cycles = 6
	ctx := context.Background()
	var hits atomic.Int64
	s := reflectingSite(t, pages, &hits, true)
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	dcfg := discovery.DefaultConfig()
	dcfg.MaxDepth = pages + 1 // follow the whole chain
	opts := scan.Options{Evidence: ev, Discovery: &dcfg}

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	ctrl := newCtrl(t, db, q, opts)
	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	crashes := 0
	for cycle := 1; cycle <= cycles; cycle++ {
		// Crash once the target has seen a few more requests than at the last
		// crash — or skip the crash if the scan already completed.
		target := hits.Load() + int64(2+3*cycle)
		completed := false
		waitFor(t, 20*time.Second, func() bool {
			if st, err := ctrl.Status(ctx, sc.ID); err == nil && st.Scan.State == domain.ScanCompleted {
				completed = true
				return true
			}
			return hits.Load() >= target
		})
		if completed {
			break
		}
		ctrl.Shutdown()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		crashes++

		db, q = openSQLite(t, dbPath)
		ctrl = newCtrl(t, db, q, opts)
		if _, err := ctrl.Recover(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := ctrl.RecoverScans(ctx); err != nil {
			t.Fatal(err)
		}
		if err := ctrl.Resume(ctx, sc.ID); err != nil {
			t.Fatalf("cycle %d: resume: %v", cycle, err)
		}
	}
	defer db.Close()
	// The completion budget is sized for the -race build, not the wall clock of
	// an un-instrumented run. Measured on this fixture: ~2.4s without -race and
	// ~30s with it (252 SQLite-backed jobs in the no-crash run; 72 of them are
	// browserless JobVerify skips serialised on the browser group's single
	// worker, which alone costs ~15s under -race at the measured ~213ms per
	// job). The crashes also requeue in-flight work, so the tail after the
	// last resume can exceed the fixture's own baseline. A bigger budget alone
	// would hide a real wedge, so the wait also fails early when outstanding
	// jobs exist and no worker holds any of them for longer than stallAfter
	// (see completionWatch).
	done := waitCompletedProgressing(t, ctrl, sc.ID, 2*time.Minute, 20*time.Second)
	if crashes < 3 {
		t.Fatalf("stress setup: only %d crashes landed before completion", crashes)
	}
	findings := assertScanIntegrity(t, db, ev, q, sc.ID, 4*pages+3, pages) // only the pages' own query params reflect; the default Header IPs never do
	t.Logf("crashes=%d findings=%d jobs=%+v tests=%+v", crashes, len(findings), done.Jobs, done.Tests)
}

// Concurrent scans under heavy pause/resume churn from several goroutines:
// half are then canceled, half run to completion. No deadlock, no panic,
// canceled scans end with no pending jobs and stay canceled, completed scans
// satisfy every release invariant.
func TestStress_ConcurrentScansPauseResumeCancelChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	const scans = 4
	const pages = 6
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctrl := newCtrl(t, st, q, scan.Options{Evidence: ev})

	ids := make([]domain.ID, scans)
	for i := range ids {
		var hits atomic.Int64
		s := reflectingSite(t, pages, &hits, false)
		proj, tgt := seedProject(t, st, s.URL, hostScope())
		sc := createScan(t, ctrl, proj, tgt, workersCfg(3), domain.StopPolicy{})
		if err := ctrl.Start(ctx, sc.ID); err != nil {
			t.Fatal(err)
		}
		ids[i] = sc.ID
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for n := 0; n < 40; n++ {
				id := ids[(g+n)%scans]
				switch (g * n) % 3 {
				case 0:
					_ = ctrl.Pause(ctx, id)
				case 1:
					_ = ctrl.Resume(ctx, id)
				default:
					_, _ = ctrl.Status(ctx, id)
				}
			}
		}(g)
	}
	wg.Wait()

	for i, id := range ids {
		if i%2 == 0 {
			if err := ctrl.Cancel(ctx, id); err != nil {
				t.Fatalf("cancel %s: %v", id, err)
			}
			continue
		}
		if err := ctrl.Resume(ctx, id); err != nil && !strings.Contains(err.Error(), "not running") {
			t.Fatalf("resume %s: %v", id, err)
		}
	}
	for i, id := range ids {
		if i%2 == 0 {
			st, _ := ctrl.Status(ctx, id)
			if st.Scan.State != domain.ScanCanceled || st.Jobs.Pending() != 0 || st.Running {
				t.Fatalf("canceled scan %s: state=%s pending=%d running=%v", id, st.Scan.State, st.Jobs.Pending(), st.Running)
			}
			continue
		}
		waitStatus(t, ctrl, id, 30*time.Second, isCompleted)
		assertScanIntegrity(t, st, ev, q, id, 4*pages+3, pages) // only the pages' own query params reflect; the default Header IPs never do
	}
	// A canceled scan never comes back to life.
	for i, id := range ids {
		if i%2 == 0 {
			if err := ctrl.Resume(ctx, id); err == nil {
				t.Fatalf("resume of canceled scan %s succeeded", id)
			}
		}
	}
}

// Repeated session loss → AwaitingAuth → re-authentication cycles on an
// existing-session scan. Every request the target sees carries the session
// cookie (no unauthenticated work ever slips through while awaiting auth or
// after re-auth), and the scan still completes with every site found.
func TestStress_SessionExpiryReauthCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	const pages = 8
	const cycles = 5
	ctx := context.Background()
	var total, authed atomic.Int64
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			total.Add(1)
			if c, err := r.Cookie("sid"); err == nil && c.Value == "s3cret" {
				authed.Add(1)
			}
			if r.URL.Path == "/" {
				var b strings.Builder
				for i := 0; i < pages; i++ {
					fmt.Fprintf(&b, `<a href="/p%d?v%d=x">p</a> `, i, i)
				}
				writeHTML(w, b.String())
				return
			}
			var i int
			if _, err := fmt.Sscanf(r.URL.Path, "/p%d", &i); err != nil || i < 0 || i >= pages {
				http.NotFound(w, r)
				return
			}
			time.Sleep(5 * time.Millisecond)
			writeHTML(w, "<div>"+r.URL.Query().Get(fmt.Sprintf("v%d", i))+"</div>")
		})
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	state := writeState(t, t.TempDir())
	saved, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}

	for cycle := 0; cycle < cycles; cycle++ {
		cur, _ := ctrl.Status(ctx, sc.ID)
		if cur.Scan.State == domain.ScanCompleted {
			break
		}
		if cycle%2 == 0 {
			// Material removed: detected by Authenticator.Validate.
			if err := os.Remove(state); err != nil {
				t.Fatal(err)
			}
		} else {
			// Time-based expiry: detected via ExpiresAt.
			sess, err := st.Sessions().GetByScan(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			past := time.Now().Add(-time.Minute)
			sess.ExpiresAt = &past
			if err := st.Sessions().Update(ctx, sess); err != nil {
				t.Fatal(err)
			}
		}
		var paused bool
		waitFor(t, 5*time.Second, func() bool {
			st, _ := ctrl.Status(ctx, sc.ID)
			paused = st.Scan.State == domain.ScanAwaitingAuth
			return paused || st.Scan.State == domain.ScanCompleted
		})
		if !paused {
			break // completed before the monitor saw the loss; nothing to resume
		}
		if cycle%2 == 0 {
			if err := ctrl.Resume(ctx, sc.ID); err == nil {
				t.Fatal("resume without session material succeeded")
			}
			if err := os.WriteFile(state, saved, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := ctrl.Resume(ctx, sc.ID); err != nil {
			t.Fatalf("cycle %d: re-auth resume: %v", cycle, err)
		}
	}
	waitStatus(t, ctrl, sc.ID, 30*time.Second, isCompleted)
	if total.Load() != authed.Load() {
		t.Fatalf("%d of %d requests were sent without the session", total.Load()-authed.Load(), total.Load())
	}
	assertScanIntegrity(t, st, nil, q, sc.ID, 4*pages+3, pages) // only the pages' own query params reflect; the default Header IPs never do ("sid" is excluded as the session's own auth cookie)
}

// completionWatch distinguishes a slow-but-advancing scan from a wedged one.
//
// The failure that motivated it looked identical in the status view: queued
// jobs, one or more running, zero failed/dead. The difference is whether the
// queue is still ADVANCING. A settled job (succeeded/failed/canceled/dead) or a
// worker holding a lease resets the clock; a pending queue that no worker holds
// for the whole stall window is the shape of a real wedge (nothing will ever
// lease it), and it is reported immediately instead of being masked by a large
// completion budget. A handler that hangs while HOLDING a lease is bounded
// separately by the worker pool's JobTimeout.
type completionWatch struct {
	stallAfter time.Duration
	lastDone   int
	idleSince  time.Time
	started    bool
}

// stalled reports whether the queue has been pending-but-unowned for longer
// than the watch's window.
func (w *completionWatch) stalled(now time.Time, s queue.Stats) bool {
	done := s.Succeeded + s.Failed + s.Canceled + s.Dead
	if !w.started || done != w.lastDone {
		w.started = true
		w.lastDone = done
		w.idleSince = now
		return false
	}
	if s.Pending() == 0 {
		return false
	}
	if s.Leased+s.Running > 0 {
		w.idleSince = now
		return false
	}
	return now.Sub(w.idleSince) > w.stallAfter
}

// waitCompletedProgressing waits for a scan to complete within budget while
// failing early when the queue stops moving. budget must include the -race
// overhead of the fixture (see the caller's comment); the watchdog, not the
// budget, is what catches a real stall.
func waitCompletedProgressing(t *testing.T, c *scan.Controller, id domain.ID, budget, stallAfter time.Duration) *scan.Status {
	t.Helper()
	deadline := time.Now().Add(budget)
	watch := &completionWatch{stallAfter: stallAfter}
	var last *scan.Status
	for time.Now().Before(deadline) {
		st, err := c.Status(context.Background(), id)
		if err == nil {
			last = st
			if st.Scan.State == domain.ScanCompleted {
				return st
			}
			if watch.stalled(time.Now(), st.Jobs) {
				t.Fatalf("scan %s wedged: %d job(s) outstanding and none leased/running for over %s (last: state=%s discovery=%s jobs=%+v)",
					id, st.Jobs.Pending(), stallAfter, st.Scan.State, st.Discovery.State, st.Jobs)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if last == nil {
		t.Fatalf("status never available within %s", budget)
	}
	t.Fatalf("scan not completed within %s; last: state=%s discovery=%s jobs=%+v",
		budget, last.Scan.State, last.Discovery.State, last.Jobs)
	return nil
}

func TestCompletionWatchDistinguishesProgressFromStall(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	const stallAfter = 20 * time.Second

	// Queued work that no worker ever leases is a wedge once the window passes.
	w := &completionWatch{stallAfter: stallAfter}
	queued := queue.Stats{Queued: 3}
	if w.stalled(start, queued) {
		t.Fatal("the first observation must not be a stall")
	}
	if w.stalled(start.Add(19*time.Second), queued) {
		t.Fatal("stall reported before the window elapsed")
	}
	if !w.stalled(start.Add(21*time.Second), queued) {
		t.Fatal("queued work with no leased/running worker must be reported")
	}

	// A settled job resets the clock: the queue is advancing.
	w = &completionWatch{stallAfter: stallAfter}
	w.stalled(start, queue.Stats{Queued: 1, Running: 1})
	if w.stalled(start.Add(10*time.Second), queue.Stats{Queued: 0, Succeeded: 1}) {
		t.Fatal("a freshly settled job must reset the stall clock")
	}

	// A worker holding a lease also resets the clock; its handler is bounded by
	// the pool's JobTimeout instead.
	w = &completionWatch{stallAfter: stallAfter}
	w.stalled(start, queue.Stats{Queued: 1, Running: 1})
	if w.stalled(start.Add(30*time.Second), queue.Stats{Queued: 1, Running: 1}) {
		t.Fatal("a running job is the pool deadline's concern, not the watchdog's")
	}

	// Nothing pending is never a stall, however long it takes.
	w = &completionWatch{stallAfter: stallAfter}
	w.stalled(start, queue.Stats{Succeeded: 5})
	if w.stalled(start.Add(time.Hour), queue.Stats{Succeeded: 5}) {
		t.Fatal("an empty queue must not be reported as stalled")
	}
}

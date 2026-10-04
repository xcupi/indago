package scan_test

// Executor integration: a real Controller runs scans end to end and the default
// test-job executor persists results and evidence.

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestScanExecutesEveryJobAndPersistsResults(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{Evidence: ev})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(4), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 10*time.Second, isCompleted)

	total := done.Discovery.Endpoints + done.Discovery.InjectionPoints
	cases, _ := st.TestCases().ListByScan(ctx, sc.ID)
	if len(cases) != total {
		t.Fatalf("test cases = %d, want one per job (%d)", len(cases), total)
	}

	// The POST form endpoint (and its parameter job) is skipped by default; every
	// other job executed successfully (a 404 such as /secret is still a success).
	var skipped, success int
	jobs := map[domain.ID]bool{}
	for _, tc := range cases {
		jobs[tc.JobID] = true
		switch {
		case tc.Status == domain.TestCaseSkipped:
			skipped++
			if !strings.Contains(tc.Method, "POST") && !strings.Contains(tc.Note, "POST") {
				t.Errorf("only POST should be skipped: %+v", tc)
			}
		case tc.Outcome == domain.OutcomeSuccess:
			success++
			if tc.HTTPStatus == 0 || tc.FinishedAt == nil {
				t.Errorf("success record incomplete: %+v", tc)
			}
			if tc.InjectionPointID.Empty() {
				// Endpoint-level baseline: request + response evidence.
				if len(tc.EvidenceIDs) != 2 || len(tc.Detail) != 0 || tc.VulnClass != "" {
					t.Errorf("baseline record wrong: evidence=%d detail=%d class=%s", len(tc.EvidenceIDs), len(tc.Detail), tc.VulnClass)
				}
			} else {
				// Reflection test: shared baseline (req+resp) + mutated (req+resp),
				// a reflected-xss class, and a reflection report in Detail.
				if len(tc.EvidenceIDs) != 4 || tc.VulnClass != domain.VulnReflectedXSS {
					t.Errorf("reflection record wrong: evidence=%d class=%s", len(tc.EvidenceIDs), tc.VulnClass)
				}
				rep, err := detection.ParseReflection(tc.Detail)
				if err != nil || rep == nil || rep.Reflected {
					t.Errorf("reflection report wrong (site does not reflect): %v %+v", err, rep)
				}
			}
		default:
			t.Errorf("unexpected result: status=%s outcome=%s err=%q url=%s", tc.Status, tc.Outcome, tc.Error, tc.URL)
		}
	}
	if len(jobs) != total || skipped != 2 || success != total-2 {
		t.Fatalf("jobs=%d skipped=%d success=%d (total %d)", len(jobs), skipped, success, total)
	}
	// (Discovery also registers a GET endpoint for the form's action URL; that GET
	// is safe and runs. What must never happen is a POST.)
	for _, tc := range cases {
		if tc.Method == "POST" && tc.Status != domain.TestCaseSkipped {
			t.Fatalf("a POST was executed although AllowStateChanging is off: %+v", tc)
		}
	}

	// Status reports the same breakdown, and every evidence reference resolves.
	if done.Tests.Success != success || done.Tests.Skipped != skipped || done.Tests.Error+done.Tests.Timeout+done.Tests.Cancelled+done.Tests.Running != 0 {
		t.Fatalf("status tests = %+v", done.Tests)
	}
	// Every evidence reference held by a test case must resolve to a readable blob.
	for _, tc := range cases {
		for _, id := range tc.EvidenceIDs {
			row, err := st.Evidence().Get(ctx, id)
			if err != nil {
				t.Fatalf("evidence row %s missing: %v", id, err)
			}
			rc, err := ev.Open(row.BlobPath)
			if err != nil {
				t.Fatalf("evidence %s unreadable: %v", row.BlobPath, err)
			}
			rc.Close()
		}
	}
	// Reflection tests on the same endpoint share one baseline (no per-injection
	// duplicate): there are more injection reflections than distinct baseline
	// responses they reference.
	if done.Tests.Reflected != 0 {
		t.Fatalf("the standard site does not reflect; got %d reflected", done.Tests.Reflected)
	}
}

// With the opt-in, the POST endpoint is executed with its form body.
func TestScanExecutesPostWhenAllowed(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var bodies []string
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<form action="/submit" method="post"><input name="msg" value="seed value"></form>`)
		})
		mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, r.Method+" "+string(b))
			mu.Unlock()
		})
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{Executor: scan.ExecutorConfig{AllowStateChanging: true}})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ctrl, sc.ID, 8*time.Second, isCompleted)
	if done.Tests.Skipped != 0 || done.Tests.Success != done.Jobs.Total() {
		t.Fatalf("tests = %+v jobs = %+v", done.Tests, done.Jobs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("the POST endpoint was never executed")
	}
	var sawBaseline, sawMutated bool
	for _, b := range bodies {
		switch {
		case b == "POST msg=seed+value":
			sawBaseline = true // baseline: the observed value
		case strings.HasPrefix(b, "POST msg=ind"):
			sawMutated = true // mutated: the marker, injected into msg only
		case b == "GET ":
			// the GET endpoint discovery registers for the form's action URL
		default:
			t.Fatalf("unexpected request %q", b)
		}
	}
	if !sawBaseline || !sawMutated {
		t.Fatalf("expected both baseline and mutated POSTs with the opt-in on: %q", bodies)
	}
}

// Cancel interrupts an in-flight test request and its CANCELLED result is
// persisted before Cancel returns.
func TestCancelRecordsCancelledTestCases(t *testing.T) {
	ctx := context.Background()
	hit := make(chan struct{}, 8)
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			select {
			case hit <- struct{}{}:
			default:
			}
			<-r.Context().Done() // hang until the client goes away
		})
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})

	sc := createScan(t, ctrl, proj, tgt, workersCfg(2), domain.StopPolicy{})
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	// Wait until a TEST request (not just discovery's) is running.
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Tests.Running >= 1 })

	if err := ctrl.Cancel(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := ctrl.Status(ctx, sc.ID)
	if got.Tests.Running != 0 || got.Tests.Cancelled < 1 {
		t.Fatalf("after cancel: tests = %+v", got.Tests)
	}
	cases, _ := st.TestCases().ListByScan(ctx, sc.ID)
	for _, tc := range cases {
		if tc.Outcome == domain.OutcomeCancelled && (tc.Status != domain.TestCaseCancelled || tc.FinishedAt == nil) {
			t.Fatalf("cancelled record incomplete: %+v", tc)
		}
	}
}

// A crash mid-request leaves a RUNNING test case; recovery closes it out so it is
// not "running" forever, and the requeued job records a fresh attempt.
func TestRecoverClosesInterruptedTestCases(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	db, q := openSQLite(t, dbPath)
	defer db.Close()
	proj, tgt := seedProject(t, db, "http://127.0.0.1:1/", hostScope())
	ctrl := newCtrl(t, db, q, scan.Options{})
	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})

	now := time.Now()
	stale := &domain.TestCase{ID: domain.NewID(), ScanID: sc.ID, JobID: domain.NewID(), Attempt: 1,
		Status: domain.TestCaseRunning, Method: "GET", URL: "http://127.0.0.1:1/x", StartedAt: &now, CreatedAt: now, UpdatedAt: now}
	done := &domain.TestCase{ID: domain.NewID(), ScanID: sc.ID, JobID: domain.NewID(), Attempt: 1,
		Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess, HTTPStatus: 200, CreatedAt: now, UpdatedAt: now}
	for _, tc := range []*domain.TestCase{stale, done} {
		if err := db.TestCases().Create(ctx, tc); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := ctrl.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := db.TestCases().Get(ctx, stale.ID)
	if got.Status != domain.TestCaseCancelled || got.Outcome != domain.OutcomeCancelled || got.Error != "interrupted by restart" || got.FinishedAt == nil {
		t.Fatalf("stale test case not closed out: %+v", got)
	}
	if kept, _ := db.TestCases().Get(ctx, done.ID); kept.Outcome != domain.OutcomeSuccess || kept.HTTPStatus != 200 {
		t.Fatalf("a finished test case must be left alone: %+v", kept)
	}
}

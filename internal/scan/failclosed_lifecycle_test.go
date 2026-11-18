package scan_test

// Lifecycle half of the scanHTTPEngine fail-closed contract (the white-box
// half is internal/scan/scan_http_engine_test.go).
//
// A scan that asks for a proxy pool / TLS override / hunting User-Agent and
// whose scoped client cannot be built must not start, resume, or be resumed
// after a restart. Falling back to the shared engine would send target requests
// without what the operator configured — the QA finding this pins. These tests
// count requests at a fake shared engine, so a regression shows up as a nonzero
// count, not as a log line nobody reads.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

// failClosedLifecycleEngine stands in for the shared HTTP engine. Every Do is a
// request the scan was not allowed to send directly.
type failClosedLifecycleEngine struct {
	requests atomic.Int64
}

func (e *failClosedLifecycleEngine) Do(context.Context, *httpengine.Request) (*httpengine.Response, error) {
	e.requests.Add(1)
	return &httpengine.Response{
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html; charset=utf-8"}},
		Body:    []byte(`<!doctype html><html><body>ok</body></html>`),
	}, nil
}

// corruptScanConfig rewrites a persisted scan's config to a proxy entry that
// httpengine.New rejects, carrying a credential that must never reach the
// persisted error. CreateScanParams validation would refuse this, which is why
// it is written directly: the defensive path exists for a row that predates the
// validation or was edited outside the API.
func corruptScanConfig(t *testing.T, st store.Store, id domain.ID) {
	t.Helper()
	ctx := context.Background()
	sc, err := st.Scans().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	sc.Config.ProxyPool = []string{"http://user:s3cr3t@[::1"}
	if err := st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
}

func setScanState(t *testing.T, st store.Store, id domain.ID, state domain.ScanState) {
	t.Helper()
	ctx := context.Background()
	sc, err := st.Scans().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	sc.State = state
	if err := st.Scans().Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
}

func TestStartFailsClosedWhenScopedClientCannotBeBuilt(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	eng := &failClosedLifecycleEngine{}
	ctrl := newCtrl(t, st, q, scan.Options{HTTP: eng})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1", hostScope())
	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})
	corruptScanConfig(t, st, sc.ID)

	err := ctrl.Start(ctx, sc.ID)
	if !errors.Is(err, scan.ErrScanHTTPClient) {
		t.Fatalf("Start = %v, want ErrScanHTTPClient", err)
	}

	got, err := st.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanFailed {
		t.Fatalf("scan state = %s, want failed (Start must record the refusal, not leave it running)", got.State)
	}
	if !strings.Contains(got.Error, "refusing") {
		t.Fatalf("persisted error %q does not explain the refusal", got.Error)
	}
	if strings.Contains(got.Error, "s3cr3t") {
		t.Fatalf("proxy credential leaked into the persisted scan error: %q", got.Error)
	}
	if ctrl.IsRunning(sc.ID) {
		t.Fatal("a refused Start left a live execution behind")
	}
	// Nothing may reach the target through the shared engine, now or shortly
	// after: discovery would have started asynchronously under the old fallback.
	time.Sleep(200 * time.Millisecond)
	if n := eng.requests.Load(); n != 0 {
		t.Fatalf("refused Start sent %d direct target request(s) through the shared engine", n)
	}
	// Terminal, so a second Start is a bad-state error rather than a restart.
	if err := ctrl.Start(ctx, sc.ID); !errors.Is(err, scan.ErrBadState) {
		t.Fatalf("second Start = %v, want ErrBadState", err)
	}
}

func TestResumeFailsClosedAndStaysPaused(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	eng := &failClosedLifecycleEngine{}
	ctrl := newCtrl(t, st, q, scan.Options{HTTP: eng})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1", hostScope())
	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})
	corruptScanConfig(t, st, sc.ID)
	// A scan left paused (for example restored after a restart).
	setScanState(t, st, sc.ID, domain.ScanPaused)

	if err := ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrScanHTTPClient) {
		t.Fatalf("Resume = %v, want ErrScanHTTPClient", err)
	}
	got, err := st.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanPaused {
		t.Fatalf("scan state = %s, want paused so the operator can fix and retry", got.State)
	}
	if !strings.Contains(got.Error, "refusing") {
		t.Fatalf("persisted error %q does not explain the refusal", got.Error)
	}
	if ctrl.IsRunning(sc.ID) {
		t.Fatal("a refused Resume left a live execution behind")
	}
	time.Sleep(200 * time.Millisecond)
	if n := eng.requests.Load(); n != 0 {
		t.Fatalf("refused Resume sent %d direct target request(s)", n)
	}
	// Consistent on retry: same refusal, same state, still no traffic.
	if err := ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrScanHTTPClient) {
		t.Fatalf("second Resume = %v, want ErrScanHTTPClient", err)
	}
	if got, _ := st.Scans().Get(ctx, sc.ID); got.State != domain.ScanPaused {
		t.Fatalf("after a second refused Resume the state is %s, want paused", got.State)
	}
	if n := eng.requests.Load(); n != 0 {
		t.Fatalf("second refused Resume sent %d direct target request(s)", n)
	}
}

// The restart path: a scan persisted as running is restored as paused (recovery
// never sends traffic), and resuming it then fails closed instead of starting an
// unproxied run.
func TestRecoverThenResumeFailsClosed(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	eng := &failClosedLifecycleEngine{}
	ctrl := newCtrl(t, st, q, scan.Options{HTTP: eng})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1", hostScope())
	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})
	corruptScanConfig(t, st, sc.ID)
	setScanState(t, st, sc.ID, domain.ScanRunning) // interrupted by a restart

	n, err := ctrl.RecoverScans(ctx)
	if err != nil {
		t.Fatalf("RecoverScans: %v", err)
	}
	if n != 1 {
		t.Fatalf("RecoverScans changed %d scans, want 1", n)
	}
	got, err := st.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanPaused {
		t.Fatalf("after recovery state = %s, want paused", got.State)
	}

	if err := ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrScanHTTPClient) {
		t.Fatalf("Resume after recovery = %v, want ErrScanHTTPClient", err)
	}
	if ctrl.IsRunning(sc.ID) {
		t.Fatal("a refused resume after recovery left a live execution behind")
	}
	time.Sleep(200 * time.Millisecond)
	if n := eng.requests.Load(); n != 0 {
		t.Fatalf("recover+resume sent %d direct target request(s)", n)
	}
}

// Positive control: a scan that asks for nothing special still starts normally
// and its traffic really flows through the shared engine.
func TestStartStillWorksWithoutAScopedClientRequest(t *testing.T) {
	ctx := context.Background()
	st, q := memory.New(), queue.NewMemory()
	eng := &failClosedLifecycleEngine{}
	ctrl := newCtrl(t, st, q, scan.Options{HTTP: eng})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1", hostScope())
	sc := createScan(t, ctrl, proj, tgt, workersCfg(1), domain.StopPolicy{})

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatalf("Start without a proxy/TLS/UA request = %v, want success", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for eng.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := eng.requests.Load(); n == 0 {
		t.Fatal("the shared engine saw no request; the positive control cannot prove the normal path still works")
	}
	_ = ctrl.Cancel(ctx, sc.ID)
}

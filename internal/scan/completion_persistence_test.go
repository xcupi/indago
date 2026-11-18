package scan_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/store/memory"
)

// These tests are deliberately inert: no target is contacted and no detector
// runs. The scan is created with every engine skipped and discovery already
// marked complete, so the monitor's very FIRST quiet tick is its completion
// tick — exactly the code path under test. The only moving part is an in-memory
// store that fails scan writes on demand.
//
// The failure they pin down: finish used to remove the execution from
// Controller.running and only THEN write COMPLETED, treating every write error
// as "a cancel won the race". A transient storage error therefore exited the
// monitor with the row still `running` and nothing left to drive it — a
// permanently orphaned scan, with the cause misreported.

// errStoreDown is the injected transient storage failure.
var errStoreDown = errors.New("injected: store temporarily unavailable")

// faultyScans wraps a real ScanRepo and fails Update calls for chosen states.
type faultyScans struct {
	store.ScanRepo

	mu sync.Mutex
	// failRemaining counts completion-state writes that must fail. A negative
	// value keeps failing every completion write.
	failRemaining int
	// failAll fails every Update, whatever the state.
	failAll bool
	// failAfter, when non-negative, fails every Update from the (n+1)-th call
	// on: the first n updates succeed. Independent of timing, unlike arming a
	// flag from another goroutine.
	failAfter int
	updates   int
	// onFailure runs (outside the lock) when an injected failure fires.
	onFailure func()
	// written records the state of every row that reached the real store.
	written []domain.ScanState
}

// failCompletionWrites arms the store to reject the next n writes of a
// COMPLETED row (n < 0: reject them all). Writes of other states pass through.
func (r *faultyScans) failCompletionWrites(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failRemaining = n
	r.failAll = false
}

// failEveryWrite arms the store to reject every Update.
func (r *faultyScans) failEveryWrite() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failAll = true
}

// failWritesAfter lets the next n Updates through and rejects every one after
// that. Used to let the scan reach `running` and then take the store down.
func (r *faultyScans) failWritesAfter(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failAfter = n
	r.failAll = false
}

func (r *faultyScans) setOnFailure(fn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onFailure = fn
}

func (r *faultyScans) writtenStates() []domain.ScanState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.ScanState(nil), r.written...)
}

func (r *faultyScans) Update(ctx context.Context, s *domain.Scan) error {
	r.mu.Lock()
	hook := r.onFailure
	r.updates++
	fail := r.failAll ||
		(s.State == domain.ScanCompleted && r.failRemaining != 0) ||
		(r.failAfter >= 0 && r.updates > r.failAfter)
	if fail && !r.failAll && r.failRemaining > 0 {
		r.failRemaining--
	}
	if !fail {
		r.written = append(r.written, s.State)
	}
	r.mu.Unlock()

	if fail {
		if hook != nil {
			hook()
		}
		return errStoreDown
	}
	return r.ScanRepo.Update(ctx, s)
}

// faultyStore exposes the faulty scan repo and delegates everything else.
type faultyStore struct {
	store.Store
	scans *faultyScans
}

func (s *faultyStore) Scans() store.ScanRepo { return s.scans }

// syncBuffer is a goroutine-safe log sink: the monitor logs while the test
// asserts on what it wrote.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// completionEnv is one inert, not-yet-started scan whose monitor will complete
// it as soon as it is started.
type completionEnv struct {
	ctrl  *scan.Controller
	store *faultyStore
	scans *faultyScans
	logs  *syncBuffer
	scan  domain.ID
}

// newCompletionEnv builds the environment and leaves the scan created but
// stopped, so a test can arm a store fault BEFORE the monitor can tick.
func newCompletionEnv(t *testing.T) *completionEnv {
	t.Helper()
	ctx := context.Background()

	base := memory.New()
	faults := &faultyScans{ScanRepo: base.Scans(), failAfter: -1}
	st := &faultyStore{Store: base, scans: faults}
	logs := &syncBuffer{}

	ctrl := scan.NewController(st, queue.NewMemory(), slog.New(slog.NewTextHandler(logs, nil)), "test", scan.Options{
		PollInterval: 20 * time.Millisecond,
		IdlePoll:     5 * time.Millisecond,
	})
	t.Cleanup(ctrl.Shutdown)

	proj := &domain.Project{ID: domain.NewID(), Name: "p"}
	if err := base.Projects().Create(ctx, proj); err != nil {
		t.Fatal(err)
	}
	tgt := &domain.Target{ID: domain.NewID(), ProjectID: proj.ID, Name: "t", BaseURL: "https://example.com/"}
	if err := base.Targets().Create(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	if err := base.Scopes().Create(ctx, &domain.Scope{ID: domain.NewID(), ProjectID: proj.ID, IncludeHosts: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}

	// Every engine and every one-time pass is off: the quiet tick this test
	// drives enqueues no work at all, so no worker ever executes anything.
	cfg := domain.ScanConfig{
		SkipReflectedXSS:   true,
		SkipDOMXSS:         true,
		SkipAccessControl:  true,
		SkipIDOR:           true,
		SkipInfoDisclosure: true,
		SkipSSRF:           true,
		SkipPathTraversal:  true,
		SkipCORS:           true,
		SkipOpenRedirect:   true,
		SkipGraphQL:        true,
	}
	sc, err := ctrl.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: proj.ID,
		TargetID:  tgt.ID,
		Name:      "inert-completion",
		Profile:   domain.ProfileCustom,
		Config:    &cfg,
		Stop:      domain.StopPolicy{Mode: domain.StopContinueAll},
		AuthMode:  domain.AuthAnonymous,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Discovery already finished: launch() then starts no crawl, so this scan
	// reaches completion without a single network request.
	cur, err := base.Scans().Get(ctx, sc.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	cur.Discovery = domain.DiscoveryComplete
	if err := base.Scans().Update(ctx, cur); err != nil {
		t.Fatalf("mark discovery complete: %v", err)
	}

	return &completionEnv{ctrl: ctrl, store: st, scans: faults, logs: logs, scan: sc.ID}
}

// start launches the scan's execution. Called only after the store fault (if
// any) is armed, so the monitor's first tick already sees it.
func (e *completionEnv) start(t *testing.T) {
	t.Helper()
	if err := e.ctrl.Start(context.Background(), e.scan); err != nil {
		t.Fatalf("start: %v", err)
	}
}

func (e *completionEnv) state(t *testing.T) *domain.Scan {
	t.Helper()
	sc, err := e.store.Scans().Get(context.Background(), e.scan)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	return sc
}

func (e *completionEnv) waitTerminal(t *testing.T) *domain.Scan {
	t.Helper()
	waitFor(t, 3*time.Second, func() bool {
		sc, err := e.store.Scans().Get(context.Background(), e.scan)
		return err == nil && sc.State.IsTerminal()
	})
	return e.state(t)
}

// TestCompletionRetriesTransientStoreError is the regression test for the
// transient case: a failed completion write must be retried (bounded), and the
// scan must end up durably COMPLETED — not stranded in `running`.
func TestCompletionRetriesTransientStoreError(t *testing.T) {
	env := newCompletionEnv(t)
	env.scans.failCompletionWrites(2) // two transient failures, then healthy
	env.start(t)

	sc := env.waitTerminal(t)
	if sc.State != domain.ScanCompleted {
		t.Fatalf("state = %s (error %q), want completed: a transient store error must be retried, not turned into a stranded scan", sc.State, sc.Error)
	}
	if sc.EndedAt == nil {
		t.Fatal("completed scan has no ended_at")
	}
	waitFor(t, time.Second, func() bool { return !env.ctrl.IsRunning(env.scan) })

	if !hasState(env.scans.writtenStates(), domain.ScanCompleted) {
		t.Fatal("completed state never reached the store")
	}
	logs := env.logs.String()
	if got := strings.Count(logs, "finish: retrying completion write"); got != 2 {
		t.Fatalf("retry log lines = %d, want 2 (bounded retries must be observable)\nlogs:\n%s", got, logs)
	}
	if !strings.Contains(logs, "scan completed") {
		t.Fatalf("no completion log after a successful retry:\n%s", logs)
	}
}

// TestCompletionNeverReportsCompletedWhenPersistenceFails is the "never lie"
// half: when every completion write fails for the whole retry budget, the scan
// must NOT be reported as completed. It must instead be terminal and explain
// itself, so it cannot look like a healthy running scan with no execution.
func TestCompletionNeverReportsCompletedWhenPersistenceFails(t *testing.T) {
	// Exactly the retry budget, then the store recovers — so the fault is
	// transient, it just outlives the bounded retries.
	env := newCompletionEnv(t)
	env.scans.failCompletionWrites(4)
	env.start(t)

	sc := env.waitTerminal(t)
	if sc.State == domain.ScanCompleted {
		t.Fatal("scan reported completed although no completion write ever succeeded")
	}
	if sc.State != domain.ScanFailed {
		t.Fatalf("state = %s, want failed after the completion write was abandoned", sc.State)
	}
	if !strings.Contains(sc.Error, "completion could not be persisted") {
		t.Fatalf("failure reason = %q, want it to name the unpersisted completion", sc.Error)
	}
	if hasState(env.scans.writtenStates(), domain.ScanCompleted) {
		t.Fatal("a COMPLETED row reached the store after the retries were exhausted")
	}
	waitFor(t, time.Second, func() bool { return !env.ctrl.IsRunning(env.scan) })

	logs := env.logs.String()
	if got := strings.Count(logs, "finish: retrying completion write"); got != 3 {
		t.Fatalf("retry log lines = %d, want 3 (attempts 2..4, i.e. bounded)\nlogs:\n%s", got, logs)
	}
	if !strings.Contains(logs, "could not persist completion") {
		t.Fatalf("no error-level log for the abandoned completion:\n%s", logs)
	}
	if strings.Contains(logs, "scan completed") {
		t.Fatalf("completion was logged although it was never persisted:\n%s", logs)
	}
}

// TestCompletionDoesNotOverwriteConcurrentCancel covers the ownership rule: a
// cancel that lands while the completion write keeps failing must win. finish
// may not write COMPLETED over it, and it must drop its own execution so the
// scan is not simultaneously "canceling" and "running here".
func TestCompletionDoesNotOverwriteConcurrentCancel(t *testing.T) {
	ctx := context.Background()
	env := newCompletionEnv(t)
	env.scans.failCompletionWrites(-1) // no completion write may ever land
	// The injected failure stands in for a Cancel that got there first: move
	// the row to `canceling` the way Controller.Cancel does, through the REAL
	// repo (the fault is only on the completion write itself).
	env.scans.setOnFailure(func() {
		cur, err := env.store.Store.Scans().Get(ctx, env.scan)
		if err != nil || cur.State != domain.ScanRunning {
			return
		}
		cur.State = domain.ScanCanceling
		_ = env.store.Store.Scans().Update(ctx, cur)
	})
	env.start(t)

	waitFor(t, 3*time.Second, func() bool {
		sc, err := env.store.Scans().Get(ctx, env.scan)
		return err == nil && sc.State != domain.ScanRunning
	})

	if sc := env.state(t); sc.State == domain.ScanCompleted {
		t.Fatal("finish overwrote a concurrent cancel with completed")
	}
	if hasState(env.scans.writtenStates(), domain.ScanCompleted) {
		t.Fatal("a COMPLETED row reached the store after a concurrent cancel won")
	}
	// The distinct log line is written after finish releases ownership, so wait
	// for it rather than racing the monitor's last statement.
	waitFor(t, 2*time.Second, func() bool {
		return strings.Contains(env.logs.String(), "completion superseded")
	})
	if env.ctrl.IsRunning(env.scan) {
		t.Fatal("a superseded completion kept ownership of the execution")
	}
}

// TestCompletionReleasesOwnershipWhenStoreIsUnavailable is the fully-down case:
// neither the completion nor the failure can be written. The scan must not be
// reported completed, and the monitor must still exit and release the
// execution instead of keeping a phantom "running" scan in the map.
func TestCompletionReleasesOwnershipWhenStoreIsUnavailable(t *testing.T) {
	env := newCompletionEnv(t)
	// The scan's own `created -> running` write must land (otherwise Start
	// fails); every write after that is rejected, so the completion write, its
	// retries, and the resulting failure record all fail.
	env.scans.failWritesAfter(1)
	env.start(t)

	waitFor(t, 3*time.Second, func() bool { return !env.ctrl.IsRunning(env.scan) })

	// The row is left where it was (still `running`): with the store down there
	// is nothing truthful to write, and a restart's recovery is what resumes
	// it. What matters is that no completed state was ever claimed.
	if sc := env.state(t); sc.State == domain.ScanCompleted {
		t.Fatal("scan reported completed while every write was failing")
	}
	if hasState(env.scans.writtenStates(), domain.ScanCompleted) {
		t.Fatal("a COMPLETED row reached the store while every write was failing")
	}
}

// TestResumeDuringFinalizingCompletionRebuildsExecution covers the window this
// fix opens deliberately: the execution stays registered while its completion
// write is in flight. A pause that lands there moves the scan to `paused`; a
// following resume must build a NEW execution instead of "resuming" a pool that
// was already torn down — otherwise the scan would look running with nothing
// driving it, which is the same phantom this path exists to prevent.
func TestResumeDuringFinalizingCompletionRebuildsExecution(t *testing.T) {
	ctx := context.Background()
	env := newCompletionEnv(t)
	env.scans.failCompletionWrites(-1) // completion keeps failing: the window stays open
	env.start(t)

	// Wait until finish has actually attempted the write (and failed), i.e. the
	// execution is torn down but still owned.
	waitFor(t, 3*time.Second, func() bool {
		return strings.Contains(env.logs.String(), "finish: retrying completion write")
	})

	if err := env.ctrl.Pause(ctx, env.scan); err != nil {
		t.Fatalf("pause during finalizing completion: %v", err)
	}
	env.scans.failCompletionWrites(0) // the store recovers for the rebuilt execution
	if err := env.ctrl.Resume(ctx, env.scan); err != nil {
		t.Fatalf("resume after a finalizing completion: %v", err)
	}
	if !env.ctrl.IsRunning(env.scan) {
		t.Fatal("resume did not install a live execution")
	}
	// A rebuilt execution is a NEW worker pool. Reusing the finalizing one would
	// leave the scan "running" with a dead pool behind it.
	if got := strings.Count(env.logs.String(), "worker pool started"); got < 2 {
		t.Fatalf("worker pool starts = %d, want at least 2 (resume must rebuild, not un-stop a finished pool)", got)
	}

	waitFor(t, 3*time.Second, func() bool {
		sc, err := env.store.Scans().Get(ctx, env.scan)
		return err == nil && sc.State == domain.ScanCompleted
	})
	if !hasState(env.scans.writtenStates(), domain.ScanCompleted) {
		t.Fatal("rebuilt execution never persisted its completion")
	}
}

func hasState(states []domain.ScanState, want domain.ScanState) bool {
	for _, s := range states {
		if s == want {
			return true
		}
	}
	return false
}

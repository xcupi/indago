package scan

// White-box: scanHTTPEngine is what actually makes a scan's raw HTTP
// candidate/reflection testing (not just browser verification) respect a
// per-scan domain.ScanConfig.ProxyPool / TLS override / hunting User-Agent.
// See proxy_pool_test.go (scan_test) for the create/validate/persist half.
//
// The fail-closed contract these tests pin: when the scan asked for one of those
// and the client that carries it cannot be built, the scan MUST NOT fall back to
// the shared engine — that would send target traffic unproxied, with Go's TLS
// fingerprint or without the operator's hunting identifier.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

// failClosedEngine stands in for the shared engine. Every Do is a request the
// scan was NOT allowed to send directly.
type failClosedEngine struct {
	requests atomic.Int64
}

func (e *failClosedEngine) Do(context.Context, *httpengine.Request) (*httpengine.Response, error) {
	e.requests.Add(1)
	return &httpengine.Response{Status: 200, Body: []byte("ok")}, nil
}

func TestScanHTTPEngineSharesEngineWithoutProxyPool(t *testing.T) {
	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test", Options{HTTP: shared})

	eng, closeEng, err := c.scanHTTPEngine(&domain.Scan{})
	if err != nil {
		t.Fatalf("scanHTTPEngine without a proxy/TLS/UA request = %v, want the shared engine", err)
	}
	defer closeEng()

	if eng != httpengine.Engine(shared) {
		t.Fatalf("expected the shared engine to be reused when no scoped client is requested, got a different engine")
	}
}

func TestScanHTTPEngineBuildsDedicatedClientForProxyPool(t *testing.T) {
	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	baseCfg := httpengine.DefaultConfig()
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: shared, HTTPConfig: baseCfg})

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"http://proxy1:8080"}}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	if err != nil {
		t.Fatalf("scanHTTPEngine with a valid pool = %v, want a dedicated client", err)
	}
	defer closeEng()

	if eng == httpengine.Engine(shared) {
		t.Fatal("expected a scan-scoped client when ProxyPool is set, got the shared engine")
	}
	if _, ok := eng.(*httpengine.Client); !ok {
		t.Fatalf("expected a *httpengine.Client, got %T", eng)
	}
	// closeEng must be safe to call without crashing (releases the dedicated
	// client's idle connections; stopExecution calls it unconditionally).
	closeEng()
}

// A pool entry that New() itself rejects (not CreateScan's validateProxyPool,
// which catches most of them — this is the defensive path for a row that
// somehow still fails to build) must REFUSE the scan, never fall back.
func TestScanHTTPEngineFailsClosedWhenPoolEntryIsUnusable(t *testing.T) {
	shared := &failClosedEngine{}
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: shared, HTTPConfig: httpengine.DefaultConfig()})

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"://not a valid url"}}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	defer closeEng()

	if !errors.Is(err, ErrScanHTTPClient) {
		t.Fatalf("scanHTTPEngine with an unusable pool entry = %v, want ErrScanHTTPClient", err)
	}
	if eng != nil {
		t.Fatalf("scanHTTPEngine returned %T alongside the error; a refused scan must not get any engine", eng)
	}
	if n := shared.requests.Load(); n != 0 {
		t.Fatalf("the shared engine was used %d time(s) for a refused scan", n)
	}
}

// An internal construction failure (not a config-validation failure) follows the
// same fail-closed path.
func TestScanHTTPEngineFailsClosedOnInternalConstructionFailure(t *testing.T) {
	old := newHTTPEngine
	newHTTPEngine = func(httpengine.Config) (*httpengine.Client, error) {
		return nil, errors.New("internal: transport construction failed")
	}
	t.Cleanup(func() { newHTTPEngine = old })

	shared := &failClosedEngine{}
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: shared, HTTPConfig: httpengine.DefaultConfig()})

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"http://127.0.0.1:3128"}}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	defer closeEng()

	if !errors.Is(err, ErrScanHTTPClient) {
		t.Fatalf("scanHTTPEngine with an internal construction failure = %v, want ErrScanHTTPClient", err)
	}
	if eng != nil {
		t.Fatalf("engine = %T, want nil", eng)
	}
	if n := shared.requests.Load(); n != 0 {
		t.Fatalf("shared engine used %d time(s) after a construction failure", n)
	}
}

// A hunting User-Agent that cannot be applied must be reported, not silently
// dropped: continuing would send requests without the operator's identifier.
func TestScanHTTPEngineFailsClosedForUserAgentOnly(t *testing.T) {
	old := newHTTPEngine
	newHTTPEngine = func(httpengine.Config) (*httpengine.Client, error) {
		return nil, errors.New("internal: client construction failed")
	}
	t.Cleanup(func() { newHTTPEngine = old })

	shared := &failClosedEngine{}
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: shared, HTTPConfig: httpengine.DefaultConfig()})

	sc := &domain.Scan{Config: domain.ScanConfig{HuntingUserAgent: "indago-hunting/1.0"}}
	eng, closeEng, err := c.scanHTTPEngine(sc)
	defer closeEng()

	if !errors.Is(err, ErrScanHTTPClient) {
		t.Fatalf("scanHTTPEngine with an unappliable hunting User-Agent = %v, want ErrScanHTTPClient", err)
	}
	if eng != nil {
		t.Fatalf("engine = %T, want nil", eng)
	}
	if !strings.Contains(err.Error(), "User-Agent") {
		t.Fatalf("error %q does not say the User-Agent could not be applied", err)
	}
	if n := shared.requests.Load(); n != 0 {
		t.Fatalf("shared engine used %d time(s) after dropping the User-Agent", n)
	}
}

// The refusal is persisted on the scan, so a proxy credential embedded in the
// pool URL must not travel with it.
func TestScanHTTPEngineRedactsProxyCredentials(t *testing.T) {
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: &failClosedEngine{}, HTTPConfig: httpengine.DefaultConfig()})

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"http://user:s3cr3t@[::1"}}}
	_, closeEng, err := c.scanHTTPEngine(sc)
	defer closeEng()

	if !errors.Is(err, ErrScanHTTPClient) {
		t.Fatalf("scanHTTPEngine = %v, want ErrScanHTTPClient", err)
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("proxy credential leaked into the scan error: %v", err)
	}
	if !strings.Contains(err.Error(), "***@") {
		t.Fatalf("error %q does not show a redacted userinfo", err)
	}
}

// launch is the single path Start/Resume take. It must abort before the worker
// pool, discovery or preflight exist, so a refused scan emits ZERO target
// requests and leaves no running execution behind.
func TestLaunchSendsNothingWhenScopedClientCannotBeBuilt(t *testing.T) {
	shared := &failClosedEngine{}
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test", Options{HTTP: shared})
	sc := &domain.Scan{
		ID: domain.NewID(),
		Config: domain.ScanConfig{
			ProxyPool:               []string{"http://127.0.0.1:3128"},
			RandomizeTLSFingerprint: true, // mutually exclusive with a proxy: New() refuses it
		},
	}

	ex, err := c.launch(context.Background(), sc, domain.Scope{}, nil)
	if !errors.Is(err, ErrScanHTTPClient) {
		t.Fatalf("launch = %v, want ErrScanHTTPClient", err)
	}
	if ex != nil {
		t.Fatalf("launch returned an execution for a refused scan")
	}
	if n := shared.requests.Load(); n != 0 {
		t.Fatalf("launch sent %d direct target request(s) through the shared engine", n)
	}
	c.mu.Lock()
	running := len(c.running)
	c.mu.Unlock()
	if running != 0 {
		t.Fatalf("refused launch left %d running execution(s)", running)
	}
}

package scan

// White-box: scanHTTPEngine is what actually makes a scan's raw HTTP
// candidate/reflection testing (not just browser verification) respect a
// per-scan domain.ScanConfig.ProxyPool. See proxy_pool_test.go (scan_test)
// for the create/validate/persist half of this feature.

import (
	"log/slog"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func TestScanHTTPEngineSharesEngineWithoutProxyPool(t *testing.T) {
	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test", Options{HTTP: shared})

	eng, closeEng := c.scanHTTPEngine(&domain.Scan{})
	defer closeEng()

	if eng != httpengine.Engine(shared) {
		t.Fatalf("expected the shared engine to be reused when ProxyPool is empty, got a different engine")
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
	eng, closeEng := c.scanHTTPEngine(sc)
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

func TestScanHTTPEngineFallsBackWhenPoolEntryIsUnusable(t *testing.T) {
	// A pool entry that New() itself rejects (not CreateScan's own
	// validateProxyPool, which should already have caught this — this
	// exercises the defensive fallback for a client that somehow still fails
	// to build) must not crash scanHTTPEngine; it should fall back to the
	// shared engine with a logged warning.
	shared, err := httpengine.New(httpengine.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	baseCfg := httpengine.DefaultConfig()
	baseCfg.ProxyPool = []string{"http://ignored:1"} // overwritten by sc.Config.ProxyPool below
	c := NewController(memory.New(), queue.NewMemory(), slog.Default(), "test",
		Options{HTTP: shared, HTTPConfig: baseCfg})

	sc := &domain.Scan{Config: domain.ScanConfig{ProxyPool: []string{"://not a valid url"}}}
	eng, closeEng := c.scanHTTPEngine(sc)
	defer closeEng()

	if eng != httpengine.Engine(shared) {
		t.Fatal("expected fallback to the shared engine when the dedicated client fails to build")
	}
}

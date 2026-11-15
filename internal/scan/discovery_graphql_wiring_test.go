package scan

// Wiring for the lightweight GraphQL well-known probe: discovery asks /graphql
// on every scan that keeps the GraphQL engine, and asks nothing when the
// operator skipped it (domain.ScanConfig.SkipGraphQL). The discovery side is
// tested in internal/discovery; this test pins the per-scan switch that feeds it.

import (
	"io"
	"log/slog"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func TestDiscoveryConfigCarriesSkipGraphQL(t *testing.T) {
	ctrl := NewController(memory.New(), queue.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test", Options{})
	t.Cleanup(ctrl.Shutdown)

	// Default: the GraphQL engine runs, so discovery probes the conventional
	// entry point even at the conservative default (no wordlist recon).
	on := ctrl.discoveryConfig(&domain.Scan{Config: domain.ScanConfig{}})
	if on.SkipGraphQLProbe {
		t.Fatal("GraphQL probe disabled for a scan that keeps the GraphQL engine")
	}
	if on.ReconLevel != "" && on.ReconLevel.Enabled() {
		t.Fatalf("test premise broken: recon level = %q, want the default (no recon)", on.ReconLevel)
	}

	// -skip-graphql: nothing would consume the endpoint, so nothing probes it.
	off := ctrl.discoveryConfig(&domain.Scan{Config: domain.ScanConfig{SkipGraphQL: true}})
	if !off.SkipGraphQLProbe {
		t.Fatal("GraphQL probe still enabled for a scan with SkipGraphQL set")
	}
}

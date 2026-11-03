package scan_test

// Recon-level wiring: the per-scan wordlist recon level is validated and
// persisted at creation (opt-in, default off) and rejected when unknown.

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

func TestCreateScanPersistsReconLevel(t *testing.T) {
	f := setup(t, true, []string{"example.com"})
	sc, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
		ReconLevel: "standard",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sc.Config.ReconLevel != "standard" {
		t.Fatalf("recon level = %q, want standard", sc.Config.ReconLevel)
	}

	// Default stays off: no recon_level means the pre-existing behaviour.
	def, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
	})
	if err != nil {
		t.Fatalf("create default: %v", err)
	}
	if def.Config.ReconLevel != "" {
		t.Fatalf("default recon level = %q, want empty (off)", def.Config.ReconLevel)
	}
}

func TestCreateScanRejectsUnknownReconLevel(t *testing.T) {
	f := setup(t, true, []string{"example.com"})
	_, err := f.ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: f.proj, TargetID: f.tgt, Profile: domain.ProfileBalanced,
		ReconLevel: "loud",
	})
	if !errors.Is(err, scan.ErrBadConfig) {
		t.Fatalf("expected ErrBadConfig, got %v", err)
	}
}

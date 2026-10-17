package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// Candidate profile settings are validated when the scan is created, stored in
// the scan's config, and survive on the persisted row.
func TestCreateScanCandidateProfileValidationAndPersistence(t *testing.T) {
	st, q := memory.New(), queue.NewMemory()
	site := standardSite(t)
	proj, tgt := seedProject(t, st, site.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	ctx := context.Background()
	base := scan.CreateScanParams{ProjectID: proj, TargetID: tgt, Name: "p"}

	for _, bad := range []struct {
		profile string
		max     int
	}{{"aggressive", 0}, {"standard", 33}, {"standard", 1000000}, {"standard", -1}, {"", -5}} {
		p := base
		p.CandidateProfile, p.MaxCandidates = bad.profile, bad.max
		if _, err := ctrl.CreateScan(ctx, p); !errors.Is(err, scan.ErrBadConfig) {
			t.Fatalf("profile=%q max=%d: err = %v, want ErrBadConfig", bad.profile, bad.max, err)
		}
	}

	p := base
	p.CandidateProfile, p.MaxCandidates = "minimal", 2
	sc, err := ctrl.CreateScan(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.Scans().Get(ctx, sc.ID)
	if got.Config.CandidateProfile != "minimal" || got.Config.MaxCandidates != 2 {
		t.Fatalf("persisted config = %+v", got.Config)
	}

	// Defaults: nothing set means the standard profile (stored as empty).
	def, err := ctrl.CreateScan(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := st.Scans().Get(ctx, def.ID); d.Config.CandidateProfile != "" || d.Config.MaxCandidates != 0 {
		t.Fatalf("default config = %+v", d.Config)
	}
}

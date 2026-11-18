package scan

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

// Both write-probe slices require the server-wide AllowStateChanging opt-in AND
// the per-scan flag; skip_write_endpoints suppresses them too. A per-scan flag
// alone must never authorize a POST.
func TestWriteProbeGatesRequireBothOptIns(t *testing.T) {
	adminCases := []struct {
		name  string
		cfg   domain.ScanConfig
		allow bool
		want  bool
	}{
		{"per-scan only", domain.ScanConfig{EnableAdminStepProbe: true}, false, false},
		{"server only", domain.ScanConfig{}, true, false},
		{"double opt-in", domain.ScanConfig{EnableAdminStepProbe: true}, true, true},
		{"skip write endpoints", domain.ScanConfig{EnableAdminStepProbe: true, SkipWriteEndpoints: true}, true, false},
	}
	for _, tc := range adminCases {
		if got := adminStepProbeEnabled(tc.cfg, tc.allow); got != tc.want {
			t.Errorf("adminStepProbeEnabled(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}

	objectCases := []struct {
		name  string
		cfg   domain.ScanConfig
		allow bool
		want  bool
	}{
		{"per-scan only", domain.ScanConfig{EnableObjectFamilyProbe: true}, false, false},
		{"server only", domain.ScanConfig{}, true, false},
		{"double opt-in", domain.ScanConfig{EnableObjectFamilyProbe: true}, true, true},
		{"skip write endpoints", domain.ScanConfig{EnableObjectFamilyProbe: true, SkipWriteEndpoints: true}, true, false},
	}
	for _, tc := range objectCases {
		if got := objectFamilyProbeEnabled(tc.cfg, tc.allow); got != tc.want {
			t.Errorf("objectFamilyProbeEnabled(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

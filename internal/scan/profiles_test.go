package scan_test

import (
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

func TestProfileConfigDefaults(t *testing.T) {
	bal := scan.ProfileConfig(domain.ProfileBalanced)
	if bal.DiscoveryConcurrency != 4 || bal.HTTPConcurrency != 10 || bal.BrowserConcurrency != 2 {
		t.Fatalf("balanced defaults wrong: %+v", bal)
	}
	cons := scan.ProfileConfig(domain.ProfileConservative)
	if cons.HTTPConcurrency >= bal.HTTPConcurrency {
		t.Fatal("conservative should be lower concurrency than balanced")
	}
	fast := scan.ProfileConfig(domain.ProfileFast)
	if fast.HTTPConcurrency <= bal.HTTPConcurrency {
		t.Fatal("fast should be higher concurrency than balanced")
	}
	// Unknown profile falls back to balanced.
	unk := scan.ProfileConfig(domain.ProfileName("weird"))
	if unk != bal {
		t.Fatalf("unknown profile should fall back to balanced, got %+v", unk)
	}
}

func TestEvaluateStop(t *testing.T) {
	cases := []struct {
		name      string
		policy    domain.StopPolicy
		confirmed int
		wantStop  bool
		wantPause bool
	}{
		{"continue", domain.StopPolicy{Mode: domain.StopContinueAll}, 5, false, false},
		{"first-none", domain.StopPolicy{Mode: domain.StopFirstConfirmed}, 0, false, false},
		{"first-hit", domain.StopPolicy{Mode: domain.StopFirstConfirmed}, 1, true, false},
		{"n-below", domain.StopPolicy{Mode: domain.StopAfterNConfirmed, ConfirmedLimit: 3}, 2, false, false},
		{"n-hit", domain.StopPolicy{Mode: domain.StopAfterNConfirmed, ConfirmedLimit: 3}, 3, true, false},
		{"pause-ask", domain.StopPolicy{Mode: domain.StopPauseAndAsk}, 1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := scan.EvaluateStop(tc.policy, tc.confirmed)
			if d.Stop != tc.wantStop || d.Pause != tc.wantPause {
				t.Fatalf("got stop=%v pause=%v, want stop=%v pause=%v", d.Stop, d.Pause, tc.wantStop, tc.wantPause)
			}
		})
	}
}

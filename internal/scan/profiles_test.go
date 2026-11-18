package scan_test

import (
	"reflect"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
)

func TestProfileConfigDefaults(t *testing.T) {
	bal := scan.ProfileConfig(domain.ProfileBalanced)
	if bal.DiscoveryConcurrency != 4 || bal.HTTPConcurrency != 10 || bal.BrowserConcurrency != 2 || bal.RequestsPerSecond != 10 {
		t.Fatalf("balanced defaults wrong: %+v", bal)
	}
	cons := scan.ProfileConfig(domain.ProfileConservative)
	if cons.DiscoveryConcurrency != 2 || cons.HTTPConcurrency != 4 || cons.BrowserConcurrency != 1 || cons.RequestsPerSecond != 2 {
		t.Fatalf("conservative defaults wrong: %+v", cons)
	}
	if cons.HTTPConcurrency >= bal.HTTPConcurrency || cons.RequestsPerSecond >= bal.RequestsPerSecond {
		t.Fatal("conservative should be lower concurrency/rate than balanced")
	}
	fast := scan.ProfileConfig(domain.ProfileFast)
	if fast.HTTPConcurrency <= bal.HTTPConcurrency || fast.RequestsPerSecond <= bal.RequestsPerSecond {
		t.Fatal("fast should be higher concurrency/rate than balanced")
	}
	// An unnamed or unknown profile falls back to the conservative default —
	// never to the more aggressive balanced preset.
	for _, name := range []domain.ProfileName{"", "weird"} {
		if got := scan.ProfileConfig(name); !reflect.DeepEqual(got, cons) {
			t.Fatalf("profile %q should fall back to conservative, got %+v", name, got)
		}
	}
	if domain.DefaultProfile != domain.ProfileConservative {
		t.Fatalf("domain.DefaultProfile = %q, want conservative", domain.DefaultProfile)
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

package main

import (
	"testing"

	"github.com/indago/indago/internal/config"
)

func TestRateLimitFlagsOverlayConfigAndValidate(t *testing.T) {
	base := config.ServerConfig{Addr: "127.0.0.1:8750", APIRate: 7, APIBurst: 30}
	cases := []struct {
		name      string
		set       map[string]bool
		rate      float64
		burst     int
		wantRate  float64
		wantBurst int
		wantErr   bool
	}{
		{"no flags keep config", map[string]bool{}, 50, 200, 7, 30, false},
		{"flags override config", map[string]bool{"api-rate": true, "api-burst": true}, 2, 4, 2, 4, false},
		{"only rate flag set", map[string]bool{"api-rate": true}, 9, 200, 9, 30, false},
		{"rate 0 disables", map[string]bool{"api-rate": true}, 0, 30, 0, 30, false},
		{"negative rate refused", map[string]bool{"api-rate": true}, -1, 30, 0, 0, true},
		{"burst 0 with rate refused", map[string]bool{"api-burst": true}, 7, 0, 0, 0, true},
		{"negative burst refused", map[string]bool{"api-burst": true}, 7, -2, 0, 0, true},
	}
	for _, c := range cases {
		got, err := overlayRateLimitFlags(base, c.set, c.rate, c.burst)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if got.APIRate != c.wantRate || got.APIBurst != c.wantBurst {
			t.Errorf("%s: got %v/%d, want %v/%d", c.name, got.APIRate, got.APIBurst, c.wantRate, c.wantBurst)
		}
	}
}

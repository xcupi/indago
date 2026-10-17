package main

import (
	"fmt"

	"github.com/indago/indago/internal/config"
)

// overlayRateLimitFlags applies -api-rate/-api-burst over the config-file
// values, the way -addr overrides config.json. Only flags the operator actually
// passed (set) replace the config value; flags left at their defaults never
// override it. The result is validated, so a bad value fails before the server
// starts.
func overlayRateLimitFlags(sc config.ServerConfig, set map[string]bool, rate float64, burst int) (config.ServerConfig, error) {
	if set["api-rate"] {
		sc.APIRate = rate
	}
	if set["api-burst"] {
		sc.APIBurst = burst
	}
	if err := sc.Validate(); err != nil {
		return config.ServerConfig{}, fmt.Errorf("invalid -api-rate/-api-burst: %w", err)
	}
	return sc, nil
}

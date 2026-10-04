package scan

import "github.com/indago/indago/internal/domain"

// Worker group names used by the controller to map scan concurrency controls to
// worker pool groups.
const (
	GroupDiscovery = "discovery"
	GroupHTTP      = "http"
	GroupBrowser   = "browser"
)

// ProfileConfig returns the concurrency/rate preset for a named profile.
//
// Defaults are conservative by design. The Balanced profile matches the spec's
// initial defaults (Discovery=4, HTTP=10, Browser=2). Custom returns Balanced as
// a starting point for the caller to override.
func ProfileConfig(name domain.ProfileName) domain.ScanConfig {
	switch name {
	case domain.ProfileConservative:
		return domain.ScanConfig{
			DiscoveryConcurrency: 2,
			HTTPConcurrency:      4,
			BrowserConcurrency:   1,
			RequestsPerSecond:    2,
		}
	case domain.ProfileFast:
		return domain.ScanConfig{
			DiscoveryConcurrency: 8,
			HTTPConcurrency:      25,
			BrowserConcurrency:   4,
			RequestsPerSecond:    50,
		}
	case domain.ProfileBalanced, domain.ProfileCustom:
		fallthrough
	default:
		return domain.ScanConfig{
			DiscoveryConcurrency: 4,
			HTTPConcurrency:      10,
			BrowserConcurrency:   2,
			RequestsPerSecond:    10,
		}
	}
}

// StopDecision is the outcome of evaluating a stop policy.
type StopDecision struct {
	Stop   bool
	Pause  bool // pause-and-ask instead of stopping
	Reason string
}

// EvaluateStop decides whether a scan should stop or pause given the number of
// confirmed findings so far. It is a pure function so the stop controls are
// testable independently of scan execution.
func EvaluateStop(policy domain.StopPolicy, confirmed int) StopDecision {
	switch policy.Mode {
	case domain.StopFirstConfirmed:
		if confirmed >= 1 {
			return StopDecision{Stop: true, Reason: "stop after first confirmed finding"}
		}
	case domain.StopAfterNConfirmed:
		if policy.ConfirmedLimit > 0 && confirmed >= policy.ConfirmedLimit {
			return StopDecision{Stop: true, Reason: "confirmed limit reached"}
		}
	case domain.StopPauseAndAsk:
		if confirmed >= 1 {
			return StopDecision{Pause: true, Reason: "pause and ask after confirmed finding"}
		}
	case domain.StopContinueAll:
		// never stops on findings
	}
	return StopDecision{}
}

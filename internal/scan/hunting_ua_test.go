package scan

import (
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestHuntingUserAgentAppendAndReplace(t *testing.T) {
	c := &Controller{}
	sc := &domain.Scan{Config: domain.ScanConfig{HuntingUserAgent: "-BugBounty-CyberGhost--31337"}}
	if got, want := c.huntingUserAgent(sc), "Indago -BugBounty-CyberGhost--31337"; got != want {
		t.Fatalf("append = %q, want %q", got, want)
	}

	sc.Config.HuntingUserAgent = " -BugBounty-CyberGhost--31337 "
	if got, want := c.huntingUserAgent(sc), "Indago -BugBounty-CyberGhost--31337"; got != want {
		t.Fatalf("trimmed append = %q, want %q", got, want)
	}

	sc.Config.HuntingUserAgent = "Mozilla/5.0 BugBounty"
	sc.Config.HuntingUserAgentReplace = true
	if got, want := c.huntingUserAgent(sc), "Mozilla/5.0 BugBounty"; got != want {
		t.Fatalf("replace = %q, want %q", got, want)
	}

	sc.Config.HuntingUserAgent = ""
	if got := c.huntingUserAgent(sc); got != "" {
		t.Fatalf("empty = %q, want empty (engine default)", got)
	}
}

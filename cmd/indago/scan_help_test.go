package main

import (
	"flag"
	"strconv"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

// The -max-candidates help must not promise a single per-point cap: after the
// canonical set at a point completes without confirmation, the automatic
// bypass fallback may add up to its own bounded Technique allowance. An
// operator who reads only this flag's help has to be able to see that.
func TestScanCreateMaxCandidatesHelpDisclosesAutomaticFallback(t *testing.T) {
	fs := flag.NewFlagSet("scan create", flag.ContinueOnError)
	registerMaxCandidates(fs)

	f := fs.Lookup("max-candidates")
	if f == nil {
		t.Fatal("-max-candidates flag is not registered")
	}
	usage := f.Usage
	// The cap must be scoped in the clause that defines it, not merely appear
	// somewhere later in the sentence (the fallback clause says "canonical" too).
	if !strings.HasPrefix(usage, "cap on CANONICAL candidates") {
		t.Fatalf("help must open by scoping the cap to canonical candidates, got %q", usage)
	}
	cap := strconv.Itoa(detection.MaxEvasionCandidatesPerInjectionPoint)
	if !strings.Contains(usage, "automatic") || !strings.Contains(usage, cap) {
		t.Fatalf("help must disclose the separately bounded automatic fallback and its cap (%s), got %q", cap, usage)
	}
}

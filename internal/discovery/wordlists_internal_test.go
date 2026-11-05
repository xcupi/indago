package discovery

import (
	"strings"
	"testing"
)

// The curated lists must stay in the documented size bands and be free of
// duplicates/blank entries: the per-level request arithmetic in
// docs/recon-wordlists.md is computed from them.
func TestEmbeddedWordlistSizes(t *testing.T) {
	bands := []struct {
		name  string
		level ReconLevel
		min   int
		max   int
	}{
		{"safe", ReconSafe, 150, 300},
		{"aggressive", ReconAggressive, 150, 300},
	}
	for _, b := range bands {
		paths := b.level.Paths()
		if len(paths) < b.min || len(paths) > b.max {
			t.Fatalf("%s path list has %d entries, want %d..%d", b.name, len(paths), b.min, b.max)
		}
		seen := make(map[string]bool, len(paths))
		for _, p := range paths {
			if strings.TrimSpace(p) == "" || strings.HasPrefix(p, "#") {
				t.Fatalf("%s list contains a blank/comment entry %q", b.name, p)
			}
			if seen[p] {
				t.Fatalf("%s list contains duplicate %q", b.name, p)
			}
			seen[p] = true
		}
	}
	if n := len(builtinParamNames()); n < 100 || n > 200 {
		t.Fatalf("parameter list has %d entries, want 100..200", n)
	}
	exts := builtinExtensions()
	if len(exts) == 0 || len(exts) > 12 {
		t.Fatalf("extension list has %d entries", len(exts))
	}
	for _, want := range []string{".bak", ".old", ".orig", ".zip", ".sql", ".tar.gz", ".json", "~"} {
		found := false
		for _, e := range exts {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("extension list is missing %q", want)
		}
	}
}

// The aggressive list is the safe list plus the extended entries: a higher
// level only ever adds probes, never replaces them.
func TestAggressivePathsSupersetOfSafe(t *testing.T) {
	safe := map[string]bool{}
	for _, p := range corePaths() {
		safe[p] = true
	}
	for _, p := range ReconAggressive.Paths() {
		if !safe[p] {
			continue
		}
		delete(safe, p)
	}
	if len(safe) != 0 {
		t.Fatalf("aggressive list dropped %d core path(s): %v", len(safe), safe)
	}
}

func TestParamNamesForEndpointRotatesDeterministically(t *testing.T) {
	names := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		names = append(names, "p"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	first := paramNamesForEndpoint(names, 0)
	second := paramNamesForEndpoint(names, 0)
	if len(first) != maxParamProbesPerEndpoint {
		t.Fatalf("first endpoint got %d names, want %d", len(first), maxParamProbesPerEndpoint)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatal("parameter selection is not deterministic")
	}
	other := paramNamesForEndpoint(names, 1)
	if strings.Join(first, ",") == strings.Join(other, ",") {
		t.Fatal("endpoint rotation did not move the window")
	}
	if got := paramNamesForEndpoint(nil, 0); got != nil {
		t.Fatalf("empty list produced %v", got)
	}
}

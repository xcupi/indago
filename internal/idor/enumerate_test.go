package idor

// Bounded enumeration tests: fixed arithmetic only, no network. The exact sets
// are part of the engine's contract — an operator must be able to predict every
// identifier a scan will try before it runs.

import (
	"strings"
	"testing"
)

func enumerationValues(cs []Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Value)
	}
	return out
}

// TestEnumerateNumericBaselineIsExact is the required arithmetic check:
// baseline 7 with N=3 must produce exactly 6, 8, 1, 2, 3.
func TestEnumerateNumericBaselineIsExact(t *testing.T) {
	got := EnumerateCandidates("7", 3)
	want := []string{"6", "8", "1", "2", "3"}
	if strings.Join(enumerationValues(got), ",") != strings.Join(want, ",") {
		t.Fatalf("enumeration of 7 with N=3 = %v, want %v", enumerationValues(got), want)
	}
	for _, c := range got {
		if c.Source != "enumerate" || c.Shape != ShapeNumeric {
			t.Fatalf("candidate %+v must be a numeric enumeration candidate", c)
		}
	}
}

// TestEnumerateZeroPaddedStaysPadded: a padded baseline produces ONLY
// zero-padded variants, at the baseline's width.
func TestEnumerateZeroPaddedStaysPadded(t *testing.T) {
	got := EnumerateCandidates("007", 3)
	want := []string{"006", "008", "001", "002", "003"}
	if strings.Join(enumerationValues(got), ",") != strings.Join(want, ",") {
		t.Fatalf("enumeration of 007 with N=3 = %v, want %v", enumerationValues(got), want)
	}
	for _, v := range enumerationValues(got) {
		if len(v) != 3 || v[0] != '0' {
			t.Fatalf("unpadded value %q produced from a zero-padded baseline", v)
		}
	}
}

func TestEnumerateArithmeticEdgeCases(t *testing.T) {
	t.Run("baseline 1 never proposes 0", func(t *testing.T) {
		got := enumerationValues(EnumerateCandidates("1", 3))
		for _, v := range got {
			if v == "0" || v == "1" {
				t.Fatalf("baseline 1 produced %v", got)
			}
		}
		if strings.Join(got, ",") != "2,3" {
			t.Fatalf("baseline 1 with N=3 = %v, want [2 3]", got)
		}
	})

	t.Run("slug baseline gets the fixed neighbour set", func(t *testing.T) {
		got := enumerationValues(EnumerateCandidates("wiener", 5))
		if strings.Join(got, ",") != "admin,test,demo,guest" {
			t.Fatalf("slug enumeration = %v, want admin,test,demo,guest", got)
		}
	})

	t.Run("opaque baselines are never enumerated", func(t *testing.T) {
		for _, own := range []string{
			"8f14e45f-ceea-467f-a8d5-1b3c4d5e6f70",
			"wiener@example.com",
			"a3f9c1e0b7d2e4f5",
			"",
		} {
			if got := EnumerateCandidates(own, 5); len(got) != 0 {
				t.Fatalf("opaque baseline %q was enumerated: %v", own, enumerationValues(got))
			}
		}
	})

	t.Run("N is clamped and the set is hard-capped", func(t *testing.T) {
		got := EnumerateCandidates("7", 100)
		if len(got) > MaxEnumerationPerSite {
			t.Fatalf("N=100 produced %d candidates, cap is %d", len(got), MaxEnumerationPerSite)
		}
		// The last candidate must come from 1..10, never from 1..100.
		if v := got[len(got)-1].Value; v != "10" {
			t.Fatalf("last clamped candidate = %q, want 10", v)
		}
		opts := EnumerationOptions{Neighbours: 100}
		if n := opts.ResolveNeighbours(); n != MaxEnumerationNeighbours {
			t.Fatalf("ResolveNeighbours(100) = %d, want %d", n, MaxEnumerationNeighbours)
		}
	})

	t.Run("the baseline is never repeated", func(t *testing.T) {
		for _, v := range enumerationValues(EnumerateCandidates("2", 5)) {
			if v == "2" {
				t.Fatal("enumeration proposed the baseline itself")
			}
		}
	})
}

// TestEnumerateIsDeterministic guards the "same scan data, same probes" rule.
func TestEnumerateIsDeterministic(t *testing.T) {
	first := strings.Join(enumerationValues(EnumerateCandidates("42", 4)), ",")
	second := strings.Join(enumerationValues(EnumerateCandidates("42", 4)), ",")
	if first != second {
		t.Fatalf("enumeration is not deterministic: %q vs %q", first, second)
	}
}

// TestDeriveLegacyNumericSetUnchanged pins the pre-enumeration derivation that
// enumeration-off scans still use, verbatim.
func TestDeriveLegacyNumericSetUnchanged(t *testing.T) {
	got, reason := DeriveCandidates("7", nil, nil, 0)
	if reason != "" {
		t.Fatalf("reason = %q, want none", reason)
	}
	want := []string{"8", "6", "9", "5", "10"}
	var values []string
	for _, c := range got {
		values = append(values, c.Value)
	}
	if strings.Join(values, ",") != strings.Join(want, ",") {
		t.Fatalf("legacy derivation of 7 = %v, want %v", values, want)
	}
}

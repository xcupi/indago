package idor

// Bounded enumeration: the classic `?id=1`, `?id=2`, … case.
//
// Harvesting can only propose identifiers the scan's own data already
// contains. On a real target the victim's identifier often appears nowhere in
// the caller's pages (the PortSwigger "User ID controlled by request
// parameter" lab is exactly this: carlos never appears in wiener's pages), so
// a harvester-only engine would sit silent on the most common IDOR class.
//
// Enumeration is therefore a small, OPT-IN, hard-bounded arithmetic step:
//
//	numeric baseline 7, N=3  → 6, 8, 1, 2, 3
//	padded baseline 007,N=3  → 006, 008, 001, 002, 003
//	slug baseline wiener     → admin, test, demo, guest
//
// It is not a wordlist and not a brute force: at most
// MaxEnumerationPerSite values, the arithmetic is fixed and deterministic,
// and every probe still goes through idor.Decide — a response that returns
// the caller's own data is Rejected, never Confirmed.

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// DefaultEnumerationNeighbours is N when the operator enables enumeration
	// without choosing a value: value±1 then 1..5.
	DefaultEnumerationNeighbours = 5
	// MaxEnumerationNeighbours is the hard ceiling on N. It exists so no
	// configuration can turn the engine into an enumeration run.
	MaxEnumerationNeighbours = 10
	// MaxEnumerationPerSite is the hard ceiling on enumeration candidates for
	// one injection point: the two direct neighbours plus 1..N.
	MaxEnumerationPerSite = 2 + MaxEnumerationNeighbours
)

// enumerationSlugs are the only slug neighbours ever tried. A short random
// slug gets these four common lab/operator accounts, never a wordlist.
var enumerationSlugs = []string{"admin", "test", "demo", "guest"}

// EnumerationOptions is the scan's opt-in for bounded enumeration.
type EnumerationOptions struct {
	// Enabled is the operator's explicit -idor-enumerate / idor_enumerate
	// switch. Off (the zero value) changes nothing about the engine.
	Enabled bool
	// Neighbours is N in the specification. Non-positive means
	// DefaultEnumerationNeighbours; values above MaxEnumerationNeighbours are
	// clamped.
	Neighbours int
}

// ResolveNeighbours clamps N into the engine's stated range.
func (o EnumerationOptions) ResolveNeighbours() int {
	n := o.Neighbours
	if n <= 0 {
		n = DefaultEnumerationNeighbours
	}
	if n > MaxEnumerationNeighbours {
		n = MaxEnumerationNeighbours
	}
	return n
}

// EnumerateCandidates returns the bounded, deterministic enumeration set for
// one observed baseline value.
//
// Numeric baseline n (width w, optionally zero-padded):
//
//	n-1 (only when > 0), n+1, then 1..N — each formatted with zero padding
//	ONLY when the baseline itself was zero-padded, at the baseline's width.
//
// Short-slug baseline: admin, test, demo, guest. Anything else (UUID, email,
// long opaque value) yields nothing: there is no meaningful "nearby" value.
//
// The caller's own value is never repeated, and the set is capped at
// MaxEnumerationPerSite.
func EnumerateCandidates(own string, neighbours int) []Candidate {
	if neighbours <= 0 {
		neighbours = DefaultEnumerationNeighbours
	}
	if neighbours > MaxEnumerationNeighbours {
		neighbours = MaxEnumerationNeighbours
	}
	own = strings.TrimSpace(own)
	if own == "" {
		return nil
	}

	seen := map[string]bool{strings.ToLower(own): true}
	out := make([]Candidate, 0, MaxEnumerationPerSite)
	add := func(value string, shape Shape) {
		if value == "" || len(out) >= MaxEnumerationPerSite {
			return
		}
		key := strings.ToLower(value)
		if seen[key] || !candidateShaped(value) {
			return
		}
		seen[key] = true
		out = append(out, Candidate{Value: value, Source: "enumerate", Shape: shape})
	}

	num, width, padded, ok := numericBaseline(own)
	if ok {
		if num > 1 {
			add(formatNumeric(num-1, width, padded), ShapeNumeric)
		}
		add(formatNumeric(num+1, width, padded), ShapeNumeric)
		for i := 1; i <= neighbours; i++ {
			add(formatNumeric(i, width, padded), ShapeNumeric)
		}
		return out
	}

	// A short slug (username-shaped, e.g. wiener) gets only the fixed common
	// neighbours. UUIDs, emails, asset fingerprints and opaque values are never
	// enumerated: there is no meaningful "nearby" value to try.
	if shape, ok := classifyHarvested(own); ok && shape == ShapeUsername {
		for _, slug := range enumerationSlugs {
			add(slug, ShapeUsername)
		}
	}
	return out
}

// numericBaseline parses a numeric observed value and reports the zero-padding
// format that must be preserved: width is the baseline's digit count and
// padded is true when it starts with '0' (007).
func numericBaseline(own string) (n, width int, padded, ok bool) {
	if !numericRE.MatchString(own) || len(own) > 12 {
		return 0, 0, false, false
	}
	parsed, err := strconv.Atoi(own)
	if err != nil || parsed < 0 {
		return 0, 0, false, false
	}
	return parsed, len(own), len(own) > 1 && own[0] == '0', true
}

// formatNumeric renders a neighbour, preserving the baseline's width and zero
// padding when it had any.
func formatNumeric(v, width int, padded bool) string {
	if !padded {
		return strconv.Itoa(v)
	}
	return fmt.Sprintf("%0*d", width, v)
}

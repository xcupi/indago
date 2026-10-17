package web

import (
	"crypto/sha256"
	"testing"
)

// Internal test for the bearer comparison helper (constant-time, fixed-length
// digest comparison).
func TestBearerMatches(t *testing.T) {
	const tok = "indago-test-token-9f2c7d41a8e6b305c1d9e2f7a4b8c6d0"
	d := sha256.Sum256([]byte(tok))
	digest := d[:]

	cases := map[string]struct {
		header string
		want   bool
	}{
		"exact Bearer":            {"Bearer " + tok, true},
		"lowercase scheme":        {"bearer " + tok, true},
		"wrong token same length": {"Bearer " + tok[:len(tok)-1] + "X", false},
		"prefix of token":         {"Bearer " + tok[:20], false},
		"token plus suffix":       {"Bearer " + tok + "x", false},
		"empty token":             {"Bearer ", false},
		"scheme only":             {"Bearer", false},
		"basic scheme":            {"Basic " + tok, false},
		"no header":               {"", false},
		"bare token":              {tok, false},
	}
	for name, c := range cases {
		if got := bearerMatches(c.header, digest); got != c.want {
			t.Errorf("%s: bearerMatches = %v, want %v", name, got, c.want)
		}
	}
	if bearerMatches("Bearer "+tok, nil) {
		t.Error("a nil digest (auth disabled) must never match")
	}
}

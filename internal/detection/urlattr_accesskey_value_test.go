package detection_test

// Regression for the attribute-value defect in the href breakout family: the
// accesskey declaration the planner emits must carry a BARE value. The historical
// shape quoted the value with the same delimiter that closes the href —
//
//	'accesskey='x' onclick=<marker> x='
//
// — so a reader that takes the value's bytes literally (the verification layer
// deriving the key to dispatch, or any entity-decoding consumer) saw a value
// beginning with a quote ('x) instead of x, and the access-key chord it pressed
// could never reach the handler. The unquoted form keeps the delimiter quote
// outside the value, so the value is exactly one character:
//
//	'accesskey=x onclick=<marker> x='
//
// These tests plan real reflected sites for both quote styles (and for the
// unproven-delimiter case, where both styles are planned) and assert the
// invariant on EVERY generated variant of the family, so the regression cannot
// come back through a new shape.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// accessKeyValueOf returns the raw bytes a value reader sees after
// `accesskey=`: everything up to the next whitespace or the end of the tag.
// It deliberately neither strips quotes nor trims: a reader such as the
// verification layer must never have to, because whatever it reads is the KEY
// it dispatches. A quote or a space in the returned bytes is the defect this
// test exists to catch.
func accessKeyValueOf(v string) (string, bool) {
	i := strings.Index(strings.ToLower(v), "accesskey")
	if i < 0 {
		return "", false
	}
	i += len("accesskey")
	for i < len(v) && isAttrSpace(v[i]) {
		i++
	}
	if i >= len(v) || v[i] != '=' {
		return "", false
	}
	i++
	for i < len(v) && isAttrSpace(v[i]) {
		i++
	}
	start := i
	for i < len(v) && !isAttrSpace(v[i]) && v[i] != '>' {
		i++
	}
	return v[start:i], true
}

func isAttrSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// bareAccessKey reports whether a reader sees exactly one printable,
// non-quote character — the only thing that can be dispatched as a single
// access-key chord, and what "the value is x, never 'x" means operationally.
func bareAccessKey(value string) bool {
	if len(value) != 1 {
		return false
	}
	c := value[0]
	return c > 0x20 && c < 0x7f && c != '\'' && c != '"' && c != '`'
}

// TestGeneratedAccessKeyValuesAreBareCharacters is the regression itself: for
// every variant the planner generates in this family — both quote styles, the
// link-attribute shape and the raw-query href breakout, proven and unproven
// delimiters alike — parsing the accesskey value yields a bare character.
func TestGeneratedAccessKeyValuesAreBareCharacters(t *testing.T) {
	fixtures := []struct {
		name           string
		body           []byte
		loc            domain.ParamLocation
		wantBreakouts  int // href breakout variants (Candidate.Delimiter != "")
		wantAccessKeys int // every candidate in the plan declaring an accesskey
	}{
		{"named parameter, single-quoted link", hrefFixture("link", sq, false, urlAttrProbe.Value()), domain.LocationQuery, 0, 2},
		{"named parameter, double-quoted link", hrefFixture("link", dq, false, urlAttrProbe.Value()), domain.LocationQuery, 0, 2},
		// The raw-query plan also carries the TAB-separated sibling of every
		// accesskey-bearing shape (href and link), so each of those candidates
		// is inspected too: 2 href + 2 link.
		{"raw query, single-quoted href", hrefFixture("link", sq, false, urlAttrProbe.Value()), domain.LocationRawQuery, 1, 4},
		{"raw query, double-quoted href", hrefFixture("link", dq, false, urlAttrProbe.Value()), domain.LocationRawQuery, 1, 4},
		// The analyser cannot prove the delimiter here, so BOTH styles are
		// planned; each must still carry a clean value. Plus the link shape.
		// With the TAB siblings: 2 href + 2 link per style, so 6 total.
		{"raw query, unproven delimiter", quoteFixture(dq, "angles", urlAttrProbe.Value()), domain.LocationRawQuery, 2, 6},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			_, plan := urlAttrPlan(t, tc.body, tc.loc)

			breakouts := hrefBreakouts(plan)
			if len(breakouts) != tc.wantBreakouts {
				t.Fatalf("%d href breakouts planned, want %d: %+v", len(breakouts), tc.wantBreakouts, plan.Candidates)
			}

			// Every href breakout variant, in this family, parses to x.
			for _, c := range breakouts {
				if got := parseBareAccessKey(t, c.Value); got != "x" {
					t.Fatalf("%s-quoted breakout declares accesskey=%q, want the bare character x: %q", c.Delimiter, got, c.Value)
				}
			}

			// And so does every other generated candidate that declares an
			// accesskey (the link-attribute shape shares the vector). Walking
			// the whole plan means a future variant cannot slip through.
			seen := 0
			for _, c := range plan.Candidates {
				if !strings.Contains(strings.ToLower(c.Value), "accesskey") {
					continue
				}
				seen++
				if got := parseBareAccessKey(t, c.Value); got != "x" {
					t.Fatalf("candidate %q declares accesskey=%q, want the bare character x", c.Value, got)
				}
			}
			if seen != tc.wantAccessKeys {
				t.Fatalf("inspected %d accesskey-bearing candidates, want %d (the fixture must really exercise the family)", seen, tc.wantAccessKeys)
			}
		})
	}
}

// parseBareAccessKey extracts the declared value and fails unless a reader sees
// exactly one bare character (no leading/trailing quote, no whitespace).
func parseBareAccessKey(t *testing.T, value string) string {
	t.Helper()
	got, ok := accessKeyValueOf(value)
	if !ok {
		t.Fatalf("candidate %q has no readable accesskey declaration", value)
	}
	if !bareAccessKey(got) {
		t.Fatalf("candidate %q parses accesskey value %q, want a bare single character (no quotes, no whitespace)", value, got)
	}
	return got
}

// TestAccessKeyValueReaderRejectsTheHistoricalShape proves the check is
// sensitive: the shape this regression came from — the value quoted with the
// very delimiter that closes the href — parses as a value beginning with a
// quote, so it must be rejected by the same predicate the plan test uses.
func TestAccessKeyValueReaderRejectsTheHistoricalShape(t *testing.T) {
	old := `'accesskey='x' onclick=` + urlAttrProbe.Token + ` x='`
	got, ok := accessKeyValueOf(old)
	if !ok {
		t.Fatalf("reader could not read the historical shape %q", old)
	}
	if got == "x" || bareAccessKey(got) {
		t.Fatalf("historical shape %q parses as %q, which the bare-value check must reject", old, got)
	}
	if !strings.HasPrefix(got, sq) {
		t.Fatalf("historical shape parses as %q, want a value beginning with the delimiter quote", got)
	}

	// The fixed shape, for contrast: the same reader sees exactly the key.
	fixed := `'accesskey=x onclick=` + urlAttrProbe.Token + ` x='`
	if got, ok := accessKeyValueOf(fixed); !ok || !bareAccessKey(got) || got != "x" {
		t.Fatalf("fixed shape %q parses as %q (ok=%v), want the bare character x", fixed, got, ok)
	}
}

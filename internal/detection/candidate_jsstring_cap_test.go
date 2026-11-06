package detection_test

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

// Measured on PortSwigger lab 5 (search box): the same value is reflected
// twice — once in element text and once inside a single-quoted JS string — and
// the reader HTML-encodes < > " while backslash-escaping every quote. With two
// sites on one injection point the per-point cap has to choose, and the
// escape-breaker lost: it was judged as needing a raw quote (which this reader
// provably escapes), so it was deprioritized below every shape whose characters
// were merely entity-encoded, and dropped before it was ever sent.
//
// The shape's real dependency is the BACKSLASH, not the quote: it exists
// precisely because the reader escapes the quote. Planning must reflect that,
// otherwise the one route that works is the one route never tried.
func TestPlanBackslashBreakSurvivesThePerPointCapOnATwoSiteEcho(t *testing.T) {
	m := tok()
	angleQuotes := func(v string) string {
		v = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(v)
		return strings.ReplaceAll(v, `'`, `\'`)
	}
	probe := angleQuotes(candProbe.Value())
	doc := "<h1>0 search results for '" + probe + "'</h1>\n" +
		"<script>var searchTerms = '" + probe + "';</script>"
	rep := planBody(t, []byte(doc), candHTML)

	spec, err := detection.ResolveProfile("standard", 0)
	if err != nil {
		t.Fatal(err)
	}
	selected, _ := spec.Select(rep.Plan.Candidates)
	if len(selected) > spec.MaxPerInjectionPoint {
		t.Fatalf("selection exceeded the profile cap: %d > %d", len(selected), spec.MaxPerInjectionPoint)
	}
	want := `\';` + m + `//`
	for _, c := range selected {
		if c.Value == want {
			return
		}
	}
	var got []string
	for _, c := range selected {
		got = append(got, c.Value)
	}
	t.Fatalf("the backslash break %q was not selected within the cap; selected %v", want, got)
}

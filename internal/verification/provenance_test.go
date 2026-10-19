package verification

import (
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

func genuineException(marker string) browser.RuntimeException {
	return browser.RuntimeException{
		Location:         browser.RuntimeLocation{ScriptID: "7", FrameID: "main", ContextID: 3, SourceSHA256: "abc"},
		Description:      "ReferenceError: " + marker + " is not defined",
		ClassName:        "ReferenceError",
		MarkerIdentifier: true,
	}
}

func TestMatchRuntimeExecution(t *testing.T) {
	const m = "ind0123456789abcdef"
	base := func(ex ...browser.RuntimeException) browser.RuntimeObservations {
		return browser.RuntimeObservations{Available: true, MainFrameID: "main", Exceptions: ex}
	}
	cases := []struct {
		name string
		obs  browser.RuntimeObservations
		want bool
	}{
		{"engine attributed marker identifier confirms", base(genuineException(m)), true},
		{"unavailable provenance never confirms", browser.RuntimeObservations{MainFrameID: "main", Exceptions: []browser.RuntimeException{genuineException(m)}}, false},
		{"missing main frame never confirms", browser.RuntimeObservations{Available: true, Exceptions: []browser.RuntimeException{genuineException(m)}}, false},
		{"marker not at paused instruction never confirms", func() browser.RuntimeObservations {
			e := genuineException(m)
			e.MarkerIdentifier = false
			return base(e)
		}(), false},
		{"child frame exception never confirms main frame", func() browser.RuntimeObservations {
			e := genuineException(m)
			e.Location.FrameID = "child"
			return base(e)
		}(), false},
		{"wrong error class never confirms", func() browser.RuntimeObservations {
			e := genuineException(m)
			e.ClassName = "TypeError"
			return base(e)
		}(), false},
		{"description of another identifier never confirms", func() browser.RuntimeObservations {
			e := genuineException(m)
			e.Description = "ReferenceError: other is not defined"
			return base(e)
		}(), false},
		{"missing source digest never confirms", func() browser.RuntimeObservations {
			e := genuineException(m)
			e.Location.SourceSHA256 = ""
			return base(e)
		}(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got := MatchRuntimeExecution(m, tc.obs)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if _, _, ok := MatchRuntimeExecution("", base(genuineException(m))); ok {
		t.Fatal("empty marker confirmed")
	}
}

func TestHasUnattributedMarkerException(t *testing.T) {
	const m = "ind0123456789abcdef"
	forged := genuineException(m)
	forged.MarkerIdentifier = false
	unrelated := browser.RuntimeException{Description: "TypeError: x is not a function"}
	if !hasUnattributedMarkerException(m, browser.RuntimeObservations{Exceptions: []browser.RuntimeException{forged}}) {
		t.Fatal("forged marker exception was not flagged")
	}
	if hasUnattributedMarkerException(m, browser.RuntimeObservations{Exceptions: []browser.RuntimeException{unrelated}}) {
		t.Fatal("unrelated page error was flagged as forged")
	}
	if hasUnattributedMarkerException(m, browser.RuntimeObservations{MainFrameID: "main", Exceptions: []browser.RuntimeException{genuineException(m)}}) {
		t.Fatal("genuine attributed exception was flagged as forged")
	}
	child := genuineException(m)
	child.Location.FrameID = "child"
	if !hasUnattributedMarkerException(m, browser.RuntimeObservations{MainFrameID: "main", Exceptions: []browser.RuntimeException{child}}) {
		t.Fatal("genuine execution in a child frame must not read as a clean negative")
	}
	if !hasUnattributedMarkerException(m, browser.RuntimeObservations{Exceptions: []browser.RuntimeException{genuineException(m)}}) {
		t.Fatal("an unknown main frame must not read as a clean negative")
	}
	// CDP descriptions append the stack, and the page URL carries the payload
	// (and so the marker) in its query string. Only the message line counts.
	stackOnly := browser.RuntimeException{Description: "ReferenceError: other is not defined\n    at http://127.0.0.1:1/?q=%3C" + m + "x%3E:1:88"}
	if hasUnattributedMarkerException(m, browser.RuntimeObservations{Exceptions: []browser.RuntimeException{stackOnly}}) {
		t.Fatal("marker appearing only in the stack URL was flagged as forged")
	}
	forgedWithStack := forged
	forgedWithStack.Description += "\n    at http://127.0.0.1:1/?q=" + m + ":1:1"
	if !hasUnattributedMarkerException(m, browser.RuntimeObservations{Exceptions: []browser.RuntimeException{forgedWithStack}}) {
		t.Fatal("forged marker message with a stack was not flagged")
	}
	if hasUnattributedMarkerException("", browser.RuntimeObservations{Exceptions: []browser.RuntimeException{forged}}) {
		t.Fatal("empty marker flagged")
	}
}

func TestDecideWithProvenance(t *testing.T) {
	const m = "ind0123456789abcdef"
	avail := func(ex ...browser.RuntimeException) browser.RuntimeObservations {
		return browser.RuntimeObservations{Available: true, MainFrameID: "main", Exceptions: ex}
	}
	forged := genuineException(m)
	forged.MarkerIdentifier = false
	child := genuineException(m)
	child.Location.FrameID = "child"
	unrelated := browser.RuntimeException{Description: "TypeError: x is not a function\n    at http://h/?q=" + m}
	cases := []struct {
		name       string
		matched    bool
		inDOM      bool
		obs        browser.RuntimeObservations
		wantVerdct domain.Verdict
	}{
		{"matched confirms", true, true, avail(genuineException(m)), domain.VerdictConfirmed},
		{"unrelated error and nothing executed is rejected", false, true, avail(unrelated), domain.VerdictRejected},
		{"no exception at all, marker absent, stays inconclusive per decide", false, false, avail(), domain.VerdictInconclusive},
		{"forged message is inconclusive", false, true, avail(forged), domain.VerdictInconclusive},
		{"genuine child-frame execution is inconclusive", false, true, avail(child), domain.VerdictInconclusive},
		{"unavailable provenance is inconclusive even when matched elsewhere", false, true, browser.RuntimeObservations{MainFrameID: "main"}, domain.VerdictInconclusive},
		{"unknown main frame is inconclusive", false, true, browser.RuntimeObservations{Available: true}, domain.VerdictInconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, notes := DecideWithProvenance(m, tc.matched, tc.inDOM, tc.obs)
			if got != tc.wantVerdct {
				t.Fatalf("verdict = %s, want %s (%s)", got, tc.wantVerdct, notes)
			}
		})
	}
}

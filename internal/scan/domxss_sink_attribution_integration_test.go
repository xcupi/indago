//go:build browser_integration

package scan

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// This file pins the two measured properties of the lab page shape
// location.search -> element assignment:
//
//  1. an HTML-sink observation stands on its own: the same page confirms when
//     innerHTML is the ONLY assignment, and a text-only assignment
//     (innerText/textContent) never confirms, with the existing wording;
//  2. the measured external script is ordinary ES5 whose statements end at line
//     breaks, so the static pass must analyse it — no "could not be parsed" /
//     "could not be analysed" note for a file the browser happily runs.
//
// History: the earlier debug fixture served reflectedDOMScriptInnerHTML
// unmodified, which still contains the literal placeholder
// DECODE(searchResultsObj.searchTerm). That page throws
// "ReferenceError: DECODE is not defined" before it ever reaches its sink, so
// "innerHTML only -> 0 findings" measured a broken PAGE, not an attribution
// defect. The variants below substitute the real expression, so every page here
// actually runs its sink; the sink statement is then the only difference.

// attributionScript is the measured external script with the element
// assignment(s) as the only variable part. Statements deliberately end at line
// breaks (no semicolon), exactly as the live file does.
func attributionScript(assign string) string {
	return `function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var searchTerm = searchResultsObj.searchTerm
        var markup = "<h1>0 search results for '" + searchTerm + "'</h1>"
` + assign + `
    }
}
`
}

// attributionStaticScript is the same external-file shape, but with the flow
// visible to the STATIC pass as well (no XHR indirection): the assignment is
// still inside a function defined in the external script, so a site here can
// only come from analysing that file. The script loads before the
// .blog-header element exists, so showResults() re-runs itself at
// DOMContentLoaded; search() exists only because the shared page calls it.
const attributionStaticScript = `function showResults() {
    var term = new URLSearchParams(location.search).get('search')
    var header = document.getElementsByClassName("blog-header")[0]
    if (!header) {
        window.addEventListener('DOMContentLoaded', showResults)
        return
    }
    header.innerHTML = term
}
function search(path) {}
showResults()
`

// attributionNeverRunsScript is the previous (broken) shape of the fixture, kept
// as an honest negative: the script runs BEFORE the .blog-header element
// exists, so the sink statement throws and never executes in the browser.
const attributionNeverRunsScript = `function showResults() {
    var term = new URLSearchParams(location.search).get('search')
    var header = document.getElementsByClassName("blog-header")[0]
    header.innerHTML = term
}
showResults()
`

const attributionHTMLAssign = `        blogHeader.innerHTML = "<h1>0 search results for '" + searchTerm + "'</h1>"`

// TestDOMXSSSinkAttributionVariants is the four-variant matrix: the two text
// sinks stay negative on their own AND when combined with innerHTML, and the
// HTML sink confirms by itself.
func TestDOMXSSSinkAttributionVariants(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	for _, tc := range []struct {
		name, assign, textSink string
		confirm                bool
	}{
		{
			name:    "innerText+innerHTML",
			assign:  `        blogHeader.innerText = "0 results for '" + searchTerm + "'"` + "\n" + attributionHTMLAssign,
			confirm: true,
		},
		{
			name:    "innerHTML only",
			assign:  attributionHTMLAssign,
			confirm: true,
		},
		{
			name:     "textContent only",
			assign:   `        blogHeader.textContent = "<h1>0 search results for '" + searchTerm + "'</h1>"`,
			textSink: "textContent",
			confirm:  false,
		},
		{
			name:     "innerText only",
			assign:   `        blogHeader.innerText = "<h1>0 search results for '" + searchTerm + "'</h1>"`,
			textSink: "innerText",
			confirm:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lab := newReflectedLab(t, reflectedLab{sink: attributionScript(tc.assign)})
			findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
			if got := reflectedDOMConfirmed(findings); got != tc.confirm {
				t.Fatalf("confirmed=%v want %v: %s", got, tc.confirm, reflectedDOMVerdicts(findings))
			}
			// The script is ordinary ES5 in every variant, so no variant may
			// claim its reference could not be analysed.
			for _, c := range cases {
				if strings.Contains(c.Note, "could not be parsed") || strings.Contains(c.Note, "could not be analysed") {
					t.Fatalf("ordinary ES5 must not report a parse failure: %q", c.Note)
				}
			}
			note := reflectedDOMReachabilityNote(t, cases)
			if !tc.confirm {
				// The measured page also eval()s the XHR echo, and eval is an
				// implemented reachability sink, so the note names eval - and ONLY
				// eval: the text sink that fired must never be reported as a
				// reachable HTML sink, and nothing may confirm (asserted above).
				if !strings.HasPrefix(note, "reachable sink: eval from location.search") ||
					strings.Contains(note, "reachable sink: innerHTML") ||
					strings.Contains(note, "reachable sink: outerHTML") {
					t.Fatalf("text-only negative must name only the eval sink, note=%q", note)
				}
				for _, f := range findings {
					if f.Verdict != domain.VerdictRejected {
						t.Fatalf("a text-only sink must end Rejected, got %s", reflectedDOMVerdicts(findings))
					}
				}
				return
			}
			// An HTML-sink observation stands on its own: the sink the harness
			// reported must be innerHTML, never a text sink that happened to
			// fire on the same page.
			if !strings.Contains(note, "reachable sink: innerHTML ") {
				t.Fatalf("the HTML-sink observation must stand on its own, note=%q", note)
			}
			for _, f := range findings {
				if f.Verdict != domain.VerdictConfirmed {
					continue
				}
				if !strings.Contains(f.Title, "innerHTML") {
					t.Fatalf("confirmed finding must name the HTML sink, title=%q", f.Title)
				}
				if strings.Contains(f.Title, "innerText") || strings.Contains(f.Title, "textContent") {
					t.Fatalf("a text sink must never label a confirmed finding, title=%q", f.Title)
				}
			}
		})
	}
}

// TestDOMXSSExternalScriptES5StaticAnalysis: the measured file's ES5 (line-break
// statement ends, a for loop, string concatenation) must reach the static pass,
// and the sink inside the external function must confirm — with no parse-failure
// note anywhere. A page whose flow is statically visible proves the file was
// really analysed, not merely tolerated.
func TestDOMXSSExternalScriptES5StaticAnalysis(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	t.Run("measured XHR echo file confirms without a parse note", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: attributionScript(attributionHTMLAssign)})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		if !reflectedDOMConfirmed(findings) {
			t.Fatalf("innerHTML assigned inside a function in the external script must confirm: %s", reflectedDOMVerdicts(findings))
		}
		for _, c := range cases {
			if strings.Contains(c.Note, "could not be parsed") || strings.Contains(c.Note, "could not be analysed") {
				t.Fatalf("the measured file must not be reported as unparsable: %q", c.Note)
			}
		}
	})

	t.Run("statically visible sink in the external file is reported", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: attributionStaticScript})
		findings, cases, env := runReflectedDOMJobEnv(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if !strings.Contains(note, "static pass (advisory, no verdict): innerHTML reachable at ") {
			t.Fatalf("the static pass must analyse the external body and name its sink, note=%q", note)
		}
		if !strings.Contains(note, "/resources/js/searchResults.js") {
			t.Fatalf("the static site must carry the external script URL, note=%q", note)
		}
		if !strings.Contains(note, "reachable sink: innerHTML from location.search") {
			t.Fatalf("the sink must be reachable in the real browser, not only statically: %q", note)
		}
		if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
			t.Fatalf("line-break-terminated ES5 with an external innerHTML sink must Confirm: %s", reflectedDOMVerdicts(findings))
		}
		d := decodeFindingDetail(findings[0].Detail)
		var confirmed *domain.Finding
		var proof domain.ID
		for _, a := range d.Attempts {
			if a.Verdict == domain.VerdictConfirmed && !a.VerifyTestCaseID.Empty() {
				confirmed, proof = findings[0], a.VerifyTestCaseID
			}
		}
		if confirmed == nil {
			t.Fatalf("no Confirmed verification attempt with a test case: %+v", d.Attempts)
		}
		var attemptIDs []domain.ID
		for _, a := range d.Attempts {
			attemptIDs = append(attemptIDs, a.VerifyTestCaseID)
		}
		bodies := htmlSourceMatrixEvidenceFor(t, env, confirmed, proof, attemptIDs...)
		log := bodies[domain.EvidenceBrowserLog]
		marker := detection.NewProbe(env.scanID, confirmed.EndpointID).Token
		if !strings.Contains(log, "playwright: "+marker+" is not defined") {
			t.Fatalf("Confirmed needs the marker-specific browser page error: %s", log)
		}
		// The page must run cleanly apart from that signal: no fixture error
		// (undefined function, missing element) may stand in for the proof.
		for _, bad := range []string{"search is not defined", "showResults is not defined", "Cannot set properties of undefined", "Cannot read properties of undefined"} {
			if strings.Contains(log, bad) {
				t.Fatalf("unexpected fixture error %q in the verification log: %s", bad, log)
			}
		}
		if !strings.Contains(bodies[domain.EvidenceDOM], `onerror="`+marker+`"`) {
			t.Fatalf("the injected marker handler must be in the rendered DOM: %s", bodies[domain.EvidenceDOM])
		}
	})

	t.Run("a static sink the browser never runs is an advisory-only negative", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: attributionNeverRunsScript})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if !strings.Contains(note, "static pass (advisory, no verdict): innerHTML reachable at ") || !strings.Contains(note, "no implemented DOM-XSS sink reachable") {
			t.Fatalf("a sink that never runs must be a runtime negative that still names the static site, note=%q", note)
		}
		if len(findings) != 0 {
			t.Fatalf("static analysis alone must not create or confirm a finding: %s", reflectedDOMVerdicts(findings))
		}
	})
}

// TestDOMXSSEncodedEchoStaysNegativeEverywhere: the honesty control the matrix
// must not lose. An HTML-encoded echo is text; it stays negative through the
// innerHTML sink in the external script.
func TestDOMXSSEncodedEchoStaysNegativeEverywhere(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	lab := newReflectedLab(t, reflectedLab{sink: attributionScript(attributionHTMLAssign), echo: reflectedEchoHTMLEscaped})
	findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
	if reflectedDOMConfirmed(findings) {
		t.Fatalf("an HTML-encoded echo is text, not markup: %s", reflectedDOMVerdicts(findings))
	}
	// The canary is plain alphanumerics, so it genuinely reaches innerHTML even
	// when the echo is HTML-escaped: reachability is reported. The escaped
	// markup payload then does not execute, so every attempt must end Rejected.
	note := reflectedDOMReachabilityNote(t, cases)
	if !strings.HasPrefix(note, "reachable sink: innerHTML from location.search") {
		t.Fatalf("expected the canary to reach innerHTML, got %q", note)
	}
	if len(findings) == 0 {
		t.Fatal("a reachable sink with an escaped payload must record a Rejected finding, not nothing")
	}
	for _, f := range findings {
		if f.Verdict != domain.VerdictRejected {
			t.Fatalf("an HTML-encoded echo must end Rejected: %s", reflectedDOMVerdicts(findings))
		}
	}
}

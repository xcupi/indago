//go:build browser_integration

package scan

import (
	"strings"
	"testing"

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
// only come from analysing that file.
const attributionStaticScript = `function showResults() {
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
			assign:  `        h1.innerText = "0 results for '" + searchTerm + "'"` + "\n" + attributionHTMLAssign,
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
				if !strings.Contains(note, "no implemented DOM-XSS sink reachable") ||
					!strings.Contains(note, "text-only sink ("+tc.textSink+")") ||
					strings.Contains(note, "reachable sink:") {
					t.Fatalf("text-only negative wording changed: %q", note)
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
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if !strings.Contains(note, "static pass (advisory, no verdict): innerHTML reachable at ") {
			t.Fatalf("the static pass must analyse the external body and name its sink, note=%q", note)
		}
		if !strings.Contains(note, "/resources/js/searchResults.js") {
			t.Fatalf("the static site must carry the external script URL, note=%q", note)
		}
		if !reflectedDOMConfirmed(findings) {
			t.Fatalf("line-break-terminated ES5 with an external innerHTML sink must confirm: %s", reflectedDOMVerdicts(findings))
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
	note := reflectedDOMReachabilityNote(t, cases)
	if !strings.Contains(note, "no implemented DOM-XSS sink reachable") {
		t.Fatalf("expected the honest negative, got %q", note)
	}
}

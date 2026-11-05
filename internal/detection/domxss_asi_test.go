package detection_test

// Automatic semicolon insertion: ordinary ES5 ends statements at a line break.
// The external-script parser used to record "unparsed statement tail near var"
// for such code and reported the whole reference as unparsable.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
)

const asiScript = `function search(path) {
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
        var h1 = document.createElement("h1");
        blogHeader.innerHTML = "<h1>0 search results for '" + searchTerm + "'</h1>"
    }
}
var q = new URLSearchParams(location.search).get('search')
search('/search-results')
`

func asiStatic(t *testing.T, body string) detection.DOMXSSStaticResult {
	t.Helper()
	const pageURL = "http://lab.test/"
	page := `<!doctype html><html><head><script src="/a.js"></script></head><body></body></html>`
	f := &countingFetcher{bodies: map[string]string{"http://lab.test/a.js": body}}
	scripts := loadPage(t, detection.NewDOMXSSScriptLoader(), f, pageURL, page)
	return detection.DOMXSSStaticReachabilityWithScripts(page, pageURL, detection.DOMSourceQuery, "search", scripts)
}

func TestDOMXSSExternalScriptLineBreakStatementsParse(t *testing.T) {
	res := asiStatic(t, asiScript)
	if len(res.ScriptProblems) != 0 {
		t.Fatalf("ordinary ES5 with line-break statement ends must parse, got %+v", res.ScriptProblems)
	}
	if res.AnalysedScripts != 1 {
		t.Fatalf("analysed=%d, want 1", res.AnalysedScripts)
	}
}

func TestDOMXSSExternalScriptGenuinelyUnparseableStillReported(t *testing.T) {
	// Two expressions on ONE line with no separator is not valid JS and must
	// not be waved through by the line-break rule.
	res := asiStatic(t, "var a = 1 var b = 2;\nvar c = location.search;\n")
	if len(res.ScriptProblems) != 1 || res.ScriptProblems[0].Reason != detection.DOMXSSScriptSkipParseFailed {
		t.Fatalf("want one %q problem, got %+v", detection.DOMXSSScriptSkipParseFailed, res.ScriptProblems)
	}
	if !strings.Contains(res.ScriptProblems[0].Detail, "unparsed statement tail") {
		t.Fatalf("detail = %q", res.ScriptProblems[0].Detail)
	}
}

func TestDOMXSSReturnLineBreakReturnsNothing(t *testing.T) {
	res := asiStatic(t, "function f() {\n  return\n  location.search\n}\ndocument.write(f())\n")
	for _, s := range res.Sites {
		if s.Sink == detection.DOMSinkDocumentWrite {
			t.Fatalf("`return` + newline returns undefined; no taint may reach document.write: %+v", res.Sites)
		}
	}
}

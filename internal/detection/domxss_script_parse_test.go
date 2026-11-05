package detection

// The static pass reads scripts with a small hand-written parser. These tests
// pin the two properties the measured lab script exposed:
//
//   - ordinary ES5 that relies on automatic semicolon insertion parses cleanly
//     (the measured file terminates `var searchTerm = ...` with a line break and
//     increments a for-loop counter with `++i`, and the parser used to record
//     `unparsed statement tail near "var"` and skip the following statement);
//   - a construct the parser genuinely cannot understand is still REPORTED as a
//     parse failure, and the statements after it are still analysed — the fix is
//     not "declare everything parseable and stop complaining".

import (
	"strings"
	"testing"
)

// scriptMeasuredES5 is the measured /resources/js/searchResults.js shape with
// the sink written to innerHTML: a function holding an XMLHttpRequest, an
// onreadystatechange function that evals the response, and a second function
// with line-terminated `var` declarations, string concatenation, a for loop
// with `++i`, and an innerHTML write.
const scriptMeasuredES5 = `function search(path) {
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
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var markup = "<h1>0 search results for '" + searchTerm + "'</h1>";
        blogHeader.innerHTML = markup;
        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            blogList.innerHTML += "<br/>";
        }
    }
}
`

// parseForTest tokenizes and parses one script body, returning the program and
// every gap the parser recorded.
func parseForTest(t *testing.T, src string) (*dxsStmt, []dxsParseGap) {
	t.Helper()
	toks, err := dxsTokenize(src, 1)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	p := &dxsParser{toks: toks}
	prog := p.parseProgram()
	return prog, p.gaps
}

// TestDOMXSSLineTerminatedES5Parses: the measured file must produce no parse
// gap at all. Its constructs are all ordinary ES5, so an "unparsed statement
// tail" here means the static pass silently dropped real code.
func TestDOMXSSLineTerminatedES5Parses(t *testing.T) {
	_, gaps := parseForTest(t, scriptMeasuredES5)
	if len(gaps) != 0 {
		t.Fatalf("ordinary ES5 must parse without gaps, got %+v", gaps)
	}
}

// TestDOMXSSLineTerminatedStatementKeepsNextStatement: a line break ends a
// statement, but the statement that follows it is still parsed. Before the fix
// the parser recorded a gap at `document` and skipped the sink entirely, so this
// test fails both by finding no site and by reporting a gap.
func TestDOMXSSLineTerminatedStatementKeepsNextStatement(t *testing.T) {
	const page = `<!doctype html><body><script>var q = location.search
document.body.innerHTML = q
</script></body></html>`
	res := DOMXSSStaticReachability(page, DOMSourceQuery, "q")
	if len(res.Unresolved) != 0 {
		t.Fatalf("no construct here is unsupported, got %+v", res.Unresolved)
	}
	var found bool
	for _, site := range res.Sites {
		if site.Sink == DOMSinkInnerHTML {
			found = true
		}
	}
	if !found {
		t.Fatalf("the sink on the line after a line-terminated statement must still be analysed, got %+v", res.Sites)
	}
}

// TestDOMXSSExpressionContinuationIsNotSplitByALineBreak: the line break is only
// treated as a terminator where the expression parser has already stopped. A
// call continuation the grammar allows stays one statement, so the approximation
// does not invent a second statement out of `foo` + newline + `('x')`.
func TestDOMXSSExpressionContinuationIsNotSplitByALineBreak(t *testing.T) {
	prog, gaps := parseForTest(t, "var q = foo\n('x')\n")
	if len(gaps) != 0 {
		t.Fatalf("a legal continuation must not produce a gap, got %+v", gaps)
	}
	if len(prog.stmts) != 1 {
		t.Fatalf("a call continuation is ONE statement, got %d", len(prog.stmts))
	}
}

// TestDOMXSSReturnLineBreakEndsTheStatement: `return` is a restricted
// production. A newline after it ends the statement, so the next line is not its
// operand and must not be reported as the returned value.
func TestDOMXSSReturnLineBreakEndsTheStatement(t *testing.T) {
	prog, gaps := parseForTest(t, "function f() {\n    var q = location.search\n    return\n    q\n}\n")
	if len(gaps) != 0 {
		t.Fatalf("no gap expected, got %+v", gaps)
	}
	var ret *dxsStmt
	for _, st := range prog.stmts {
		if st.kind != dxsStmtFuncDecl || len(st.names) == 0 || st.names[0] != "f" || st.fn == nil {
			continue
		}
		for _, inner := range st.fn.body.stmts {
			if inner.kind == dxsStmtReturn {
				ret = inner
			}
		}
	}
	if ret == nil {
		t.Fatal("the return statement was not parsed")
	}
	if len(ret.exprs) != 0 {
		t.Fatalf("a line break after return ends the statement; got operand %+v", ret.exprs)
	}
}

// TestDOMXSSUnsupportedConstructStillReportsParseFailure: the honesty contract.
// `class` is genuinely unsupported by this parser, so the reference is still
// recorded as unparsable (the static pass turns that into "not analysed", never
// into a clean negative) — while the statements AFTER the unsupported construct
// are still analysed, so the fix never discards the file's remaining code.
func TestDOMXSSUnsupportedConstructStillReportsParseFailure(t *testing.T) {
	const page = `<!doctype html><html><head><script src="/app.js"></script></head><body></body></html>`
	const pageURL = "http://lab.test/"
	const body = `class Widget {
    constructor(name) { this.name = name; }
}
document.body.innerHTML = location.search;
`
	f := DOMXSSScriptFetcherFunc(func(string) (string, error) { return body, nil })
	scripts := NewDOMXSSScriptLoader().ScriptsFor(f, pageURL, DOMXSSScriptSrcs(page))
	res := DOMXSSStaticReachabilityWithScripts(page, pageURL, DOMSourceQuery, "q", scripts)

	if len(res.ScriptProblems) == 0 {
		t.Fatal("an unsupported construct must still be reported, not silently accepted")
	}
	if !strings.Contains(res.ScriptProblems[0].Reason, DOMXSSScriptSkipParseFailed) {
		t.Fatalf("problem reason = %q, want %q", res.ScriptProblems[0].Reason, DOMXSSScriptSkipParseFailed)
	}
	var sawGap bool
	for _, u := range res.Unresolved {
		if u.Reason == "unparsed script" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("the unsupported construct must stay in the unresolved list, got %+v", res.Unresolved)
	}
	var sawSink bool
	for _, site := range res.Sites {
		if site.Sink == DOMSinkInnerHTML {
			sawSink = true
		}
	}
	if !sawSink {
		t.Fatalf("statements after the unsupported construct must still be analysed, got %+v", res.Sites)
	}
}

// TestDOMXSSExternalScriptMeasuredFileHasNoParseProblem: end-to-end through the
// loader, the measured external file is analysed — no "could not be parsed"
// problem for the reference.
func TestDOMXSSExternalScriptMeasuredFileHasNoParseProblem(t *testing.T) {
	const page = `<!doctype html><html><head><script src="/resources/js/searchResults.js"></script></head><body></body></html>`
	const pageURL = "http://lab.test/"
	f := DOMXSSScriptFetcherFunc(func(string) (string, error) { return scriptMeasuredES5, nil })
	scripts := NewDOMXSSScriptLoader().ScriptsFor(f, pageURL, DOMXSSScriptSrcs(page))
	res := DOMXSSStaticReachabilityWithScripts(page, pageURL, DOMSourceQuery, "search", scripts)
	if len(res.ScriptProblems) != 0 {
		t.Fatalf("the measured file must not be reported as unparsable, got %+v", res.ScriptProblems)
	}
	for _, u := range res.Unresolved {
		if u.Reason == "unparsed script" {
			t.Fatalf("no parse gap expected in the measured file, got %+v", u)
		}
	}
}

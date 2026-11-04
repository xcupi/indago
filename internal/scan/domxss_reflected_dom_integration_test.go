//go:build browser_integration

package scan

// Real-Chromium fixture for the application page measured by QA lab
// `ps-sink-observation`.
//
// The page below is the one the live scan actually received: it is copied
// verbatim from that scan's own stored response evidence
// (`/resources/js/searchResults.js` and the document that loads it). What the
// page does with the echoed search term is the whole point of this file:
//
//	location.search -> XHR /search-results -> JSON -> eval -> searchTerm
//	                                                        |
//	                              h1.innerText <---------- +  (TEXT, never executes)
//
// so the marker never reaches an HTML sink on this page at all, and its only
// innerHTML write is the constant "<br/>". The engine's negative is therefore
// correct; what was missing was any statement of WHERE the marker went, which
// made a correct negative read like a blind sink hook.
//
// Asserted end to end through the real executor:
//
//  1. the measured page stays negative AND its note now names the text-only
//     sink that received the marker (the diagnostic);
//  2. the same page with its one `innerText` assignment changed to `innerHTML`
//     is CONFIRMED - the hook is not blind to a marker-bearing innerHTML write,
//     including one that arrives through XHR -> JSON -> eval;
//  3. a server that does not echo the marker stays negative, and says nothing
//     about text sinks (the diagnostic is marker-gated);
//  4. an HTML-encoded echo never confirms: escaped markup is text;
//  5. a percent-encoded echo confirms only when the page itself decodes it -
//     encoding is not sanitisation, but innerHTML does not percent-decode
//     either, so the two cases are kept apart instead of conflated;
//  6. an inline copy of the same script produces the same result as the
//     external file (golden control: the external-script path changed nothing).
//
// The lab is loopback httptest; no real host is contacted.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// reflectedDOMHTML is the live document, verbatim (the lab header's own
// stylesheet links and websocket script are kept: they are part of the page
// the scan measured).
const reflectedDOMHTML = `<!DOCTYPE html>
<html>
    <head>
        <link href=/resources/labheader/css/academyLabHeader.css rel=stylesheet>
        <link href=/resources/css/labsBlog.css rel=stylesheet>
        <title>Reflected DOM XSS</title>
    </head>
    <body>
        <script src="/resources/labheader/js/labHeader.js"></script>
        <div theme="blog">
            <section class="maincontainer">
                <div class="container is-page">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <script src='/resources/js/searchResults.js'></script>
                    <script>search('search-results')</script>
                    <section class="blog-header">
                    </section>
                    <section class=search>
                        <form action=/ method=GET>
                            <input type=text placeholder='Search the blog...' name=search>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
                    <section class="blog-list">
                    </section>
                </div>
            </section>
        </div>
    </body>
</html>`

// reflectedDOMInlineHTML is the same page with the script inlined: the golden
// control for "an external script and an inline script behave identically".
const reflectedDOMInlineHTML = `<!DOCTYPE html>
<html>
    <head><title>Reflected DOM XSS</title></head>
    <body>
        <script>__SCRIPT__</script>
        <script>search('search-results')</script>
        <section class="blog-header"></section>
        <section class=search>
            <form action=/ method=GET>
                <input type=text placeholder='Search the blog...' name=search>
                <button type=submit class=button>Search</button>
            </form>
        </section>
        <section class="blog-list"></section>
    </body>
</html>`

// reflectedDOMScriptInnerText is the live /resources/js/searchResults.js,
// verbatim: the echoed term is written with innerText.
const reflectedDOMScriptInnerText = `function search(path) {
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

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        blogHeader.appendChild(h1);
        var hr = document.createElement("hr");
        blogHeader.appendChild(hr)

        for (var i = 0; i < searchResults.length; ++i)
        {
            var searchResult = searchResults[i];
            if (searchResult.id) {
                var blogLink = document.createElement("a");
                blogLink.setAttribute("href", "/post?postId=" + searchResult.id);
                blogList.appendChild(blogLink);
            }

            blogList.innerHTML += "<br/>";
        }
    }
}
`

// reflectedDOMScriptInnerHTML is the SAME script with exactly one change: the
// echoed term is assigned to innerHTML instead of innerText. This is the shape
// the QA brief describes, and it must confirm.
const reflectedDOMScriptInnerHTML = `function search(path) {
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
        var searchTerm = DECODE(searchResultsObj.searchTerm)
        var h1 = "<h1>0 search results for '" + searchTerm + "'</h1>";
        blogHeader.innerHTML = h1;
        blogList.innerHTML = "";
    }
}
`

// reflectedDOMScriptMarkupGated is the exploitable page a bare text canary
// cannot expose: the term goes through innerHTML only once it looks like
// markup, otherwise it is written as text. The canary therefore reaches a
// text-only sink here even though the page has a real innerHTML sink.
const reflectedDOMScriptMarkupGated = `function search(path) {
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
        if (searchTerm.indexOf("<") !== -1) {
            blogHeader.innerHTML = "<h1>0 search results for '" + searchTerm + "'</h1>";
        } else {
            var h1 = document.createElement("h1");
            h1.innerText = "0 search results for '" + searchTerm + "'";
            blogHeader.appendChild(h1);
        }
    }
}
`

// reflectedDOMScriptTextContent writes the term with textContent whatever it
// looks like: a markup payload must stay inert here.
const reflectedDOMScriptTextContent = `function search(path) {
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
        var h1 = document.createElement("h1");
        h1.textContent = "0 search results for '" + searchResultsObj.searchTerm + "'";
        blogHeader.appendChild(h1);
    }
}
`

// reflectedDOMScriptInnerHTMLDecoded is the same innerHTML script but it
// percent-decodes the echoed term first: the page, not the scanner, turns a
// percent-encoded echo back into markup.
const reflectedDOMScriptInnerHTMLDecoded = reflectedDOMScriptInnerHTML

type reflectedEcho int

const (
	// reflectedEchoRaw returns the term exactly as the server received it.
	reflectedEchoRaw reflectedEcho = iota
	// reflectedEchoNone answers with an unrelated value: the marker never
	// reaches the page.
	reflectedEchoNone
	// reflectedEchoHTMLEscaped escapes the term for HTML: genuinely inert
	// through an innerHTML sink.
	reflectedEchoHTMLEscaped
	// reflectedEchoPercentEncoded returns the term percent-encoded, which
	// innerHTML does not decode.
	reflectedEchoPercentEncoded
)

// reflectedLab renders one variant of the measured application page.
type reflectedLab struct {
	echo   reflectedEcho
	sink   string // reflectedDOMScriptInnerText or ...InnerHTML
	decode bool   // page percent-decodes the echoed term before writing it
	inline bool   // serve the script inline instead of as a file
}

func newReflectedLab(t *testing.T, cfg reflectedLab) *httptest.Server {
	t.Helper()
	script := cfg.sink
	decodeExpr := "searchResultsObj.searchTerm"
	if cfg.decode {
		decodeExpr = "decodeURIComponent(searchResultsObj.searchTerm)"
	}
	script = strings.ReplaceAll(script, "DECODE(searchResultsObj.searchTerm)", decodeExpr)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if cfg.inline {
			fmt.Fprint(w, strings.ReplaceAll(reflectedDOMInlineHTML, "__SCRIPT__", script))
			return
		}
		fmt.Fprint(w, reflectedDOMHTML)
	})
	mux.HandleFunc("/resources/js/searchResults.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		fmt.Fprint(w, script)
	})
	mux.HandleFunc("/resources/labheader/js/labHeader.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		fmt.Fprint(w, "completedListeners = [];")
	})
	mux.HandleFunc("/search-results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		term := r.URL.Query().Get("search")
		switch cfg.echo {
		case reflectedEchoNone:
			term = ""
		case reflectedEchoHTMLEscaped:
			term = reflectedHTMLEscape(term)
		case reflectedEchoPercentEncoded:
			// Percent-encode for a URL value, but with %20 (not "+") for
			// spaces: decodeURIComponent, which is what a page would call,
			// leaves "+" alone.
			term = strings.ReplaceAll(url.QueryEscape(term), "+", "%20")
		}
		fmt.Fprintf(w, `{"results":[],"searchTerm":%q}`, term)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// reflectedHTMLEscape escapes the five markup-significant characters and
// leaves every alphanumeric marker byte untouched, so this control can never be
// satisfied by the marker simply disappearing.
func reflectedHTMLEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

// runReflectedDOMJob runs the location.search DOM-XSS job for the lab root and
// returns the findings recorded for that endpoint plus every TestCase.
func runReflectedDOMJob(t *testing.T, mgr *browser.Manager, labURL string) ([]*domain.Finding, []*domain.TestCase) {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(labURL+"/", domain.MethodGET)
	env.param(ep, "search", domain.LocationQuery, "x")
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, labURL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
		t.Fatalf("dom-xss job: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return sourceSelectionFindings(t, env.st, env.scanID, ep.ID), cases
}

// reflectedDOMReachabilityNote returns the reachability note recorded for the
// lab endpoint, so a test can assert on what the operator is told.
func reflectedDOMReachabilityNote(t *testing.T, cases []*domain.TestCase) string {
	t.Helper()
	for _, tc := range cases {
		if strings.Contains(tc.Note, "location.search parameter") {
			return tc.Note
		}
	}
	t.Fatalf("no location.search reachability case recorded: %+v", cases)
	return ""
}

func reflectedDOMConfirmed(findings []*domain.Finding) bool {
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			return true
		}
	}
	return false
}

// reflectedDOMVerdicts renders findings compactly for failure messages.
func reflectedDOMVerdicts(findings []*domain.Finding) string {
	var out []string
	for _, f := range findings {
		out = append(out, fmt.Sprintf("%s/%s", f.VulnClass, f.Verdict))
	}
	return "[" + strings.Join(out, " ") + "]"
}

func TestDOMXSSReflectedDOMPageShape(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	t.Run("measured page writes the marker with innerText and stays negative", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerText})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if len(findings) != 0 {
			t.Fatalf("a page that never writes the marker into an HTML sink must not produce a finding: %s", reflectedDOMVerdicts(findings))
		}
		if !strings.Contains(note, "no implemented DOM-XSS sink reachable") {
			t.Fatalf("expected the honest negative, got %q", note)
		}
		if !strings.Contains(note, "text-only sink (innerText)") {
			t.Fatalf("the negative must say where the marker actually went (innerText), got %q", note)
		}
		if strings.Contains(note, "reachable sink:") {
			t.Fatalf("a text write must never be reported as a reachable sink, got %q", note)
		}
	})

	t.Run("the same page with innerHTML confirms", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerHTML})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		if !reflectedDOMConfirmed(findings) {
			t.Fatalf("XHR -> JSON -> eval -> innerHTML must confirm, findings=%s notes=%d", reflectedDOMVerdicts(findings), len(cases))
		}
	})

	t.Run("server does not echo the marker stays negative", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerHTML, echo: reflectedEchoNone})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if reflectedDOMConfirmed(findings) {
			t.Fatalf("a response without the marker must not confirm: %s", reflectedDOMVerdicts(findings))
		}
		if !strings.Contains(note, "no implemented DOM-XSS sink reachable") {
			t.Fatalf("expected a negative, got %q", note)
		}
		if strings.Contains(note, "text-only sink") {
			t.Fatalf("the text-sink diagnostic is marker-gated and must be silent here, got %q", note)
		}
	})

	t.Run("HTML-encoded echo never confirms", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerHTML, echo: reflectedEchoHTMLEscaped})
		findings, _ := runReflectedDOMJob(t, mgr, lab.URL)
		if reflectedDOMConfirmed(findings) {
			t.Fatalf("an HTML-encoded echo is text, not markup: %s", reflectedDOMVerdicts(findings))
		}
	})

	t.Run("text canary reaching a text sink does not clear an innerHTML sink: markup payload confirms", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptMarkupGated})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		if !reflectedDOMConfirmed(findings) {
			t.Fatalf("innerHTML sink reached only by a markup payload must confirm, findings=%s notes=%d", reflectedDOMVerdicts(findings), len(cases))
		}
	})

	t.Run("textContent sink stays negative even with a markup payload", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptTextContent})
		findings, cases := runReflectedDOMJob(t, mgr, lab.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if len(findings) != 0 {
			t.Fatalf("textContent cannot execute markup: %s", reflectedDOMVerdicts(findings))
		}
		if !strings.Contains(note, "no implemented DOM-XSS sink reachable") || !strings.Contains(note, "text-only sink (textContent)") {
			t.Fatalf("expected the honest negative naming textContent, got %q", note)
		}
	})

	t.Run("innerHTML sink with an HTML-encoded echo stays negative under a markup payload", func(t *testing.T) {
		lab := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptMarkupGated, echo: reflectedEchoHTMLEscaped})
		findings, _ := runReflectedDOMJob(t, mgr, lab.URL)
		if reflectedDOMConfirmed(findings) {
			t.Fatalf("an HTML-encoded echo is text, not markup: %s", reflectedDOMVerdicts(findings))
		}
	})

	t.Run("percent-encoded echo confirms only because the page decodes it", func(t *testing.T) {
		encoded := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerHTML, echo: reflectedEchoPercentEncoded})
		if findings, _ := runReflectedDOMJob(t, mgr, encoded.URL); reflectedDOMConfirmed(findings) {
			t.Fatalf("innerHTML does not percent-decode, so an encoded echo must not confirm: %s", reflectedDOMVerdicts(findings))
		}
		decoded := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerHTMLDecoded, echo: reflectedEchoPercentEncoded, decode: true})
		if findings, cases := runReflectedDOMJob(t, mgr, decoded.URL); !reflectedDOMConfirmed(findings) {
			t.Fatalf("a percent-encoded echo the page itself decodes must confirm, findings=%s notes=%d", reflectedDOMVerdicts(findings), len(cases))
		}
	})

	t.Run("an inline copy of the script behaves the same", func(t *testing.T) {
		inline := newReflectedLab(t, reflectedLab{sink: reflectedDOMScriptInnerText, inline: true})
		findings, cases := runReflectedDOMJob(t, mgr, inline.URL)
		note := reflectedDOMReachabilityNote(t, cases)
		if len(findings) != 0 || !strings.Contains(note, "text-only sink (innerText)") {
			t.Fatalf("inline copy must keep the external file's result (negative, innerText), findings=%s note=%q", reflectedDOMVerdicts(findings), note)
		}
	})
}

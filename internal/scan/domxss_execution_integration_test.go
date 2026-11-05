//go:build browser_integration

package scan

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// The external script and XHR are deliberate: the query is absent from the
// document body, and only the server's response supplies the compiled code.
func TestDOMXSSExecutionXHR(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	for _, sink := range []string{"eval", "Function", "setTimeout"} {
		for _, control := range []string{"unsafe", "backslash", "no-marker", "constant", "encoded", "uninvoked", "forged", "csp"} {
			t.Run(sink+"/"+control, func(t *testing.T) {
				lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/resources/js/searchResults.js":
						w.Header().Set("Content-Type", "text/javascript")
						call := "eval(code);"
						if sink == "Function" {
							call = "new Function(code)();"
						}
						if sink == "setTimeout" {
							call = "setTimeout(code,0);"
						}
						if control == "uninvoked" {
							if sink == "Function" {
								call = "new Function(code);"
							} else {
								call = "void code;"
							}
						}
						if control == "constant" {
							call = "eval('var constant = 1');"
						}
						if control == "forged" {
							call = "console.error('ReferenceError: '+term+' is not defined');"
						}
						fmt.Fprint(w, `const term=new URLSearchParams(location.search).get('search');
       const xhr=new XMLHttpRequest();
       xhr.onreadystatechange=function(){if(this.readyState==4 && this.status==200){
        var code='var searchResultsObj = '+this.responseText;`+call+`
       }};
       xhr.open('GET','/search-results'+location.search);xhr.send();`)
					case "/search-results":
						w.Header().Set("Content-Type", "application/json")
						term := r.URL.Query().Get("search")
						switch control {
						case "no-marker":
							term = "constant"
						case "encoded":
							term = html.EscapeString(term)
						case "backslash":
							term = strings.ReplaceAll(term, `"`, `\"`)
						}
						fmt.Fprintf(w, `{"searchTerm":"%s","results":[]}`, term)
					default:
						w.Header().Set("Content-Type", "text/html")
						if control == "csp" {
							w.Header().Set("Content-Security-Policy", "script-src 'self'")
						}
						fmt.Fprint(w, `<!doctype html><body><script src="/resources/js/searchResults.js"></script></body>`)
					}
				}))
				defer lab.Close()
				env := newScanEnv(t)
				ep := env.endpoint(lab.URL+"/?search=term", domain.MethodGET)
				env.param(ep, "search", domain.LocationQuery, "term")
				ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
				if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
					t.Fatal(err)
				}
				fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
				want := control == "unsafe" || control == "backslash"
				confirmed := false
				for _, f := range fs {
					if f.Verdict != domain.VerdictConfirmed {
						continue
					}
					confirmed = true
					d := decodeFindingDetail(f.Detail)
					if len(d.Candidates) == 0 || string(d.Candidates[len(d.Candidates)-1].Context) != sink {
						t.Fatalf("wrong sink provenance: %+v", d)
					}
					foundProof := false
					for _, a := range d.Attempts {
						if a.VerifyTestCaseID == "" || a.Verdict != domain.VerdictConfirmed {
							continue
						}
						// The finding unions the evidence of every attempt: each row
						// must belong to one of them, the proof is read from this one.
						var attemptIDs []domain.ID
						for _, other := range d.Attempts {
							attemptIDs = append(attemptIDs, other.VerifyTestCaseID)
						}
						bodies := htmlSourceMatrixEvidenceFor(t, env, f, a.VerifyTestCaseID, attemptIDs...)
						if strings.Contains(bodies[domain.EvidenceBrowserLog], "is not defined") && strings.Contains(bodies[domain.EvidenceBrowserLog], `"marker_identifier":true`) {
							foundProof = true
						}
					}
					if !foundProof {
						t.Fatal("confirmed without stored native marker execution proof")
					}
				}
				if confirmed != want {
					t.Fatalf("confirmed=%v want=%v findings=%+v", confirmed, want, fs)
				}
			})
		}
	}
}

func TestDOMXSSEvalPreservesLexicalScope(t *testing.T) {
	fs, err := domXSSProvenanceFindings(t, `let local='local'; eval("local='changed'"); if(local!=='changed') throw Error('eval lost local scope'); eval(raw);`, "location.hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("direct eval must preserve local scope: %+v", fs)
	}
}

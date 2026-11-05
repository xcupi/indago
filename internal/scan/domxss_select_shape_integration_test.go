//go:build browser_integration

package scan

// The stock-checker lab shape, MEASURED against the base commit rather than
// assumed: a page's own script reads a client-side value and hands it to
// document.write INSIDE a <select>.
//
// The slice's premise — that HTML's "in select" insertion mode ignores the
// injected <img>, so only a select-closing shape can execute — is true for the
// HTML a pre-customizable-select parser built, but it is NOT true for the
// Chromium the verifier actually drives (Chrome 156 here; the spec change that
// allows arbitrary content inside <select> shipped with customizable select).
// Measured directly: a document.write'd `<option>x<img src=y onerror=…>` ends up
// as a real <img> element inside the <option>.
//
// The consequence, verified end to end below at the base commit:
//   - value as the <option>'s TEXT, query source: the first shape
//     (<script>MARKER</script> for query/document.write) executes → Confirmed;
//   - value as the <option>'s TEXT, any other source: the first markup shape
//     (<img src=x onerror=MARKER>) executes → Confirmed;
//   - value inside an ATTRIBUTE of an element inside the <select>: the first
//     shape is absorbed by the attribute, and the attribute-breakout shape
//     executes → Confirmed.
//
// So no new shape is added for this target: a select_breakout would only add a
// third browser navigation to every non-confirming document.write site and would
// never run at a site the earlier shapes already confirm. These cases pin the
// measured behaviour so a parser/shape regression shows up as a failure.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// The two client-side reads the same sink is driven from.
const (
	selectReadQuery = `let value=new URLSearchParams(location.search).get('storeId')||'';`
	selectReadHash  = `let value=decodeURIComponent(location.hash.slice(1))||'';`
)

// selectEscape is the control's pre-write escaping: every HTML-significant
// character is encoded, so no shape can leave the position it lands in.
const selectEscape = `value=value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');`

// selectTextBody is the documented nesting: the value is the text of an
// <option> inside the <select> document.write creates.
func selectTextBody(read, postRead string) string {
	return `<!doctype html><html><body><p>stock checker</p><script>` + read + postRead +
		`document.write('<select id="stockCheck"><option selected>'+value+'</option></select>');</script></body></html>`
}

// selectAttrBody is the sibling position the slice also worried about: the value
// lands inside an ATTRIBUTE of an element inside the same <select>.
func selectAttrBody(read, postRead string) string {
	return `<!doctype html><html><body><p>stock checker</p><script>` + read + postRead +
		`document.write('<select id="stockCheck"><option value="'+value+'">stock</option></select>');</script></body></html>`
}

func newSelectLab(t *testing.T) *httptest.Server {
	t.Helper()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Query().Get("shape") {
		case "query":
			fmt.Fprint(w, selectTextBody(selectReadQuery, ""))
		case "query-escaped":
			fmt.Fprint(w, selectTextBody(selectReadQuery, selectEscape))
		case "hash":
			fmt.Fprint(w, selectTextBody(selectReadHash, ""))
		case "hash-escaped":
			fmt.Fprint(w, selectTextBody(selectReadHash, selectEscape))
		case "attr":
			fmt.Fprint(w, selectAttrBody(selectReadQuery, ""))
		case "attr-escaped":
			fmt.Fprint(w, selectAttrBody(selectReadQuery, selectEscape))
		default:
			http.Error(w, "unknown shape", http.StatusBadRequest)
		}
	}))
	t.Cleanup(lab.Close)
	return lab
}

// TestDOMDocumentWriteInsideSelectIsAlreadyConfirmed asserts the fixture's exact
// bytes and then the real executor's verdicts against a real browser.
func TestDOMDocumentWriteInsideSelectIsAlreadyConfirmed(t *testing.T) {
	lab := newSelectLab(t)

	for _, tc := range []struct{ shape, want string }{
		{"query", selectTextBody(selectReadQuery, "")},
		{"hash", selectTextBody(selectReadHash, "")},
		{"attr", selectAttrBody(selectReadQuery, "")},
	} {
		resp, err := http.Get(lab.URL + "/?shape=" + tc.shape + "&storeId=hello")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != tc.want {
			t.Fatalf("served bytes for %s:\n got %q\nwant %q", tc.shape, body, tc.want)
		}
	}

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	for _, tc := range []struct {
		name          string
		shape, source string
		wantConfirmed bool
		// wantValue is a substring the CONFIRMED candidate must carry: the shape
		// that actually reached an executable position.
		wantValue string
	}{
		{
			name: "option text fed by location.search", shape: "query", source: "location.search",
			wantConfirmed: true, wantValue: "<script>",
		},
		{
			name: "option text fed by location.hash", shape: "hash", source: "location.hash",
			wantConfirmed: true, wantValue: "<img",
		},
		{
			name: "option attribute fed by location.search", shape: "attr", source: "location.search",
			wantConfirmed: true, wantValue: `"><img`,
		},
		{
			name: "escaped query value stays Rejected", shape: "query-escaped", source: "location.search",
		},
		{
			name: "escaped hash value stays Rejected", shape: "hash-escaped", source: "location.hash",
		},
		{
			name: "escaped attribute value stays Rejected", shape: "attr-escaped", source: "location.search",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			ep := domXSSLabEndpoint(t, env, lab.URL+"/?shape="+tc.shape+"&storeId=unused", "text/html")
			env.param(ep, "storeId", domain.LocationQuery, "unused")
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, tc.source)); err != nil {
				t.Fatalf("run DOM-XSS job: %v", err)
			}

			findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(findings) != 1 {
				t.Fatalf("want exactly one correlated finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			d := decodeFindingDetail(f.Detail)
			if len(d.Attempts) < 2 {
				t.Fatalf("want a reachability attempt plus shape attempts, got %d: %+v", len(d.Attempts), d.Attempts)
			}
			if d.Attempts[0].Verdict != domain.VerdictPending || len(d.Attempts[0].CandidateDedupKey) != 0 {
				t.Fatalf("first attempt must stay the reachability canary, got %+v", d.Attempts[0])
			}

			var confirmed []string
			for _, attempt := range d.Attempts {
				if attempt.Verdict == domain.VerdictConfirmed {
					confirmed = append(confirmed, attempt.CandidateValue)
					if !strings.Contains(attempt.Notes, "is not defined") {
						t.Fatalf("confirmation must carry the engine's marker execution signal, got %q", attempt.Notes)
					}
				}
			}
			if tc.wantConfirmed {
				if f.Verdict != domain.VerdictConfirmed || len(confirmed) != 1 {
					t.Fatalf("want exactly one Confirmed shape from a real browser execution, got verdict=%s confirmed=%v attempts=%+v",
						f.Verdict, confirmed, d.Attempts)
				}
				if !strings.Contains(confirmed[0], tc.wantValue) {
					t.Fatalf("confirmation must come from the expected shape %q, got %q", tc.wantValue, confirmed[0])
				}
			} else {
				if f.Verdict == domain.VerdictConfirmed || len(confirmed) != 0 {
					t.Fatalf("escaped control must never confirm: verdict=%s confirmed=%v", f.Verdict, confirmed)
				}
			}

			// Every shape that reaches the sink gets its own verification case;
			// none may be recorded as a failed probe.
			for _, c := range domXSSTestCases(t, env) {
				if c.Status == domain.TestCaseFailed {
					t.Fatalf("unexpected failed test case: %s (%s)", c.Note, c.Error)
				}
			}
		})
	}
}

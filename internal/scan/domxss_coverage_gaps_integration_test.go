//go:build browser_integration

package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

// domXSSLabEndpoint registers an endpoint with the observed content type the
// crawler/browser-network discovery would have stored for it.
func domXSSLabEndpoint(t *testing.T, env *scanEnv, rawURL, contentType string) *domain.Endpoint {
	t.Helper()
	ep := &domain.Endpoint{
		ID: domain.NewID(), ScanID: env.scanID, URL: rawURL, Method: domain.MethodGET,
		Source: domain.SourceCrawler, ContentType: contentType, CreatedAt: time.Now(),
	}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

func domXSSTestCases(t *testing.T, env *scanEnv) []*domain.TestCase {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed reproduces the
// PortSwigger "document.write sink using source location.search" shape: the
// value lands INSIDE a quoted attribute, so a standalone markup candidate
// cannot execute. Verification must try a deterministic attribute-breakout
// candidate as well, and a real marker execution must be observed — never a
// reflection, and never a page-authored console forgery.
func TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed(t *testing.T) {
	const trackerAttr = `<img src="/resources/images/tracker.gif?searchTerms=`

	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		shape := r.URL.Query().Get("shape")
		read := `const q=new URLSearchParams(location.search).get('q')||'';`
		switch shape {
		case "document_write":
			fmt.Fprint(w, `<!doctype html><body><p>tracker</p><script>`+read+
				`document.write('`+trackerAttr+`'+q+'">');</script>`)
		case "innerhtml_attribute":
			fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>`+read+
				`document.getElementById('sink').innerHTML='`+trackerAttr+`'+q+'">';</script>`)
		case "escaped":
			fmt.Fprint(w, `<!doctype html><body><script>`+read+
				`const v=q.replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;');`+
				`document.write('`+trackerAttr+`'+v+'">');</script>`)
		case "forged":
			// Escape the value so the real shape cannot execute, then print a
			// page-authored ReferenceError naming the marker. The forgery must
			// never be accepted as execution.
			fmt.Fprint(w, `<!doctype html><body><script>`+read+
				`const v=q.replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;').replaceAll('>','&gt;');`+
				`document.write('`+trackerAttr+`'+v+'">');`+
				`const m=q.match(/onerror="?([^">\s]+)/);if(m)console.error('ReferenceError: '+m[1]+' is not defined');</script>`)
		default:
			http.Error(w, "unknown shape", http.StatusBadRequest)
		}
	}))
	defer lab.Close()

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	for _, tc := range []struct {
		name, shape    string
		wantConfirmed  bool
		wantShapes     int
		wantBreakoutIn string
	}{
		{"document.write quoted attribute", "document_write", true, 2, `"><img`},
		{"innerHTML quoted attribute", "innerhtml_attribute", true, 2, `"><img`},
		{"escaped value stays Rejected", "escaped", false, 2, ""},
		{"forged console stays Rejected", "forged", false, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			ep := domXSSLabEndpoint(t, env, lab.URL+"/?shape="+tc.shape+"&q=unused", "text/html")
			env.param(ep, "q", domain.LocationQuery, "unused")
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "location.search")); err != nil {
				t.Fatalf("run DOM-XSS job: %v", err)
			}

			findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(findings) != 1 {
				t.Fatalf("want exactly one correlated finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			d := decodeFindingDetail(f.Detail)
			// One reachability (canary) attempt plus one attempt per candidate
			// shape: each distinct shape exactly once.
			if len(d.Attempts) != 1+tc.wantShapes {
				t.Fatalf("want 1 reachability + %d shape attempt(s), got %d: %+v", tc.wantShapes, len(d.Attempts), d.Attempts)
			}
			if d.Attempts[0].Verdict != domain.VerdictPending || len(d.Attempts[0].CandidateDedupKey) != 0 {
				t.Fatalf("first attempt must stay the reachability canary, got %+v", d.Attempts[0])
			}
			if tc.wantConfirmed {
				if f.Verdict != domain.VerdictConfirmed {
					t.Fatalf("attribute-context injection must confirm a genuine marker execution, got %s: %+v", f.Verdict, f.Summary)
				}
				last := d.Attempts[len(d.Attempts)-1]
				if last.Verdict != domain.VerdictConfirmed || !strings.Contains(last.CandidateValue, tc.wantBreakoutIn) {
					t.Fatalf("confirmation must come from the attribute-breakout shape, attempts=%+v", d.Attempts)
				}
			} else {
				if f.Verdict == domain.VerdictConfirmed {
					t.Fatalf("control must never confirm: %+v", f.Summary)
				}
				for _, attempt := range d.Attempts {
					if attempt.Verdict == domain.VerdictConfirmed {
						t.Fatalf("control attempt confirmed: %+v", attempt)
					}
				}
			}

			// The site must have been genuinely exercised: a real reachability
			// test case plus one verification case per shape.
			cases := domXSSTestCases(t, env)
			completed := 0
			for _, c := range cases {
				if c.Status == domain.TestCaseCompleted {
					completed++
				}
				if c.Status == domain.TestCaseFailed {
					t.Fatalf("unexpected failed test case: %s (%s)", c.Note, c.Error)
				}
			}
			if completed < 2 {
				t.Fatalf("want reachability plus verification test cases, got %d completed of %d", completed, len(cases))
			}
		})
	}
}

// TestDOMBodylessDocumentIsNotApplicable covers the postMessage probe on
// responses that cannot host a DOM: a non-HTML content type, and an HTML
// document that removed its own root. Both must be recorded as NOT APPLICABLE
// (skipped/informative), never as a Playwright error that retries, dies, and
// marks the scan's coverage incomplete. A genuinely attachable document whose
// attachment fails must still surface as an error.
func TestDOMBodylessDocumentIsNotApplicable(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>/x</loc></url></urlset>`)
		case "/removed-root":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><body><p>no root</p><script>document.removeChild(document.documentElement)</script></body></html>`)
		case "/broken-attach":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><html><body><p>root exists</p><script>document.body.appendChild=function(){throw new Error('attachment sentinel')}</script></body></html>`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer lab.Close()

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()

	type want struct {
		contentType   string
		path          string
		wantNilError  bool
		wantNoteParts []string
	}
	for _, tc := range []struct {
		name string
		want
	}{
		{
			name: "html document without an attachable root is not applicable",
			want: want{contentType: "text/html", path: "/removed-root", wantNilError: true,
				wantNoteParts: []string{"not applicable", "root"}},
		},
		{
			name: "attachment failure on a real document still errors",
			want: want{contentType: "text/html", path: "/broken-attach", wantNilError: false},
		},
		{
			name: "non-html content type is not applicable",
			want: want{contentType: "application/xml", path: "/sitemap.xml", wantNilError: true,
				wantNoteParts: []string{"application/xml", "not applicable"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScanEnv(t)
			ep := domXSSLabEndpoint(t, env, lab.URL+tc.path, tc.contentType)
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			// A body-less document previously left the postMessage Evaluate
			// pending forever; bound it so the outcome is an assertion, not a
			// hung test binary.
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "postMessage"))

			cases := domXSSTestCases(t, env)
			if len(cases) == 0 {
				t.Fatal("the probe must record an explicit test case outcome")
			}
			var failed, skipped []*domain.TestCase
			for _, c := range cases {
				switch c.Status {
				case domain.TestCaseFailed:
					failed = append(failed, c)
				case domain.TestCaseSkipped:
					skipped = append(skipped, c)
				}
			}
			if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
				t.Fatalf("no finding may be created for an unprobeable document: %+v", findings)
			}
			if tc.wantNilError {
				if err != nil {
					t.Fatalf("must be a clean not-applicable outcome, got error: %v", err)
				}
				if len(failed) != 0 {
					t.Fatalf("not-applicable must not record a failed/dead test case: %+v", failed[0])
				}
				if len(skipped) != len(cases) {
					t.Fatalf("every outcome must be an explicit skip, got %d skipped of %d", len(skipped), len(cases))
				}
				for _, c := range skipped {
					for _, part := range tc.wantNoteParts {
						if !strings.Contains(c.Note, part) {
							t.Fatalf("skip note must explain %q, got %q", part, c.Note)
						}
					}
				}
				return
			}
			if err == nil {
				t.Fatal("a genuine attachment failure on an attachable document must surface as an error")
			}
			if len(failed) == 0 {
				t.Fatalf("a genuine attachment failure must record a failed test case, cases=%+v", cases)
			}
			for _, c := range skipped {
				if strings.Contains(c.Note, "not applicable") {
					t.Fatalf("a genuine failure must never be downgraded to not-applicable: %q", c.Note)
				}
			}
		})
	}
}

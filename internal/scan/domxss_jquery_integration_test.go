//go:build browser_integration

package scan

// Real-Chromium coverage for the two jQuery DOM sinks (operator-authorized
// PortSwigger lab classes):
//
//   - jQuery.attr: a page writes a location-controlled value into an anchor's
//     href through jQuery. Only a javascript: URL executes, and only after the
//     link is activated, so the engine must perform its one deterministic
//     click on the element it located and then require the marker-specific
//     browser execution signal.
//   - jQuery.selector: a page concatenates a location-controlled value into a
//     jQuery selector/factory call. jQuery itself turns the value into markup,
//     which executes on parse; a hashchange-driven page needs one bounded hash
//     change after load before its own handler runs.
//
// The fixture is the vendored upstream jQuery 1.8.3 (see testdata/README.md):
// it is the version whose selector parser turns this lab shape into markup.
// Every control reaches the real hook and enters verification; a safe href, a
// safe/escaped selector value and a forged runtime console line must all stay
// Rejected.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func jqueryFixture(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/jquery-1.8.3.min.js")
	if err != nil {
		t.Fatalf("read vendored jQuery fixture: %v", err)
	}
	return body
}

// jqueryLab serves the fixture page plus the vendored jQuery on /jq.js.
func jqueryLab(t *testing.T, jq []byte, pageHTML string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jq.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(jq)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pageHTML)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type jqueryCase struct {
	name        string
	sink        detection.DOMXSSSink
	source      detection.DOMXSSSource
	urlSuffix   string
	queryParam  string
	page        string
	wantVerdict domain.Verdict
}

// jqueryWantValue is the single shape each new sink plans for a marker.
func jqueryWantValue(sink detection.DOMXSSSink, marker string) string {
	if sink == detection.DOMSinkJQueryAttr {
		return "javascript:" + marker
	}
	return "<img src=x onerror=" + marker + ">"
}

func runJQueryCases(t *testing.T, jq []byte, cases []jqueryCase) {
	t.Helper()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab := jqueryLab(t, jq, tc.page)
			env := newScanEnv(t)
			ep := env.endpoint(lab.URL+"/lab"+tc.urlSuffix, domain.MethodGET)
			if tc.queryParam != "" {
				env.param(ep, tc.queryParam, domain.LocationQuery, "unused")
			}
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, string(tc.source))); err != nil {
				t.Fatalf("dom-xss job: %v", err)
			}
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(fs) != 1 {
				t.Fatalf("want exactly one finding for the reachable %s site, got %d: %+v", tc.sink, len(fs), fs)
			}
			f := fs[0]
			if f.Verdict != tc.wantVerdict {
				t.Fatalf("%s verdict = %s, want %s; summary=%q", tc.name, f.Verdict, tc.wantVerdict, f.Summary)
			}
			if !strings.Contains(f.Title, string(tc.sink)) {
				t.Fatalf("finding title must name the sink %q: %q", tc.sink, f.Title)
			}
			d := decodeFindingDetail(f.Detail)
			if len(d.Candidates) != 1 {
				t.Fatalf("want one candidate shape, got %d: %+v", len(d.Candidates), d.Candidates)
			}
			cand := d.Candidates[0]
			wantValue := jqueryWantValue(tc.sink, marker)
			if string(cand.Context) != string(tc.sink) || cand.ContextSub != string(tc.source) || cand.Value != wantValue {
				t.Fatalf("candidate provenance/value wrong: %+v (want %s/%s %q)", cand, tc.sink, tc.source, wantValue)
			}
			if len(d.Attempts) != 2 {
				t.Fatalf("want reachability + verification attempts, got %d: %+v", len(d.Attempts), d.Attempts)
			}
			verifyAttempt := d.Attempts[1]
			if verifyAttempt.VerifyTestCaseID.Empty() {
				t.Fatal("verification attempt has no test case id")
			}
			if tc.wantVerdict == domain.VerdictConfirmed {
				if !strings.Contains(f.Summary, "is not defined") {
					t.Fatalf("confirmed finding must carry the marker runtime signal: %q", f.Summary)
				}
				if !strings.Contains(verifyAttempt.Notes, "activation") {
					t.Fatalf("verification notes must document the activation step: %q", verifyAttempt.Notes)
				}
				bodies := htmlSourceMatrixEvidence(t, env, f, verifyAttempt.VerifyTestCaseID)
				log := bodies[domain.EvidenceBrowserLog]
				if !strings.Contains(log, "is not defined") || !strings.Contains(log, string(tc.sink)) {
					t.Fatalf("browser-log evidence must retain the marker error and the sink report:\n%s", log)
				}
				if !strings.Contains(log, domXSSActivationEvidencePrefix) {
					t.Fatalf("browser-log evidence must record the activation step:\n%s", log)
				}
			}
			if tc.wantVerdict == domain.VerdictRejected {
				if !strings.Contains(verifyAttempt.Notes, "no execution signal") {
					t.Fatalf("a reflected-but-not-executed control must be Rejected for that reason: %q", verifyAttempt.Notes)
				}
			}
		})
	}
}

func TestDOMJQueryAnchorHrefSinkIsActivated(t *testing.T) {
	jq := jqueryFixture(t)
	base := func(safe, note, forged bool) string {
		return strings.NewReplacer(
			"__SAFE__", fmt.Sprintf("%t", safe),
			"__NOTE__", fmt.Sprintf("%t", note),
			"__FORGED__", fmt.Sprintf("%t", forged),
		).Replace(jqueryAttrPage)
	}
	runJQueryCases(t, jq, []jqueryCase{
		{
			name: "location_search_reaches_jQuery_attr_and_the_click_executes", sink: detection.DOMSinkJQueryAttr,
			source: detection.DOMSourceQuery, urlSuffix: "?returnUrl=unused", queryParam: "returnUrl",
			page: base(false, false, false), wantVerdict: domain.VerdictConfirmed,
		},
		{
			name: "safe_hash_href_stays_Rejected", sink: detection.DOMSinkJQueryAttr,
			source: detection.DOMSourceQuery, urlSuffix: "?returnUrl=unused", queryParam: "returnUrl",
			page: base(true, true, false), wantVerdict: domain.VerdictRejected,
		},
		{
			name: "forged_console_stays_Rejected", sink: detection.DOMSinkJQueryAttr,
			source: detection.DOMSourceQuery, urlSuffix: "?returnUrl=unused", queryParam: "returnUrl",
			page: base(true, true, true), wantVerdict: domain.VerdictRejected,
		},
	})
}

func TestDOMJQuerySelectorHashchangeSinkIsActivated(t *testing.T) {
	jq := jqueryFixture(t)
	base := func(safe, note, forged, wrapped bool) string {
		return strings.NewReplacer(
			"__SAFE__", fmt.Sprintf("%t", safe),
			"__NOTE__", fmt.Sprintf("%t", note),
			"__FORGED__", fmt.Sprintf("%t", forged),
			"__WRAPPED__", fmt.Sprintf("%t", wrapped),
		).Replace(jquerySelectorPage)
	}
	runJQueryCases(t, jq, []jqueryCase{
		{
			name: "hashchange_delivered_selector_markup_executes", sink: detection.DOMSinkJQuerySelector,
			source: detection.DOMSourceHash, page: base(false, false, false, false),
			wantVerdict: domain.VerdictConfirmed,
		},
		{
			// The canary itself is parsed as HTML here (the page wraps the
			// value in markup), so jQuery's own innerHTML assignment reports
			// before the factory call. The site must still be attributed to
			// the page-authored jQuery.selector call and keep its activation.
			name: "wrapped_markup_canary_keeps_the_jQuery_sink", sink: detection.DOMSinkJQuerySelector,
			source: detection.DOMSourceHash, page: base(false, false, false, true),
			wantVerdict: domain.VerdictConfirmed,
		},
		{
			name: "escaped_selector_value_stays_Rejected", sink: detection.DOMSinkJQuerySelector,
			source: detection.DOMSourceHash, page: base(true, true, false, false),
			wantVerdict: domain.VerdictRejected,
		},
		{
			name: "forged_console_stays_Rejected", sink: detection.DOMSinkJQuerySelector,
			source: detection.DOMSourceHash, page: base(true, true, true, false),
			wantVerdict: domain.VerdictRejected,
		},
	})
}

const jqueryAttrPage = `<!doctype html><html><head><meta charset="utf-8"></head><body>
<a id="backLink" href="/home">Back to list</a>
<div id="note"></div>
<script src="/jq.js"></script>
<script>
$(function () {
  var value = new URLSearchParams(window.location.search).get('returnUrl');
  if (value === null) return;
  var href = value;
  if (__SAFE__) href = '#' + encodeURIComponent(value);
  $('#backLink').attr('href', href);
  if (__NOTE__) document.getElementById('note').textContent = value;
  if (__FORGED__) console.error('ReferenceError: ' + value + ' is not defined');
});
</script></body></html>`

const jquerySelectorPage = `<!doctype html><html><head><meta charset="utf-8"></head><body>
<section class="blog-list"><h2>Hello world</h2></section>
<div id="note"></div>
<script src="/jq.js"></script>
<script>
$(window).on('hashchange', function () {
  var value = decodeURIComponent(window.location.hash.slice(1));
  var selectorValue = value;
  if (__SAFE__) selectorValue = value.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  if (__WRAPPED__) {
    $('<div class="wrap">' + selectorValue + '</div>');
  } else {
    $('section.blog-list h2:contains(' + selectorValue + ')');
  }
  if (__NOTE__) document.getElementById('note').textContent = value;
  if (__FORGED__) console.error('ReferenceError: ' + value + ' is not defined');
});
</script></body></html>`

// TestDOMJQuerySinkNativeContract proves the wrappers are observational: the
// jQuery API keeps its identity, prototype, chaining and getter behavior, and
// only marker-carrying selector/href calls produce a report.
func TestDOMJQuerySinkNativeContract(t *testing.T) {
	const marker = "JQUERYCONTRACTMARKER"
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := jqueryLab(t, jqueryFixture(t), `<!doctype html><html><body><div id="probe">x</div><script src="/jq.js"></script></body></html>`)
	bc, err := mgr.NewContext(context.Background(), browser.ContextOptions{AllowRequest: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	page, err := bc.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	if err := page.AddInitScript(context.Background(), domXSSHarnessScript(marker)); err != nil {
		t.Fatal(err)
	}
	if _, err := page.Navigate(context.Background(), lab.URL+"/static", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatal(err)
	}
	raw, err := page.Evaluate(context.Background(), strings.NewReplacer("__MARKER__", marker).Replace(jqueryContractScript))
	if err != nil {
		t.Fatalf("evaluate contract script: %v", err)
	}
	encoded, ok := raw.(string)
	if !ok {
		t.Fatalf("contract result type %T", raw)
	}
	var got struct {
		SameGlobal, Chainable, ConstructorOK bool
		Version, Getter, Tag, Href           string
		ByID, DocLen, HTMLLen                int
	}
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatalf("decode contract result %q: %v", encoded, err)
	}
	if !got.SameGlobal || !got.Chainable || !got.ConstructorOK || got.Version != "1.8.3" || got.ByID != 1 || got.DocLen != 1 || got.HTMLLen != 1 || got.Getter != "1" {
		t.Fatalf("jQuery native behavior changed by the harness: %+v", got)
	}
	if got.Tag != marker || got.Href != "https://example.invalid/"+marker {
		t.Fatalf("href write/tagging wrong: %+v", got)
	}
	// Only marker-carrying selector/href calls may produce a jQuery report.
	// jQuery's own innerHTML assignment during the markup parse is expected
	// evidence, and CDP may deliver it before or after the factory report, so
	// assert the jQuery set rather than an ordering.
	jqueryReports := map[detection.DOMXSSSink]int{}
	sawInnerHTML := false
	for _, m := range page.ConsoleMessages() {
		if !strings.HasPrefix(m.Text, domXSSConsolePrefix) {
			continue
		}
		var rep domXSSSinkReport
		if json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domXSSConsolePrefix)), &rep) != nil || !strings.Contains(rep.Value, marker) {
			continue
		}
		sink := detection.DOMXSSSink(rep.Sink)
		if sink == detection.DOMSinkInnerHTML {
			sawInnerHTML = true
			continue
		}
		jqueryReports[sink]++
	}
	if len(jqueryReports) != 2 || jqueryReports[detection.DOMSinkJQuerySelector] != 1 || jqueryReports[detection.DOMSinkJQueryAttr] != 1 {
		t.Fatalf("want exactly one selector and one href report, got %v", jqueryReports)
	}
	if !sawInnerHTML {
		t.Fatal("jQuery's own HTML parse must still be observed through innerHTML (control for the factory hook)")
	}
}

const jqueryContractScript = `(() => {
  const jq = $('#probe');
  const chained = jq.attr('data-a', '1');
  const out = {
    SameGlobal: window.$ === window.jQuery,
    Version: jQuery.fn.jquery,
    ByID: jq.length,
    DocLen: $(document).length,
    Chainable: chained === jq,
    Getter: jq.attr('data-a'),
    HTMLLen: $('<div>hi</div>').length,
    ConstructorOK: jq.constructor === jQuery
  };
  $('#probe').attr('title', '__MARKER__');
  $('<div>__MARKER__</div>');
  $('#probe').attr('href', 'https://example.invalid/__MARKER__');
  out.Tag = document.getElementById('probe').getAttribute('data-indago-xss-target');
  out.Href = document.getElementById('probe').getAttribute('href');
  return JSON.stringify(out);
})()`

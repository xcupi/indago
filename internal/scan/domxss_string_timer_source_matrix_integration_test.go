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

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

func TestDOMStringTimerSourceMatrix(t *testing.T) {
	type scenario struct{ sink, source, control string }
	var scenarios []scenario
	sources := []string{"location.hash", "location.search", "window.name", "postMessage", "document.referrer", "localStorage", "sessionStorage"}
	for _, sink := range []string{"setTimeout", "setInterval"} {
		for _, source := range sources {
			for _, control := range []string{"positive", "safe", "forged"} {
				scenarios = append(scenarios, scenario{sink, source, control})
			}
		}
		for _, control := range []string{"canceled", "csp", "callback", "reject-sender", "delayed"} {
			source := "location.hash"
			if control == "reject-sender" {
				source = "postMessage"
			}
			scenarios = append(scenarios, scenario{sink, source, control})
		}
	}
	if len(scenarios) != 52 {
		t.Fatalf("exact bounded matrix changed: %d", len(scenarios))
	}
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	for _, sc := range scenarios {
		t.Run(sc.sink+"/"+sc.source+"/"+sc.control, func(t *testing.T) {
			ctx := context.Background()
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path != "/case" {
					fmt.Fprint(w, "<!doctype html><body>neutral origin root</body>")
					return
				}
				if sc.control == "csp" {
					w.Header().Set("Content-Security-Policy", "script-src 'nonce-timer-matrix'")
				}
				fmt.Fprint(w, stringTimerMatrixPage(sc.sink, sc.source, sc.control))
			}))
			defer lab.Close()
			env := newScanEnv(t)
			endpointURL := lab.URL + "/case"
			selector := ""
			switch sc.source {
			case "location.search":
				endpointURL += "?timer_query=unused"
				selector = "timer_query"
			case "localStorage":
				selector = "timer_profile_note"
			case "sessionStorage":
				selector = "timer_tab_note"
			}
			ep := env.endpoint(endpointURL, domain.MethodGET)
			if sc.source == "location.search" {
				env.param(ep, selector, domain.LocationQuery, "unused")
			}
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, sc.source)); err != nil {
				t.Fatal(err)
			}
			cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range cases {
				if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
					t.Fatalf("required case skipped/failed: %+v", tc)
				}
			}
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			if sc.control == "callback" || sc.control == "reject-sender" {
				if len(fs) != 0 || len(cases) != 1 || !strings.Contains(cases[0].Note, "negative result") {
					t.Fatalf("non-string/unreachable control: findings=%+v cases=%+v", fs, cases)
				}
				if !strings.Contains(cases[0].Note, "no implemented DOM-XSS sink reachable") {
					t.Fatalf("negative diagnostic must cover all implemented sink categories: %q", cases[0].Note)
				}
				bc, err := mgr.NewContext(ctx, browser.ContextOptions{AllowRequest: func(u string) bool { return ex.scope.Permits(u).Allowed }})
				if err != nil {
					t.Fatal(err)
				}
				defer bc.Close()
				obs, _, err := ex.navigateSource(ctx, bc, detection.DOMXSSSource(sc.source), ep, "", marker, marker)
				if err != nil {
					t.Fatal(err)
				}
				html := obs.HTML
				if len(parseDOMXSSReachability(domXSSHarnessMessages(obs.Runtime), marker)) != 0 {
					t.Fatal("non-string/rejected sender produced reachability")
				}
				if _, _, matched := verification.MatchRuntimeExecution(marker, obs.Runtime); matched {
					t.Fatal("negative executed marker")
				}
				if sc.control == "callback" && !strings.Contains(html, `data-callback="true"`) {
					t.Fatal("native callback never executed")
				}
				if sc.control == "reject-sender" && (!strings.Contains(html, `data-sender-origin="null"`) || !strings.Contains(html, `data-source-is-window="false"`) || !strings.Contains(html, `data-rejected="true"`)) {
					t.Fatalf("real opaque sender did not reach rejecting handler: %s", html)
				}
				return
			}
			if len(fs) != 1 {
				t.Fatalf("must actually reach selected sink and verify (not a skipped selector): %+v", fs)
			}
			f := fs[0]
			d := decodeFindingDetail(f.Detail)
			parameter := selector
			if parameter == "" {
				parameter = sc.source
			}
			if len(d.Candidates) != 1 || d.Candidates[0].Context != detection.Context(sc.sink) || d.Candidates[0].ContextSub != sc.source || d.Candidates[0].Parameter != selector || d.ParameterName != parameter || d.Candidates[0].Value != marker {
				t.Fatalf("source/sink/selector/bare payload mismatch: %+v", d)
			}
			if len(d.Attempts) != 2 || d.Attempts[1].Verdict == domain.VerdictPending || len(d.TestCaseIDs) != 2 || d.Attempts[1].VerifyTestCaseID.Empty() {
				t.Fatalf("payload verification not finished: %+v", d)
			}
			wantCases := 2
			if strings.HasSuffix(sc.source, "Storage") {
				wantCases++
				if !strings.Contains(f.Summary, "attacker-relevant ability to write or poison") || !strings.Contains(d.Candidates[0].Rationale, "manual exploitability review") {
					t.Fatal("storage attacker-control caveat missing")
				}
			}
			if len(cases) != wantCases {
				t.Fatalf("test cases=%d want %d", len(cases), wantCases)
			}
			want := domain.VerdictRejected
			if sc.control == "positive" {
				want = domain.VerdictConfirmed
			}
			if f.Verdict != want {
				t.Fatalf("expected %s, actual %s: %+v", want, f.Verdict, d)
			}
			bodies := htmlSourceMatrixEvidence(t, env, f, d.Attempts[1].VerifyTestCaseID)
			log := bodies[domain.EvidenceBrowserLog]
			html := bodies[domain.EvidenceDOM]
			if !strings.Contains(html, marker) {
				t.Fatal("actual delivered payload missing from rendered DOM")
			}
			if sc.control == "positive" && (!strings.Contains(log, "playwright: "+marker+" is not defined") || !strings.Contains(d.Attempts[1].Notes, marker+" is not defined")) {
				t.Fatalf("exact page-error proof absent: %s", log)
			}
			if sc.control != "positive" && strings.Contains(log, "playwright: "+marker+" is not defined") {
				t.Fatalf("negative unexpectedly evaluated marker: %s", log)
			}
			if sc.control == "positive" && !strings.Contains(log, `"sink":"`+sc.sink+`","value":"`+marker+`"`) {
				t.Fatal("exact native timer sink/payload report missing from evidence")
			}
			if sc.control == "forged" && !strings.Contains(log, "ReferenceError: "+marker+" is not defined") {
				t.Fatal("exact forged runtime console text absent")
			}
			if sc.source == "postMessage" && (!strings.Contains(html, `data-sender-origin="null"`) || !strings.Contains(html, `data-source-is-window="false"`)) {
				t.Fatal("opaque non-self sender proof absent")
			}
			if sc.control == "csp" && !strings.Contains(log, "Content Security Policy") {
				t.Fatalf("native CSP string-evaluation refusal absent: %s", log)
			}
		})
	}
}

// A realistic application transformation extracts and decodes just the URL path
// component of the absolute referrer. Executing the whole URL is not JavaScript
// marker execution. Storage keys come from actual native getItem calls.
func stringTimerMatrixPage(sink, source, control string) string {
	action := `const id=window[` + goQuoteJS(sink) + `](value,0);`
	switch control {
	case "safe", "forged":
		action = `value=JSON.stringify(raw);` + action
	case "canceled":
		action = `const id=window[` + goQuoteJS(sink) + `](value,0);clearTimeout(id);clearInterval(id);`
	case "delayed":
		action = `window[` + goQuoteJS(sink) + `](value,60000);`
	case "callback":
		action = `window[` + goQuoteJS(sink) + `](function(){sink.dataset.callback='true';},0);`
	}
	if control == "forged" {
		action += `console.error('ReferenceError: '+raw+' is not defined');`
	}
	read := map[string]string{
		"location.hash":     `decodeURIComponent(location.hash.slice(1))`,
		"location.search":   `new URLSearchParams(location.search).get('timer_query')||''`,
		"window.name":       `window.name`,
		"document.referrer": `document.referrer?decodeURIComponent(new URL(document.referrer).pathname.slice(1)):''`,
		"localStorage":      `localStorage.getItem('timer_profile_note')||''`,
		"sessionStorage":    `sessionStorage.getItem('timer_tab_note')||''`,
	}[source]
	code := `const raw=` + read + `;sink.textContent=raw;let value=raw;` + action
	if source == "postMessage" {
		guard := ""
		if control == "reject-sender" {
			guard = `if(e.origin!==location.origin||e.source!==window){sink.dataset.rejected='true';return;}`
		}
		code = `window.addEventListener('message',e=>{sink.dataset.senderOrigin=e.origin;sink.dataset.sourceIsWindow=String(e.source===window);` + guard + `const raw=e.data;sink.textContent=raw;let value=raw;` + action + `});`
	}
	return `<!doctype html><body><div id="sink"></div><script nonce="timer-matrix">const sink=document.getElementById('sink');` + code + `</script></body>`
}

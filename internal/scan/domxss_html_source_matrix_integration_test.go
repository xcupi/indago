//go:build browser_integration

package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
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

// This is coverage of existing behavior, not a new source or sink category.
// Every pair has two reachable negatives: both must enter payload verification.
func TestDOMHTMLSourceMatrix(t *testing.T) {
	type scenario struct{ sink, source, control string }
	var scenarios []scenario
	// Keep the required inventory explicit rather than silently growing with a
	// production enum: this bounded slice is exactly two sinks by seven sources.
	sources := []string{"location.hash", "location.search", "window.name", "postMessage", "document.referrer", "localStorage", "sessionStorage"}
	for _, sink := range []string{"insertAdjacentHTML", "Range.createContextualFragment"} {
		for _, source := range sources {
			for _, control := range []string{"positive", "escaped", "forged"} {
				scenarios = append(scenarios, scenario{sink, source, control})
			}
		}
		scenarios = append(scenarios, scenario{sink, "postMessage", "reject-sender"})
	}
	scenarios = append(scenarios,
		scenario{"Range.createContextualFragment", "location.hash", "detached"},
		scenario{"Range.createContextualFragment", "location.hash", "innocent-sibling"})
	if len(scenarios) != 46 || len(scenarios) > 65 {
		t.Fatalf("bounded inventory changed: %d scenarios", len(scenarios))
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
				fmt.Fprint(w, htmlSourceMatrixPage(sc.sink, sc.source, sc.control))
			}))
			defer lab.Close()
			env := newScanEnv(t)
			endpointURL := lab.URL + "/case"
			selector := ""
			switch sc.source {
			case "location.search":
				endpointURL += "?matrix_query=unused"
				selector = "matrix_query"
			case "localStorage":
				selector = "matrix_profile_note"
			case "sessionStorage":
				selector = "matrix_tab_note"
			}
			ep := env.endpoint(endpointURL, domain.MethodGET)
			if sc.source == "location.search" {
				env.param(ep, selector, domain.LocationQuery, "unused")
			}
			ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
			job := sourceSelectionJob(t, env.scanID, ep, sc.source)
			if err := ex.Handle(ctx, job); err != nil {
				t.Fatal(err)
			}
			cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range cases {
				if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
					t.Fatalf("required scenario must run, not skip/fail: %+v", tc)
				}
			}
			fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			if sc.control == "reject-sender" {
				if len(fs) != 0 || len(cases) != 1 || !strings.Contains(cases[0].Note, "negative result") {
					t.Fatalf("sender rejection must be a real reachability negative: findings=%+v cases=%+v", fs, cases)
				}
				// Independently deliver the real payload through the same opaque
				// sender. A missing event/listener cannot masquerade as rejection.
				bc, err := mgr.NewContext(ctx, browser.ContextOptions{AllowRequest: func(u string) bool { return ex.scope.Permits(u).Allowed }})
				if err != nil {
					t.Fatal(err)
				}
				defer bc.Close()
				cand, _ := detection.DOMXSSPayloadFor(detection.DOMSourcePostMessage, detection.DOMXSSSink(sc.sink), marker)
				console, pageErrors, html, _, _, err := ex.navigateSource(ctx, bc, detection.DOMSourcePostMessage, ep, "", marker, cand.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(html, `data-sender-origin="null"`) || !strings.Contains(html, `data-source-is-window="false"`) || !strings.Contains(html, `data-rejected="true"`) {
					t.Fatalf("opaque non-self sender did not actually reach rejecting handler: %s", html)
				}
				if len(parseDOMXSSReachability(console, marker)) != 0 {
					t.Fatal("rejected sender reached sink")
				}
				if _, _, matched := verification.MatchExecutionSignal(marker, pageErrors, nil); matched {
					t.Fatal("rejected sender executed marker")
				}
				return
			}
			if len(fs) != 1 {
				t.Fatalf("every positive/escaped/forged/fragment control must reach verification; findings=%+v", fs)
			}
			f := fs[0]
			d := decodeFindingDetail(f.Detail)
			parameter := selector
			if parameter == "" {
				parameter = sc.source
			}
			if len(d.Candidates) != 1 || string(d.Candidates[0].Context) != sc.sink || d.Candidates[0].ContextSub != sc.source || d.Candidates[0].Parameter != selector || d.ParameterName != parameter {
				t.Fatalf("wrong source/sink/selector attribution: %+v", d)
			}
			if len(d.Attempts) != 2 || d.Attempts[1].Verdict == domain.VerdictPending || len(d.TestCaseIDs) != 2 || d.Attempts[1].VerifyTestCaseID.Empty() {
				t.Fatalf("control did not complete payload verification: %+v", d)
			}
			wantCases := 2
			if strings.HasSuffix(sc.source, "Storage") {
				wantCases++ // observation-only key discovery is a separate case
				if !strings.Contains(f.Summary, "attacker-relevant ability to write or poison") || !strings.Contains(d.Candidates[0].Rationale, "manual exploitability review") {
					t.Fatal("storage attacker-control caveat lost")
				}
			}
			if len(cases) != wantCases {
				t.Fatalf("test cases=%d, want %d", len(cases), wantCases)
			}
			if sc.control == "positive" {
				if f.Verdict != domain.VerdictConfirmed || !strings.Contains(d.Attempts[1].Notes, marker+" is not defined") {
					t.Fatalf("expected one Confirmed with actual marker error: %+v", f)
				}
			} else if f.Verdict == domain.VerdictConfirmed {
				t.Fatalf("control falsely Confirmed: %+v", f)
			}
			if (sc.control == "escaped" || sc.control == "forged") && f.Verdict != domain.VerdictRejected {
				t.Fatalf("escaped marker must be re-observed and rejected, not missing: %+v", f)
			}
			bodies := htmlSourceMatrixEvidence(t, env, f, d.Attempts[1].VerifyTestCaseID)
			log := bodies[domain.EvidenceBrowserLog]
			html := bodies[domain.EvidenceDOM]
			if sc.control == "positive" {
				if !strings.Contains(log, "playwright: "+marker+" is not defined") || !strings.Contains(html, `onerror="`+marker+`"`) {
					t.Fatalf("actual page error/marker handler absent: log=%s DOM=%s", log, html)
				}
				if sc.sink == "Range.createContextualFragment" {
					wantValue := d.Candidates[0].Value
					if sc.source == "document.referrer" {
						wantValue = "https://indago-domxss-probe.invalid/" + wantValue
					}
					connected := false
					for _, line := range strings.Split(log, "\n") {
						if !strings.HasPrefix(line, domXSSConsolePrefix) {
							continue
						}
						var report domXSSSinkReport
						if err := json.Unmarshal([]byte(strings.TrimPrefix(line, domXSSConsolePrefix)), &report); err != nil {
							t.Fatalf("invalid sink report: %v", err)
						}
						connected = connected || report.Connected && report.Sink == sc.sink && report.Value == wantValue
					}
					if !connected {
						t.Fatal("exact marker/sink/value connection report absent")
					}
				}
			}
			if sc.source == "postMessage" && (!strings.Contains(html, `data-sender-origin="null"`) || !strings.Contains(html, `data-source-is-window="false"`)) {
				t.Fatal("evidence must retain opaque, non-self sender semantics")
			}
			if sc.control == "forged" {
				if !strings.Contains(log, "ReferenceError: "+marker+" is not defined") || strings.Contains(log, "playwright: "+marker+" is not defined") {
					t.Fatalf("forged-console control must log exact error text without a page error: %s", log)
				}
			}
			if sc.control == "detached" || sc.control == "innocent-sibling" {
				if strings.Contains(log, `"connected":true`) || !strings.Contains(f.Summary, "target insertion of the parsed fragment was not observed") {
					t.Fatal("fragment control lost insertion guard")
				}
				if sc.control == "innocent-sibling" && !strings.Contains(html, `id="sink">safe-prefix</div>`) {
					t.Fatal("innocent sibling was not actually inserted")
				}
			}
		})
	}
}

// The fixture reads each real source; it never evals marker text or self-posts.
func htmlSourceMatrixPage(sink, source, control string) string {
	action := `sink.insertAdjacentHTML('beforeend',value);`
	if sink == "Range.createContextualFragment" {
		action = `const range=document.createRange();range.selectNodeContents(sink);const fragment=range.createContextualFragment(value);sink.appendChild(fragment);`
		if control == "detached" {
			action = `const range=document.createRange();range.selectNodeContents(sink);range.createContextualFragment(value);`
		}
		if control == "innocent-sibling" {
			action = `const range=document.createRange();range.selectNodeContents(sink);const fragment=range.createContextualFragment('safe-prefix'+value);sink.appendChild(fragment.firstChild);`
		}
	}
	if control == "escaped" || control == "forged" {
		action = `value=value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');` + action
	}
	if control == "forged" {
		action += `const match=raw.match(/onerror=([^>]+)/);if(match)console.error('ReferenceError: '+match[1]+' is not defined');`
	}
	read := map[string]string{
		"location.hash":     `decodeURIComponent(location.hash.slice(1))`,
		"location.search":   `new URLSearchParams(location.search).get('matrix_query')||''`,
		"window.name":       `window.name`,
		"document.referrer": `decodeURIComponent(document.referrer)`,
		"localStorage":      `localStorage.getItem('matrix_profile_note')||''`,
		"sessionStorage":    `sessionStorage.getItem('matrix_tab_note')||''`,
	}[source]
	code := `const raw=` + read + `;let value=raw;` + action
	if source == "postMessage" {
		guard := ""
		if control == "reject-sender" {
			guard = `if(e.origin!==location.origin||e.source!==window){sink.dataset.rejected='true';return;}`
		}
		code = `window.addEventListener('message',e=>{sink.dataset.senderOrigin=e.origin;sink.dataset.sourceIsWindow=String(e.source===window);` + guard + `const raw=e.data;let value=raw;` + action + `});`
	}
	return `<!doctype html><body><div id="sink"></div><script>const sink=document.getElementById('sink');` + code + `</script></body>`
}

func htmlSourceMatrixEvidence(t *testing.T, env *scanEnv, f *domain.Finding, verifyTestCaseID domain.ID) map[domain.EvidenceKind]string {
	t.Helper()
	out := make(map[domain.EvidenceKind]string)
	for _, id := range f.EvidenceIDs {
		ev, err := env.st.Evidence().Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if ev.ScanID != env.scanID || ev.BlobPath == "" || verifyTestCaseID.Empty() || !strings.Contains(ev.Note, fmt.Sprintf("test_case=%s", verifyTestCaseID)) || ev.MediaType == "" {
			t.Fatalf("missing evidence attribution/metadata: %+v", ev)
		}
		r, err := env.ev.Open(ev.BlobPath)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 || int64(len(body)) != ev.Size || fmt.Sprintf("%x", sha256.Sum256(body)) != ev.SHA256 {
			t.Fatalf("evidence size/hash mismatch: %+v", ev)
		}
		out[ev.Kind] = string(body)
	}
	for _, kind := range []domain.EvidenceKind{domain.EvidenceScreenshot, domain.EvidenceDOM} {
		if out[kind] == "" {
			t.Fatalf("missing %s evidence", kind)
		}
	}
	if f.Verdict == domain.VerdictConfirmed && out[domain.EvidenceBrowserLog] == "" {
		t.Fatal("missing positive browser-log evidence")
	}
	return out
}

//go:build browser_integration

package scan

// Regression coverage for the DOM-XSS harness's bounded value report.
//
// The harness used to emit `v.slice(0, 500)` after checking the FULL value for
// the marker. A supported location.hash -> innerHTML sink with a harmless
// prefix longer than 500 code units therefore lost the marker before
// parseDOMXSSReachability could see it: a fixture that genuinely executes
// natively was recorded as a successful negative and no finding was created.
//
// These are real-browser tests. Every positive case also proves the fixture
// executes the benign marker natively WITHOUT the scanner harness, so a green
// result cannot come from a reachability report alone. The emitted value must
// stay bounded at 500 JavaScript UTF-16 code units and keep the real marker.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

type markerWindowCase struct {
	name      string
	padExpr   string // app-controlled padding only, never part of the injected value
	suffix    int    // app-controlled trailing characters
	mode      string // insert | absent | escaped | forged
	confirmed bool   // expected confirmed finding
	finding   bool   // expected finding row (confirmed or rejected)
	probeErr  bool   // expected Handle error (forged harness-shaped console output)
}

func markerWindowPage(mode, padExpr string, suffix int) string {
	action := `sink.innerHTML=pad+raw+tail;`
	switch mode {
	case "absent":
		action = `sink.innerHTML=pad+'no marker is present here'+tail;`
	case "escaped":
		action = `const value=raw.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');sink.innerHTML=pad+value+tail;`
	case "forged":
		action = `console.log(` + goQuoteJS(domXSSConsolePrefix) + `+JSON.stringify({sink:'innerHTML',value:pad+raw+tail}));`
	}
	return `<!doctype html><body><div id="sink"></div><script>` +
		`const sink=document.getElementById('sink');` +
		`const raw=decodeURIComponent(location.hash.slice(1));` +
		`const pad=` + padExpr + `;` +
		fmt.Sprintf(`const tail='S'.repeat(%d);`, suffix) +
		action + `</script></body>`
}

// assertMarkerWindowNativeExecution proves the fixture really executes the
// benign marker in a plain browser context, with no scanner harness installed.
// payload is the sink-appropriate benign marker value: markup for HTML sinks,
// the bare marker for a primitive-string timer. A zero-delay timer may fire
// after load, so the marker-specific signal is polled for a bounded time
// (context-cancellable). Nothing is forced, shortened or simulated.
func assertMarkerWindowNativeExecution(t *testing.T, mgr *browser.Manager, scope domain.Scope, target, payload, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bc, err := mgr.NewContext(ctx, browser.ContextOptions{AllowRequest: func(raw string) bool {
		return scope.Permits(raw).Allowed
	}})
	if err != nil {
		t.Fatalf("open native control context: %v", err)
	}
	defer bc.Close()
	page, err := bc.NewPage(ctx)
	if err != nil {
		t.Fatalf("open native control page: %v", err)
	}
	defer page.Close()
	if _, err := page.Navigate(ctx, target+"#"+url.PathEscape(payload), browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("native control navigation: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, detail, executed := verification.MatchExecutionSignal(marker, page.PageErrors(), nil); executed {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("fixture does not execute the marker natively within the bounded wait (control invalid): %s", detail)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("native control wait cancelled: %v", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func TestDOMXSSMarkerWindowRetention(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	ctx := context.Background()

	cases := []markerWindowCase{
		{name: "zero-prefix", padExpr: "'A'.repeat(0)", mode: "insert", confirmed: true, finding: true},
		{name: "short-prefix", padExpr: "'A'.repeat(12)", mode: "insert", confirmed: true, finding: true},
		// The canary carries a 20-byte "indago-domxss-canary-" prefix, so a
		// 470-character app prefix puts the marker across the old 500 cap.
		{name: "marker-crosses-old-500-boundary", padExpr: "'A'.repeat(470)", mode: "insert", confirmed: true, finding: true},
		{name: "long-prefix-600", padExpr: "'A'.repeat(600)", mode: "insert", confirmed: true, finding: true},
		{name: "long-prefix-and-suffix", padExpr: "'A'.repeat(640)", mode: "insert", suffix: 900, confirmed: true, finding: true},
		{name: "very-long-prefix-and-suffix", padExpr: "'A'.repeat(8192)", mode: "insert", suffix: 4096, confirmed: true, finding: true},
		// 300 astral code points are 600 UTF-16 code units: the excerpt must not
		// start in the middle of a surrogate pair nor lose the marker.
		{name: "surrogate-prefix", padExpr: "'😀'.repeat(300)", mode: "insert", suffix: 300, confirmed: true, finding: true},
		{name: "marker-absent", padExpr: "'A'.repeat(600)", mode: "absent"},
		{name: "escaped-long-prefix", padExpr: "'A'.repeat(600)", mode: "escaped", finding: true},
		{name: "forged-console-long-prefix", padExpr: "'A'.repeat(600)", mode: "forged", probeErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, markerWindowPage(tc.mode, tc.padExpr, tc.suffix))
			}))
			defer lab.Close()

			env := newScanEnv(t)
			target := lab.URL + "/case"
			ep := env.endpoint(target, domain.MethodGET)
			scope := sourceSelectionScope(t, lab.URL)
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			if tc.confirmed {
				cand, ok := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
				if !ok {
					t.Fatal("production planner produced no benign candidate for the native control")
				}
				assertMarkerWindowNativeExecution(t, mgr, scope, target, cand.Value, marker)
			}

			exec := newDOMXSSExecutor(env.st, mgr, env.ev, scope, execLog(), &sync.Mutex{})
			err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceHash)))
			cases, listErr := env.st.TestCases().ListByScan(ctx, env.scanID)
			if listErr != nil {
				t.Fatal(listErr)
			}
			findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)

			if tc.probeErr {
				if err == nil {
					t.Fatal("forged harness-shaped console output must not be treated as a clean negative")
				}
				if len(findings) != 0 {
					t.Fatalf("forged console output created %d finding(s)", len(findings))
				}
				if len(cases) != 1 || cases[0].Status != domain.TestCaseFailed ||
					!strings.Contains(cases[0].Error, "not attributable to the installed harness") {
					t.Fatalf("forged report must surface as an untested probe error, cases=%+v", cases)
				}
				return
			}
			if err != nil {
				t.Fatalf("DOM-XSS probe error: %v", err)
			}
			if !tc.finding {
				if len(findings) != 0 {
					t.Fatalf("negative control produced %d finding(s): %+v", len(findings), findings)
				}
				if len(cases) != 1 || !strings.Contains(cases[0].Note, "negative result") {
					t.Fatalf("marker-absent control must be a real reachability negative, cases=%+v", cases)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("supported source/sink with %s must produce one finding (native execution was proven), findings=%+v", tc.name, findings)
			}
			f := findings[0]
			d := decodeFindingDetail(f.Detail)
			if len(d.Candidates) == 0 || len(d.Candidates) > 2 {
				t.Fatalf("want the bounded candidate shapes (markup, then attribute breakout at most): %+v", d)
			}
			for _, cand := range d.Candidates {
				if string(cand.Context) != string(detection.DOMSinkInnerHTML) ||
					cand.ContextSub != string(detection.DOMSourceHash) {
					t.Fatalf("wrong source/sink attribution: %+v", d)
				}
			}
			// One reachability attempt plus one verification attempt per tried
			// shape; the last attempt is the one that produced the final verdict.
			last := d.Attempts[len(d.Attempts)-1]
			if len(d.Attempts) != 1+len(d.Candidates) || last.VerifyTestCaseID.Empty() {
				t.Fatalf("payload verification did not complete: %+v", d)
			}
			if tc.confirmed {
				if f.Verdict != domain.VerdictConfirmed {
					t.Fatalf("verdict = %s, want confirmed (long harmless prefix must not hide native execution): %+v", f.Verdict, f)
				}
				if !strings.Contains(last.Notes, marker+" is not defined") {
					t.Fatalf("confirmed attempt lacks the marker-specific runtime signal: %q", last.Notes)
				}
				if len(f.EvidenceIDs) < 3 {
					t.Fatalf("missing screenshot/DOM/browser-log evidence: %+v", f.EvidenceIDs)
				}
			} else if f.Verdict == domain.VerdictConfirmed {
				t.Fatalf("escaped control was falsely confirmed: %+v", f)
			} else if f.Verdict != domain.VerdictRejected {
				t.Fatalf("escaped control verdict = %s, want rejected after payload verification: %+v", f.Verdict, f)
			}
		})
	}
}

// TestDOMXSSMarkerWindowExcerptNatives proves the bounded excerpt does not
// depend on page-mutable globals. The page reads the hash normally, THEN
// replaces a native the excerpt needs, then feeds raw + a 600-character
// harmless suffix to innerHTML. On the v1 candidate Math.floor -> NaN emptied
// the excerpt and a throwing String.prototype.charCodeAt made report() drop
// the report, so a natively executing sink looked unreachable. The slice case
// is a control: v1 already captured the native slice before page scripts.
func TestDOMXSSMarkerWindowExcerptNatives(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	ctx := context.Background()

	cases := []struct {
		name     string
		override string
	}{
		{"math-floor-override", `Math.floor = function () { return NaN; };`},
		{"string-charcodeat-override", `String.prototype.charCodeAt = function () { throw new Error('page override'); };`},
		{"string-slice-override", `String.prototype.slice = function () { return ''; };`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, `<!doctype html><body><div id="sink"></div><script>`+
					`const raw=decodeURIComponent(location.hash.slice(1));`+
					tc.override+
					`document.getElementById('sink').innerHTML=raw+'A'.repeat(600);`+
					`</script></body>`)
			}))
			defer lab.Close()

			env := newScanEnv(t)
			target := lab.URL + "/case"
			ep := env.endpoint(target, domain.MethodGET)
			scope := sourceSelectionScope(t, lab.URL)
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			cand, ok := detection.DOMXSSPayloadFor(detection.DOMSourceHash, detection.DOMSinkInnerHTML, marker)
			if !ok {
				t.Fatal("production planner produced no benign candidate for the native control")
			}
			assertMarkerWindowNativeExecution(t, mgr, scope, target, cand.Value, marker)

			exec := newDOMXSSExecutor(env.st, mgr, env.ev, scope, execLog(), &sync.Mutex{})
			if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceHash))); err != nil {
				t.Fatalf("DOM-XSS probe error: %v", err)
			}
			findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
				t.Fatalf("page replacement of an excerpt dependency must not hide native execution (%s), findings=%+v", tc.name, findings)
			}
			d := decodeFindingDetail(findings[0].Detail)
			if len(d.Attempts) != 2 || !strings.Contains(d.Attempts[1].Notes, marker+" is not defined") {
				t.Fatalf("confirmation lost the marker-specific runtime signal: %+v", d)
			}
			if len(findings[0].EvidenceIDs) < 3 {
				t.Fatalf("missing screenshot/DOM/browser-log evidence: %+v", findings[0].EvidenceIDs)
			}
		})
	}
}

func TestDOMXSSMarkerWindowSinkPaths(t *testing.T) {
	cases := []struct {
		name     string
		page     string
		sink     detection.DOMXSSSink
		logWant  []string
		checkLog bool
	}{
		{
			name: "range-connected-long-prefix",
			page: `<!doctype html><body><div id="sink"></div><script>` +
				`const sink=document.getElementById('sink');` +
				`const value=decodeURIComponent(location.hash.slice(1));` +
				`const range=document.createRange();range.selectNodeContents(sink);` +
				`const fragment=range.createContextualFragment('A'.repeat(600)+value);` +
				`sink.appendChild(fragment);</script></body>`,
			sink:     detection.DOMSinkCreateContextualFragment,
			logWant:  []string{`"connected":true`, string(detection.DOMSinkCreateContextualFragment)},
			checkLog: true,
		},
		{
			name: "settimeout-comment-prefix",
			page: `<!doctype html><body><div id="sink"></div><script>` +
				`const value=decodeURIComponent(location.hash.slice(1));` +
				`window.setTimeout('/*' + 'A'.repeat(600) + '*/' + value, 0);</script></body>`,
			sink:     detection.DOMSinkSetTimeout,
			checkLog: true,
		},
	}

	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, tc.page)
			}))
			defer lab.Close()

			env := newScanEnv(t)
			target := lab.URL + "/case"
			ep := env.endpoint(target, domain.MethodGET)
			scope := sourceSelectionScope(t, lab.URL)
			marker := detection.NewProbe(env.scanID, ep.ID).Token
			cand, ok := detection.DOMXSSPayloadFor(detection.DOMSourceHash, tc.sink, marker)
			if !ok {
				t.Fatal("production planner produced no benign candidate for the native control")
			}
			assertMarkerWindowNativeExecution(t, mgr, scope, target, cand.Value, marker)

			exec := newDOMXSSExecutor(env.st, mgr, env.ev, scope, execLog(), &sync.Mutex{})
			if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceHash))); err != nil {
				t.Fatalf("DOM-XSS probe error: %v", err)
			}
			findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
			if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
				t.Fatalf("%s with a 600-character harmless prefix must confirm, findings=%+v", tc.sink, findings)
			}
			d := decodeFindingDetail(findings[0].Detail)
			if len(d.Candidates) != 1 || string(d.Candidates[0].Context) != string(tc.sink) {
				t.Fatalf("wrong sink attribution: %+v", d)
			}
			if tc.checkLog {
				logs := markerWindowBrowserLog(t, env, findings[0])
				for _, want := range tc.logWant {
					if !strings.Contains(logs, want) {
						t.Fatalf("browser log lacks %q: %s", want, logs)
					}
				}
				if !strings.Contains(logs, marker) {
					t.Fatalf("browser log lost the real marker: %s", logs)
				}
			}
		})
	}
}

// markerWindowBrowserLog returns the persisted browser-log evidence for the
// finding's verification attempt.
func markerWindowBrowserLog(t *testing.T, env *scanEnv, finding *domain.Finding) string {
	t.Helper()
	ctx := context.Background()
	for _, id := range finding.EvidenceIDs {
		ev, err := env.st.Evidence().Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind != domain.EvidenceBrowserLog {
			continue
		}
		reader, err := env.ev.Open(ev.BlobPath)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	t.Fatal("missing browser-log evidence")
	return ""
}

// TestDOMXSSHarnessMarkerSnippetBounded exercises the harness report contract
// directly: at most 500 JavaScript UTF-16 code units, marker retained, and no
// lone surrogate at the excerpt edges.
func TestDOMXSSHarnessMarkerSnippetBounded(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	ctx := context.Background()
	marker := "indSnippetContractMarker"

	values := []struct {
		name  string
		value string
	}{
		{"short", "prefix-" + marker + "-suffix"},
		{"marker-at-start", marker + strings.Repeat("Z", 900)},
		{"marker-crosses-500", strings.Repeat("A", 480) + marker + strings.Repeat("B", 480)},
		{"long-prefix", strings.Repeat("A", 600) + marker},
		{"long-prefix-and-suffix", strings.Repeat("A", 600) + marker + strings.Repeat("B", 600)},
		{"surrogate-prefix", strings.Repeat("😀", 260) + marker + strings.Repeat("B", 600)},
		// Right edge: the one ASCII spacer makes the 500-unit right clip land
		// inside an emoji surrogate pair, so the end-edge trim is exercised.
		{"surrogate-suffix-right-edge", strings.Repeat("A", 600) + marker + "X" + strings.Repeat("😀", 300)},
	}

	for _, v := range values {
		t.Run(v.name, func(t *testing.T) {
			if !strings.Contains(v.value, marker) {
				t.Fatalf("invalid fixture: %q lacks the marker", v.name)
			}
			bc, err := mgr.NewContext(ctx, browser.ContextOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer bc.Close()
			page, err := bc.NewPage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer page.Close()
			if err := page.AddInitScript(ctx, domXSSHarnessScript(marker)); err != nil {
				t.Fatal(err)
			}
			if _, err := page.Navigate(ctx, "about:blank", browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
				t.Fatal(err)
			}
			literal, err := json.Marshal(v.value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := page.Evaluate(ctx, "document.body.innerHTML = "+string(literal)+";"); err != nil {
				t.Fatal(err)
			}
			var report *domXSSSinkReport
			deadline := time.Now().Add(2 * time.Second)
			for {
				count := 0
				for _, message := range page.ConsoleMessages() {
					if !strings.HasPrefix(message.Text, domXSSConsolePrefix) {
						continue
					}
					var rep domXSSSinkReport
					if json.Unmarshal([]byte(strings.TrimPrefix(message.Text, domXSSConsolePrefix)), &rep) != nil {
						continue
					}
					count++
					report = &rep
				}
				if count == 1 || time.Now().After(deadline) {
					if count != 1 {
						t.Fatalf("harness reports=%d, want exactly one", count)
					}
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			units := len(utf16.Encode([]rune(report.Value)))
			if units > 500 {
				t.Fatalf("reported value is %d UTF-16 code units, exceeds the 500-unit evidence bound", units)
			}
			if !strings.Contains(report.Value, marker) {
				t.Fatalf("reported value lost the real marker: %q", report.Value)
			}
			if !utf8.ValidString(report.Value) || strings.ContainsRune(report.Value, utf8.RuneError) {
				t.Fatalf("reported value contains a lone/broken surrogate: %q", report.Value)
			}
			if len(utf16.Encode([]rune(v.value))) > 500 && report.Value == v.value {
				t.Fatalf("reported the complete long value (%d units) instead of a bounded excerpt", units)
			}
		})
	}
}

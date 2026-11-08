//go:build browser_integration

package scan_test

// Real-Chromium coverage for the automatic AngularJS CSP-bypass gate.
//
// One loopback lab serves two routes with the SAME CSP (`script-src 'self'`, so
// inline handlers cannot run) and the SAME reflected `q`:
//
//   - /lab          boots the vendored real AngularJS 1.2.32 (ng-app plus a
//                   same-origin /angular.js), so the gate is eligible;
//   - /no-angular   is the same page without ng-app and without the Angular
//                   script, so the gate is ineligible.
//
// The first test drives a full scan and pins the whole chain the feature adds:
// the `angular_csp_bypass` candidate is planned at /lab (and only there), sent
// as a real HTTP candidate, reflected (a reflected-candidate finding exists
// only after that), and replayed by the browser verifier with its technique and
// value recorded in the finding detail. /no-angular is the RED control:
// identical policy, identical reflection, no Angular => no candidate at all,
// and every canonical shape is blocked by the policy, so nothing can Confirm.
//
// The second test measures the REAL runtime's expression semantics, because
// they decide what the verifier can possibly observe. AngularJS 1.2.32 under
// `script-src 'self'` runs its CSP-safe interpreter, which resolves an unknown
// identifier to `undefined` (a property read on the scope) instead of emitting
// a bare JavaScript identifier. `$event.composedPath()|orderBy:'<marker>'` is
// therefore evaluated — composedPath() is a DOM API, independent of Angular's
// version — but the marker never raises `ReferenceError: <marker> is not
// defined`, and that provenance signature is the verifier's only execution
// authority. The test records the measured behaviour instead of pretending a
// stub Angular would confirm.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

const angularCSPPage = `<!doctype html><html><body%s><div id="out">You searched for: '%s'</div>%s</body></html>`

func newAngularCSPLab(t *testing.T) *site {
	t.Helper()
	angular, err := os.ReadFile("testdata/angular-1.2.32.min.js")
	if err != nil {
		t.Fatalf("read vendored AngularJS fixture: %v", err)
	}
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/lab?q=hello">lab</a> <a href="/no-angular?q=hello">control</a>`)
		})
		mux.HandleFunc("/angular.js", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write(angular)
		})
		render := func(w http.ResponseWriter, r *http.Request, withAngular bool) {
			// The policy that makes the bypass relevant: same-origin script is
			// allowed, inline script and inline handlers are not.
			w.Header().Set("Content-Security-Policy", "script-src 'self'")
			app, script := "", ""
			if withAngular {
				app, script = " ng-app", `<script src="/angular.js"></script>`
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, angularCSPPage, app, r.URL.Query().Get("q"), script)
		}
		mux.HandleFunc("/lab", func(w http.ResponseWriter, r *http.Request) { render(w, r, true) })
		mux.HandleFunc("/no-angular", func(w http.ResponseWriter, r *http.Request) { render(w, r, false) })
	})
}

type angularFindingDetail struct {
	Candidates []detection.Candidate  `json:"candidates"`
	Attempts   []angularVerifyAttempt `json:"attempts"`
}

type angularVerifyAttempt struct {
	CandidateValue string         `json:"candidate_value"`
	URL            string         `json:"url"`
	Verdict        domain.Verdict `json:"verdict"`
	Notes          string         `json:"notes"`
}

func angularDetail(t *testing.T, f *domain.Finding) angularFindingDetail {
	t.Helper()
	var d angularFindingDetail
	if len(f.Detail) > 0 {
		if err := json.Unmarshal(f.Detail, &d); err != nil {
			t.Fatalf("decode finding detail: %v", err)
		}
	}
	return d
}

var angularMarkerRe = regexp.MustCompile(`ind[0-9a-f]{16}`)

func TestAngularCSPBypassIsPlannedOnlyForCSPWithoutUnsafeInlineAndAngular(t *testing.T) {
	ctx := context.Background()
	lab := newAngularCSPLab(t)
	st, q := memory.New(), queue.NewMemory()
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := newBrowserManagerOrSkip(t, 2)
	defer mgr.Close()

	proj, tgt := seedProject(t, st, lab.URL, domain.Scope{IncludeHosts: []string{"127.0.0.1"}})
	cfg := domain.ScanConfig{DiscoveryConcurrency: 4, HTTPConcurrency: 8, BrowserConcurrency: 4}
	ctrl := newCtrl(t, st, q, scan.Options{Browser: mgr, Evidence: ev})
	sc := createScan(t, ctrl, proj, tgt, &cfg, domain.StopPolicy{})

	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 300*time.Second, isCompleted)

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]*domain.Finding{}
	for _, f := range findings {
		if f.VulnClass != domain.VulnReflectedXSS {
			continue
		}
		if ep, err := st.Endpoints().Get(ctx, f.EndpointID); err == nil {
			byPath[urlPath(ep.URL)] = append(byPath[urlPath(ep.URL)], f)
		}
	}
	for p, fs := range byPath {
		for _, f := range fs {
			d := angularDetail(t, f)
			for _, c := range d.Candidates {
				if c.Technique == detection.AngularCSPBypassTechnique {
					t.Logf("%s planned %s: %q", p, c.Technique, c.Value)
				}
			}
			for _, a := range d.Attempts {
				t.Logf("%s finding=%s attempt=%s %q notes=%q", p, f.Verdict, a.Verdict, a.CandidateValue, a.Notes)
			}
		}
	}

	// /lab: the gate is eligible, so the canonical bypass candidate must have
	// been planned, sent, reflected (a reflected-candidate finding exists only
	// after that) and replayed by the browser verifier.
	var plannedValue string
	var labFinding *domain.Finding
	for _, f := range byPath["/lab"] {
		for _, c := range angularDetail(t, f).Candidates {
			if c.Technique != detection.AngularCSPBypassTechnique {
				continue
			}
			plannedValue, labFinding = c.Value, f
			if got, want := c.Value, detection.AngularCSPBypassValue(angularMarkerRe.FindString(c.Value)); got != want {
				t.Fatalf("/lab bypass value = %q, want %q", got, want)
			}
		}
	}
	if labFinding == nil {
		t.Fatalf("/lab must plan the %s candidate; reflected findings=%d", detection.AngularCSPBypassTechnique, len(byPath["/lab"]))
	}
	if !strings.Contains(plannedValue, `ng-focus="$event.composedPath()|orderBy:'`) {
		t.Fatalf("/lab bypass value does not carry the composedPath/orderBy expression: %q", plannedValue)
	}
	var replayed *angularVerifyAttempt
	for _, a := range angularDetail(t, labFinding).Attempts {
		if a.CandidateValue == plannedValue && a.URL != "" {
			a := a
			replayed = &a
		}
	}
	if replayed == nil {
		t.Fatalf("/lab bypass candidate was not replayed by browser verification: %+v", angularDetail(t, labFinding).Attempts)
	}
	t.Logf("/lab bypass verification: verdict=%s notes=%q", replayed.Verdict, replayed.Notes)
	if replayed.Verdict == domain.VerdictConfirmed && !strings.Contains(replayed.Notes, "unresolved JavaScript identifier") {
		// A confirmation must come from the deterministic marker-ReferenceError
		// provenance signal, never from reflection alone.
		t.Fatalf("a Confirmed bypass attempt must name its execution signal: %q", replayed.Notes)
	}

	// The interpolation sibling is the shape this Angular line CAN confirm: its
	// value joins the marker from two literals at runtime, so the rendered page
	// carries a string the request never carried. That is only possible if the
	// page's own Angular compiler evaluated the expression, which is exactly the
	// CSP bypass the gate exists for.
	var exprValue string
	for _, f := range byPath["/lab"] {
		for _, c := range angularDetail(t, f).Candidates {
			if c.Technique == detection.AngularCSPExpressionTechnique {
				exprValue = c.Value
			}
		}
	}
	if exprValue == "" {
		t.Fatalf("/lab must plan the %s candidate; findings=%d", detection.AngularCSPExpressionTechnique, len(byPath["/lab"]))
	}
	var exprAttempt *angularVerifyAttempt
	for _, f := range byPath["/lab"] {
		for _, a := range angularDetail(t, f).Attempts {
			if a.CandidateValue == exprValue {
				a := a
				exprAttempt = &a
			}
		}
	}
	if exprAttempt == nil {
		t.Fatalf("/lab interpolation candidate %q was never replayed by browser verification", exprValue)
	}
	if exprAttempt.Verdict != domain.VerdictConfirmed {
		t.Fatalf("/lab interpolation must Confirm under script-src 'self' (the page evaluated it), got verdict=%s notes=%q",
			exprAttempt.Verdict, exprAttempt.Notes)
	}
	if !strings.Contains(exprAttempt.Notes, "never carried") {
		t.Fatalf("a Confirmed interpolation must name its evidence (a result the request never carried): %q", exprAttempt.Notes)
	}
	t.Logf("/lab interpolation confirmation: verdict=%s notes=%q", exprAttempt.Verdict, exprAttempt.Notes)

	// RED control: /no-angular has the identical policy and reflection but no
	// Angular, so the gate must not plan the bypass, and the policy blocks every
	// inline shape, so nothing may Confirm.
	if len(byPath["/no-angular"]) == 0 {
		t.Fatalf("the control endpoint produced no reflected finding; the RED comparison is not exercised")
	}
	for _, f := range byPath["/no-angular"] {
		for _, c := range angularDetail(t, f).Candidates {
			if c.Technique == detection.AngularCSPBypassTechnique || c.Technique == detection.AngularCSPExpressionTechnique {
				t.Fatalf("/no-angular must not plan %s (no Angular on the page): %q", c.Technique, c.Value)
			}
		}
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("/no-angular must not Confirm under script-src 'self': %+v", f.Summary)
		}
	}
}

// TestVendoredAngularEvaluatesNGFocusUnderCSPWithoutReferenceError pins the
// real runtime's semantics for the exact bypass expression: Angular boots under
// `script-src 'self'` (CSP-safe mode), accepts the composedPath/orderBy
// expression, and resolves the marker identifier to `undefined` rather than
// throwing. That is why the scanner delivers this candidate but the verifier's
// marker-ReferenceError authority cannot Confirm it on this Angular line.
func TestVendoredAngularEvaluatesNGFocusUnderCSPWithoutReferenceError(t *testing.T) {
	lab := newAngularCSPLab(t)
	const marker = "ind0123456789abcdef"
	candidate := detection.AngularCSPBypassValue(marker)

	mgr := newBrowserManagerOrSkip(t, 1)
	defer mgr.Close()
	bctx, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bctx.Close()
	page, err := bctx.NewPage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()
	u := lab.URL + "/lab?q=" + strings.ReplaceAll(candidate, " ", "+")
	if _, err := page.Navigate(context.Background(), u, browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 15 * time.Second}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // let DOMContentLoaded bootstrap AngularJS

	script := `(function(){
  var inj = angular.element(document.body).injector();
  var out = {csp: inj.get('$sniffer').csp};
  var $parse = inj.get('$parse');
  try { out.marker = 'value:' + String($parse('` + marker + `')({})); } catch (e) { out.marker = 'threw:' + e.name + ': ' + e.message; }
  try {
    out.composed = Object.prototype.toString.call(
      $parse("$event.composedPath()|orderBy:'` + marker + `'")({$event:{composedPath:function(){ return [window]; }}}));
  } catch (e) { out.composed = 'threw:' + e.name + ': ' + e.message; }
  // Prove the real compiler links ng-focus and dispatches it on focus: a
  // sandbox-safe scope write is observable, so a failure here would mean the
  // mechanism itself is unavailable, not just the marker signal.
  try {
    var scope = angular.element(document.body).scope();
    var probe = inj.get('$compile')('<input ng-focus="ngFocusFired=1">')(scope);
    document.body.appendChild(probe[0]);
    probe[0].focus();
    out.ngFocus = String(scope.ngFocusFired);
  } catch (e) { out.ngFocus = 'threw:' + e.name + ': ' + e.message; }
  return JSON.stringify(out);
})()`
	raw, err := page.Evaluate(context.Background(), script)
	if err != nil {
		t.Fatalf("evaluate the real AngularJS $parse: %v", err)
	}
	var got struct {
		CSP      bool   `json:"csp"`
		Marker   string `json:"marker"`
		Composed string `json:"composed"`
		NGFocus  string `json:"ngFocus"`
	}
	if err := json.Unmarshal([]byte(fmt.Sprint(raw)), &got); err != nil {
		t.Fatalf("decode $parse measurement %v: %v", raw, err)
	}
	t.Logf("measured: csp=%v marker=%s composedPath|orderBy=%s ng-focus-dispatch=%s (candidate %s)",
		got.CSP, got.Marker, got.Composed, got.NGFocus, candidate)

	if !got.CSP {
		t.Fatalf("Angular must be in CSP-safe mode under script-src 'self': %+v", got)
	}
	if got.Marker != "value:undefined" {
		t.Fatalf("the real AngularJS must resolve the unknown marker to undefined without throwing, got %q", got.Marker)
	}
	if strings.HasPrefix(got.Composed, "threw:") {
		t.Fatalf("the exact bypass expression must be accepted by the real AngularJS evaluator, got %q", got.Composed)
	}
	if got.NGFocus != "1" {
		t.Fatalf("the real AngularJS must compile and dispatch an ng-focus handler on focus, got %q", got.NGFocus)
	}
	// The verifier's authority is an uncaught ReferenceError naming the marker;
	// on this runtime none is raised, so the candidate can never Confirm here.
	for _, e := range page.PageErrors() {
		if strings.Contains(e, marker+" is not defined") {
			t.Fatalf("the real AngularJS runtime unexpectedly raised a marker ReferenceError: %q", e)
		}
	}
}

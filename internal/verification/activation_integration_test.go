// These tests drive a REAL Chromium via Playwright against local httptest
// fixtures (no real hosts), exercising the one activation verification may
// perform for a candidate whose trigger is not page load. They reuse the
// manager/skip helpers from browser_integration_test.go.
//
// Every fixture instruments the page so the test can prove TWO separate facts:
//   - the marker was observed as code (the unchanged provenance signal), and
//   - the activation itself ran exactly once (a fixture-side counter written
//     into the DOM, captured in the post-activation evidence).
//
// A page that reflects the same marker without a handler proves the other half:
// activation never confirms by itself.
package verification_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// activationFixture serves one HTML page whose only dynamic content is the
// reflected query value, plus a head script that counts dispatches of one
// event into a data-attribute on <html>, so the counter survives into the
// post-activation DOM evidence.
type activationFixture struct {
	// body is the HTML shell; %s receives the reflected query value.
	body string
	// transform rewrites the reflected value server-side (fixture controls
	// only: pinning an animation to begin="indefinite", or removing a handler
	// for the negative control). Nil means reflect byte-for-byte.
	transform func(string) string
}

func (f activationFixture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if f.transform != nil {
			q = f.transform(q)
		}
		fmt.Fprintf(w, f.body, q)
	}
}

// countScript counts dispatches of one event (capture phase, so it also sees
// non-bubbling focus events) into a data attribute on <html>. target is the
// event target the event is actually dispatched at: "window" for resize (which
// is dispatched at window and never reaches document), "document" for focus and
// click.
func countScript(target, attr, event string) string {
	return fmt.Sprintf(`<script>
(function(){
  function bump(){
    var n = parseInt(document.documentElement.getAttribute(%q) || "0", 10) + 1;
    document.documentElement.setAttribute(%q, String(n));
  }
  %s.addEventListener(%q, bump, true);
})();
</script>`, attr, attr, target, event)
}

// SMIL beginEvent does not bubble, so the counter is attached to each
// animation element itself.
func countBeginScript(attr string) string {
	return fmt.Sprintf(`<script>
document.addEventListener('DOMContentLoaded', function(){
  function bump(){
    var n = parseInt(document.documentElement.getAttribute(%q) || "0", 10) + 1;
    document.documentElement.setAttribute(%q, String(n));
  }
  var els = document.querySelectorAll('animate, animateTransform, animateMotion, set');
  for (var i = 0; i < els.length; i++) { els[i].addEventListener('beginEvent', bump); }
});
</script>`, attr, attr)
}

func page(head, reflected string) string {
	return `<!doctype html><html><head>` + head + `</head><body><p>` + reflected + `</p></body></html>`
}

// verifyFixture sends cand.Value to the fixture page as the candidate's exact
// replayed payload (the marker is carried separately, exactly as the pipeline
// does) and returns the verification result.
func verifyFixture(t *testing.T, f activationFixture, cand detection.Candidate, marker string) *verification.Result {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	mgr := newManagerOrSkip(t)
	t.Cleanup(func() { mgr.Close() })

	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: cand,
		Marker:    marker,
		Method:    "GET",
		URL:       queryURL(srv.URL+"/", cand.Value),
		Scope:     openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Report == nil {
		t.Fatal("no report")
	}
	return res
}

func requireActivation(t *testing.T, res *verification.Result, class verification.ActivationClass, status string) *verification.Activation {
	t.Helper()
	act := res.Report.Activation
	if act == nil {
		t.Fatalf("no activation recorded; verdict %s, notes %q", res.Verdict, res.Notes)
	}
	if act.Class != class {
		t.Fatalf("activation class = %q, want %q (reason %q)", act.Class, class, act.Reason)
	}
	if act.Status != status {
		t.Fatalf("activation status = %q, want %q (error %q)", act.Status, status, act.Error)
	}
	return act
}

// requireCount asserts the fixture's own counter saw the activation exactly
// `want` times, using the post-activation DOM evidence.
func requireCount(t *testing.T, res *verification.Result, attr, want string) {
	t.Helper()
	wantAttr := attr + `="` + want + `"`
	if !strings.Contains(res.Evidence.DOMHTML, wantAttr) {
		t.Fatalf("post-activation DOM does not contain %s; the activation did not run exactly %s time(s)", wantAttr, want)
	}
}

// --- resize: <body onresize=MARKER> ---

func TestIntegrationActivationBodyOnresizeConfirms(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("window", "data-resizes", "resize"), "%s"),
	}
	value := "<body onresize=" + m + ">"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed (notes %q)", res.Verdict, res.Notes)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
	act := requireActivation(t, res, verification.ActivationResize, verification.ActivationStatusDispatched)
	if act.Method != "window.dispatchEvent(new Event('resize'))" {
		t.Fatalf("activation method = %q", act.Method)
	}
	if act.Attempts != 1 {
		t.Fatalf("activation attempts = %d, want 1", act.Attempts)
	}
	if act.SettleMS <= 0 {
		t.Fatalf("post-activation observation window was not recorded: %+v", act)
	}
	requireCount(t, res, "data-resizes", "1")
}

// Same page, handler removed: the marker still reflects, the activation still
// runs exactly once, and the verdict stays REJECTED because nothing evaluated
// the marker. This is the false-positive guard.
func TestIntegrationActivationBodyOnresizeWithoutHandlerStaysRejected(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("window", "data-resizes", "resize"), "%s"),
		transform: func(q string) string {
			return strings.ReplaceAll(q, "onresize=", "data-noop=")
		},
	}
	value := "<body onresize=" + m + ">"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (activation must never confirm on its own); notes %q", res.Verdict, res.Notes)
	}
	if !res.Report.MarkerInDOM {
		t.Fatal("the marker should still be reflected in the DOM")
	}
	if res.Report.Signal != verification.SignalNone {
		t.Fatalf("signal = %s, want none", res.Report.Signal)
	}
	requireActivation(t, res, verification.ActivationResize, verification.ActivationStatusDispatched)
	requireCount(t, res, "data-resizes", "1")
}

// --- focus: custom element with onfocus (no autofocus, so page load alone can
// never focus it) ---

func TestIntegrationActivationCustomElementFocusConfirms(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-focuses", "focus"), "%s"),
	}
	value := "<x-" + m + " tabindex=1 onfocus=" + m + "></x-" + m + ">"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed (notes %q)", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationFocus, verification.ActivationStatusDispatched)
	if act.Method != "element.focus()" {
		t.Fatalf("activation method = %q, want the native focus() path", act.Method)
	}
	requireCount(t, res, "data-focuses", "1")
}

// A focus-class candidate whose page reflects the marker with the handler
// stripped: the verifier still performs its one focus, and the verdict stays
// rejected because nothing executed.
func TestIntegrationActivationFocusWithoutHandlerStaysRejected(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-focuses", "focus"), "%s"),
		transform: func(q string) string {
			return strings.ReplaceAll(q, "onfocus=", "data-noop=")
		},
	}
	value := "<x-" + m + " tabindex=1 onfocus=" + m + "></x-" + m + ">"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected; notes %q", res.Verdict, res.Notes)
	}
	if res.Report.Signal != verification.SignalNone {
		t.Fatalf("signal = %s, want none", res.Report.Signal)
	}
	requireActivation(t, res, verification.ActivationFocus, verification.ActivationStatusDispatched)
	requireCount(t, res, "data-focuses", "1")
}

// --- animation: SVG SMIL onbegin ---

func TestIntegrationActivationSVGOnbeginConfirms(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countBeginScript("data-begins"), "%s"),
		// The fixture pins begin="indefinite" so the animation CANNOT start on
		// its own: only the verifier's single beginElement() call can dispatch
		// beginEvent. The candidate value itself is unchanged.
		transform: func(q string) string {
			return strings.ReplaceAll(q, "attributeName=transform", `attributeName=transform begin="indefinite"`)
		},
	}
	value := "<svg><animatetransform onbegin=" + m + " attributeName=transform></svg>"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed (notes %q)", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationAnimation, verification.ActivationStatusDispatched)
	if act.Method != "element.beginElement()" {
		t.Fatalf("activation method = %q", act.Method)
	}
	requireCount(t, res, "data-begins", "1")
}

// --- click: javascript: URL ---

func TestIntegrationActivationJavascriptURLConfirmsAfterOneClick(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-clicks", "click"), `<a href="%s">link</a>`),
	}
	value := "javascript:" + m
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatURL, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed (notes %q)", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationClick, verification.ActivationStatusDispatched)
	if act.Method != "element.click()" {
		t.Fatalf("activation method = %q", act.Method)
	}
	requireCount(t, res, "data-clicks", "1")
}

// --- unsupported interaction: recorded, never confirmed ---

func TestIntegrationActivationUnsupportedInteractionIsRecorded(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-overs", "mouseover"), `%s`),
	}
	value := `" onmouseover=` + m
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected; notes %q", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationUnsupported, verification.ActivationStatusSkipped)
	if act.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0 (nothing must be dispatched)", act.Attempts)
	}
	if !strings.Contains(act.Reason, "onmouseover") {
		t.Fatalf("reason = %q, want it to name the unattempted interaction", act.Reason)
	}
	if strings.Contains(res.Evidence.DOMHTML, `data-overs="1"`) {
		t.Fatal("an unsupported interaction must not have been dispatched")
	}
}

// --- activation failure: recorded, never confirmed ---

func TestIntegrationActivationFailureIsRecorded(t *testing.T) {
	m := marker(t)
	// The candidate is animation-class, but the page reflects it into plain text,
	// so there is no SMIL element to start. The verifier must record a distinct
	// failure with its error text, not confirm and not stay silent.
	f := activationFixture{
		body: page("", "<span>%s</span>"),
		transform: func(q string) string {
			return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(q)
		},
	}
	value := "<svg><animatetransform onbegin=" + m + " attributeName=transform></svg>"
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText, Value: value,
		Trigger: detection.TriggerInteraction,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected; notes %q", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationAnimation, verification.ActivationStatusFailed)
	if act.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (the attempt was made and failed)", act.Attempts)
	}
	if act.Error == "" {
		t.Fatal("the activation error must never be swallowed")
	}
	if !strings.Contains(res.Notes, "activation could not run") {
		t.Fatalf("notes = %q, want the activation failure surfaced", res.Notes)
	}
}

// --- TriggerLoad candidates: unchanged behaviour (never activated) ---

func TestIntegrationActivationTriggerLoadCandidatesAreNeverActivated(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-clicks", "click"), `<a href="%s">link</a>`),
	}
	// A shape that WOULD confirm if it were clicked, declared as a load-trigger
	// candidate: the verifier must not activate it.
	value := "javascript:" + m
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatURL, Value: value,
		Trigger: detection.TriggerLoad,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (load candidates are not activated)", res.Verdict)
	}
	if res.Report.Activation != nil {
		t.Fatalf("load candidate recorded an activation: %+v", res.Report.Activation)
	}
	if strings.Contains(res.Evidence.DOMHTML, `data-clicks="1"`) {
		t.Fatal("a load-trigger candidate must never be clicked")
	}
}

// A candidate with no declared trigger (the pre-existing default) is treated
// exactly like a load candidate: nothing is activated.
func TestIntegrationActivationLegacyCandidateWithoutTriggerIsNeverActivated(t *testing.T) {
	m := marker(t)
	f := activationFixture{
		body: page(countScript("document", "data-clicks", "click"), `<a href="%s">link</a>`),
	}
	value := "javascript:" + m
	res := verifyFixture(t, f, detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatURL, Value: value,
	}, m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected", res.Verdict)
	}
	if res.Report.Activation != nil {
		t.Fatalf("legacy candidate recorded an activation: %+v", res.Report.Activation)
	}
}

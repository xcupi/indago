// These tests drive a REAL Chromium against local httptest fixtures (no real
// hosts) for the KEYBOARD activation class: a candidate that declares an
// accesskey is activated the way a victim activates it — the platform's
// access-key chord, pressed once through the browser's real keyboard input —
// never with element.click().
//
// The fixture reproduces the live canonical-link bytes: a <link rel=canonical>
// in <head> whose single-quoted href carries the reflected value. The injected
// attributes therefore live on an element that never renders a box, which is
// exactly the position a click cannot be aimed at by a pointer.
//
// Every fixture instruments the page so the test can prove TWO separate facts:
//   - the marker was observed as code (the unchanged provenance signal), and
//   - exactly one real key chord arrived (the fixture's own keydown counter,
//     captured in the post-activation DOM evidence).
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

// accesskeyCounters counts the key chord (Alt+Shift+<key>) and the click the
// browser's own access-key action dispatches, into attributes on <html> so both
// survive into the post-activation DOM evidence.
func accesskeyCounters(key string) string {
	return fmt.Sprintf(`<script>
(function(){
  function bump(attr){
    var n = parseInt(document.documentElement.getAttribute(attr) || "0", 10) + 1;
    document.documentElement.setAttribute(attr, String(n));
  }
  document.addEventListener('keydown', function(e){
    if (e.altKey && e.shiftKey && e.key && e.key.toLowerCase() === %q) bump('data-keys');
  }, true);
  document.addEventListener('click', function(){ bump('data-clicks'); }, true);
})();
</script>`, strings.ToLower(key))
}

// accesskeyPage is the live-lab shape: the value is reflected into a
// single-quoted href of a <link> in <head>, and the injected breakout adds
// accesskey + onclick to that same element.
func accesskeyPage(head string, body string) func(q string) string {
	return func(q string) string {
		return `<!doctype html><html><head>` +
			`<link rel="canonical" href='https://lab.example/post?x=` + q + `'/>` +
			head +
			`</head><body>` + body + `</body></html>`
	}
}

func verifyAccesskey(t *testing.T, render func(q string) string, cand detection.Candidate, marker string) *verification.Result {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, render(r.URL.Query().Get("q")))
	}))
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

// accesskeyCandidate is the exact planned shape for a single-quoted href.
func accesskeyCandidate(marker string) detection.Candidate {
	return detection.Candidate{
		Source:    detection.SourceBuiltin,
		Category:  detection.CatURL,
		Value:     `'accesskey='x' onclick=` + marker + ` x='`,
		Trigger:   detection.TriggerInteraction,
		Delimiter: "single",
	}
}

// TestIntegrationActivationAccesskeyConfirmsAfterKeypress is the positive
// fixture: the marker names the element's access key, so the verifier's single
// Alt+Shift+x press makes the browser run the injected click handler and the
// marker is observed as an unresolved identifier.
func TestIntegrationActivationAccesskeyConfirmsAfterKeypress(t *testing.T) {
	m := marker(t)
	res := verifyAccesskey(t, accesskeyPage(accesskeyCounters("x"), "<h1>Post</h1>"), accesskeyCandidate(m), m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; signal=%s inDOM=%v activation=%+v notes=%q",
			res.Verdict, res.Report.Signal, res.Report.MarkerInDOM, res.Report.Activation, res.Notes)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
	act := requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusDispatched)
	if act.Method != "keyboard.press('Alt+Shift+x')" {
		t.Fatalf("activation method = %q, want the real keyboard chord", act.Method)
	}
	if act.Element != "link" {
		t.Fatalf("activation element = %q, want the non-rendered link element", act.Element)
	}
	if act.Attempts != 1 {
		t.Fatalf("activation attempts = %d, want exactly 1", act.Attempts)
	}
	if act.SettleMS <= 0 {
		t.Fatalf("post-activation observation window was not recorded: %+v", act)
	}
	if act.SettleBeforeMS <= 0 {
		t.Fatalf("the bounded settle before the keypress was not recorded: %+v", act)
	}
	// One chord arrived (the fixture's own keydown counter), and the browser's
	// own access-key action dispatched exactly one click from it.
	requireCount(t, res, "data-keys", "1")
	requireCount(t, res, "data-clicks", "1")
	if !strings.Contains(res.Evidence.DOMHTML, `accesskey="x"`) || !strings.Contains(res.Evidence.DOMHTML, `onclick="`+m+`"`) {
		t.Fatalf("post-activation DOM does not carry the injected accesskey/onclick pair: %s", res.Evidence.DOMHTML)
	}
}

// TestIntegrationActivationAccesskeyWithoutHandlerStaysRejected is the
// false-positive guard: the same page reflects the same value with the handler
// stripped. The chord still runs exactly once, and the verdict stays Rejected
// because nothing evaluated the marker.
func TestIntegrationActivationAccesskeyWithoutHandlerStaysRejected(t *testing.T) {
	m := marker(t)
	render := accesskeyPage(accesskeyCounters("x"), "<h1>Post</h1>")
	withoutHandler := func(q string) string {
		return strings.ReplaceAll(render(q), "onclick="+m, "data-noop="+m)
	}
	res := verifyAccesskey(t, withoutHandler, accesskeyCandidate(m), m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (activation must never confirm on its own); notes %q", res.Verdict, res.Notes)
	}
	if !res.Report.MarkerInDOM {
		t.Fatal("the marker should still be reflected in the DOM")
	}
	if res.Report.Signal != verification.SignalNone {
		t.Fatalf("signal = %s, want none", res.Report.Signal)
	}
	requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusDispatched)
	requireCount(t, res, "data-keys", "1")
}

// TestIntegrationActivationAccesskeyElementRemovedIsRecorded covers the
// distinct "it could not run" outcome: the page's own script removes the
// injected link before activation, while the marker stays reflected elsewhere
// in the DOM. Nothing can be pressed, and the record says so instead of
// pretending the shape was tested.
func TestIntegrationActivationAccesskeyElementRemovedIsRecorded(t *testing.T) {
	m := marker(t)
	render := func(q string) string {
		return `<!doctype html><html><head>` +
			`<link id="canonical" rel="canonical" href='https://lab.example/post?x=` + q + `'/>` +
			`<script>document.addEventListener('DOMContentLoaded', function(){` +
			`var el = document.getElementById('canonical'); if (el) el.parentNode.removeChild(el);` +
			`});</script>` +
			accesskeyCounters("x") +
			`</head><body><p>` + q + `</p></body></html>`
	}
	res := verifyAccesskey(t, render, accesskeyCandidate(m), m)

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected; notes %q", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusFailed)
	if act.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (the attempt was made and failed)", act.Attempts)
	}
	if !strings.Contains(act.Error, "accesskey") {
		t.Fatalf("activation error = %q, want it to name the missing accesskey element", act.Error)
	}
	if act.Method != "" {
		t.Fatalf("activation method = %q, want empty (no chord could be pressed)", act.Method)
	}
	if !strings.Contains(res.Notes, "activation could not run") {
		t.Fatalf("notes = %q, want the activation failure surfaced", res.Notes)
	}
	if strings.Contains(res.Evidence.DOMHTML, `data-keys="1"`) {
		t.Fatal("a key chord was dispatched even though the accesskey element was gone")
	}
}

// TestIntegrationActivationAccesskeyKeepsClickClassForPlainOnclick freezes the
// neighbouring class: a plain onclick candidate (no accesskey) is still
// activated with exactly one element.click(), never with a chord.
func TestIntegrationActivationAccesskeyKeepsClickClassForPlainOnclick(t *testing.T) {
	m := marker(t)
	render := func(q string) string {
		return `<!doctype html><html><head>` + accesskeyCounters("x") +
			`</head><body><a id="l" href="#" ` + q + `>x</a></body></html>`
	}
	cand := detection.Candidate{
		Source:   detection.SourceBuiltin,
		Category: detection.CatHTMLAttr,
		Value:    "onclick=" + m,
		Trigger:  detection.TriggerInteraction,
	}
	res := verifyAccesskey(t, render, cand, m)

	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; notes %q", res.Verdict, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationClick, verification.ActivationStatusDispatched)
	if act.Method != "element.click()" {
		t.Fatalf("activation method = %q, want element.click()", act.Method)
	}
	if strings.Contains(res.Evidence.DOMHTML, `data-keys="1"`) {
		t.Fatal("a click-class candidate must not receive a key chord")
	}
}

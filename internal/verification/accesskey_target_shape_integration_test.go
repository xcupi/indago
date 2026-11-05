// These tests pin the MEASURED truth about the access-key activation against
// the exact bytes the canonical-link target serves (HANDOFF.md): the injected
// `accesskey`/`onclick` pair sits on a `<link rel="canonical">` in <head>, an
// element that never renders a box, and the driver's single access-key chord
// activates it there just as it does on a rendered anchor.
//
// They are deliberately different from accesskey_integration_test.go: that file
// instruments the page (counters, a head <script>) to prove HOW MANY times the
// activation ran. These tests serve the target's bytes untouched, so a future
// change cannot pass by making an instrumented fixture work while the real
// shape regresses.
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

// targetPage is the target's own template, byte for byte: a single-quoted
// canonical href whose value is the injection point, and nothing else in
// <head>. %s receives the reflected value.
const targetPage = `<!doctype html><html><head><link rel="canonical" href='https://example/?x=%s'></head><body>ok</body></html>`

// verifyOnTemplate serves tmpl (one %s) and replays value into its `q`
// parameter through the real verifier.
func verifyOnTemplate(t *testing.T, tmpl, value, m string, hdr map[string]string) *verification.Result {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		fmt.Fprintf(w, tmpl, r.URL.Query().Get("q"))
	}))
	t.Cleanup(srv.Close)

	mgr := newManagerOrSkip(t)
	t.Cleanup(func() { mgr.Close() })

	v := verification.NewBrowserVerifier(mgr, verification.BrowserVerifierConfig{})
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: detection.Candidate{
			Source:    detection.SourceBuiltin,
			Category:  detection.CatURL,
			Value:     value,
			Trigger:   detection.TriggerInteraction,
			Delimiter: "single",
		},
		Marker: m,
		Method: "GET",
		URL:    queryURL(srv.URL+"/", value),
		Scope:  openScope(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// requireBoxlessLinkConfirmation asserts the whole observed chain for this
// shape: the marker ran, the activation was the keyboard chord aimed at the
// <link>, and the post-activation DOM still carries the injected pair.
func requireBoxlessLinkConfirmation(t *testing.T, res *verification.Result, m string) {
	t.Helper()
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; signal=%s activation=%+v notes=%q",
			res.Verdict, res.Report.Signal, res.Report.Activation, res.Notes)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
	act := requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusDispatched)
	if act.Method != "keyboard.press('Alt+Shift+x')" {
		t.Fatalf("activation method = %q, want the real access-key chord", act.Method)
	}
	if act.Element != "link" {
		t.Fatalf("activation element = %q, want the box-less link element", act.Element)
	}
	if act.Attempts != 1 {
		t.Fatalf("activation attempts = %d, want exactly 1", act.Attempts)
	}
	if !strings.Contains(res.Evidence.DOMHTML, `accesskey="x"`) || !strings.Contains(res.Evidence.DOMHTML, `onclick="`+m+`"`) {
		t.Fatalf("post-activation DOM does not carry the injected accesskey/onclick pair: %s", res.Evidence.DOMHTML)
	}
}

// TestIntegrationAccesskeyBoxlessLinkExactTargetBytes replays the target's
// literal payload: the accesskey value is the site-quoted form the markup
// showed. No focus help, no bringToFront, no body click — exactly what
// production does.
func TestIntegrationAccesskeyBoxlessLinkExactTargetBytes(t *testing.T) {
	m := marker(t)
	res := verifyOnTemplate(t, targetPage, `'accesskey='x' onclick='`+m+`' x='`, m, nil)
	requireBoxlessLinkConfirmation(t, res, m)
}

// TestIntegrationAccesskeyBoxlessLinkPlannerShape replays the shape the
// planner emits since the delimiter-quote fix (bare `accesskey=x`): the same
// attributes must reach the same element and confirm the same way.
func TestIntegrationAccesskeyBoxlessLinkPlannerShape(t *testing.T) {
	m := marker(t)
	res := verifyOnTemplate(t, targetPage, `'accesskey=x onclick=`+m+` x='`, m, nil)
	requireBoxlessLinkConfirmation(t, res, m)
}

// TestIntegrationAccesskeyRenderedAnchorControl is the control: the same
// payload on a RENDERED <a> in body. It confirms too, which is the point —
// access keys work in this stack generally, so the box-less case above is not
// an artefact of the fixture, and neither result stands in for the other.
func TestIntegrationAccesskeyRenderedAnchorControl(t *testing.T) {
	m := marker(t)
	tmpl := `<!doctype html><html><head></head><body>ok<a href='#?x=%s' id='ctl'>go</a></body></html>`
	res := verifyOnTemplate(t, tmpl, `'accesskey='x' onclick='`+m+`' x='`, m, nil)
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("control verdict = %s, want confirmed (activation=%+v notes=%q)",
			res.Verdict, res.Report.Activation, res.Notes)
	}
	act := requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusDispatched)
	if act.Element != "a" {
		t.Fatalf("control activation element = %q, want the rendered anchor", act.Element)
	}
}

// TestIntegrationAccesskeyCSPBlockedHandlerIsRejectedAndExplained covers the
// one measured way this exact shape ends Rejected while the activation itself
// is correct: the page's CSP refuses to compile the inline handler. The verdict
// must stay Rejected (a victim's browser would not run it either), and the
// notes must name the policy block so it is not mistaken for a broken
// activation.
func TestIntegrationAccesskeyCSPBlockedHandlerIsRejectedAndExplained(t *testing.T) {
	m := marker(t)
	res := verifyOnTemplate(t, targetPage, `'accesskey='x' onclick='`+m+`' x='`, m, map[string]string{
		"Content-Security-Policy": "script-src 'self'; object-src 'none'",
	})

	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected under a CSP that blocks inline handlers; notes=%q", res.Verdict, res.Notes)
	}
	if !res.Report.MarkerInDOM {
		t.Fatal("the marker must still be reflected: the CSP blocks execution, not reflection")
	}
	act := requireActivation(t, res, verification.ActivationKeyboard, verification.ActivationStatusDispatched)
	if act.Element != "link" {
		t.Fatalf("activation element = %q, want the injected link", act.Element)
	}
	if !strings.Contains(res.Notes, "Content-Security-Policy") || !strings.Contains(res.Notes, "not an activation failure") {
		t.Fatalf("notes = %q, want the CSP block named as a policy block, not an activation failure", res.Notes)
	}
	if !strings.Contains(strings.Join(res.Evidence.BrowserLog, "\n"), "Content Security Policy") {
		t.Fatalf("browser log does not retain the CSP violation: %q", res.Evidence.BrowserLog)
	}
}

package web_test

// Real-browser check of the token-mode artifact viewer: with a bearer token
// required, protected evidence cannot be opened by a plain navigation (the
// header cannot be sent), so the dashboard fetches it with the token. HTML
// evidence must then render in a sandboxed iframe with no script permission
// and no console origin, not as text and not as a same-origin page.

import (
	"context"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

const uiTokenTestToken = "indago-test-token-4b1e9a7c03d2f8e65a0b9c1d7e3f2a48" // dummy

func TestUITokenModeHTMLEvidenceOpensInSandboxedFrame(t *testing.T) {
	u := newUIHarnessWithToken(t, uiTokenTestToken)
	scanID := uiFindingsScan(t, u)
	f := uiFinding(t, u, scanID, domain.VerdictConfirmed, uiFindingOpts{path: "/a"}, time.Now())
	var domID domain.ID
	for _, id := range f.EvidenceIDs {
		if ev, _ := u.st.Evidence().Get(context.Background(), id); ev != nil && ev.Kind == domain.EvidenceDOM {
			domID = id
		}
	}
	if domID == "" {
		t.Fatal("finding has no DOM evidence")
	}

	u.openScanTab(scanID, "evidence")
	u.waitUI("evidence listed", `document.querySelectorAll('#evidenceBody a').length>=2`)
	href := "/api/evidence/" + string(domID) + "/content"
	u.waitUI("open link for the DOM evidence", `document.querySelector('#evidenceBody a[href="`+href+`"]')`)
	u.eval(`document.querySelector('#evidenceBody a[href="` + href + `"]').click(), true`)

	// The artifact is shown in an iframe with sandbox="" (no allow-scripts, no
	// allow-same-origin). Its document is opaque to the console, so the
	// console cannot read it.
	u.waitUI("sandboxed artifact frame shown", `(function(){var f=document.querySelector('iframe.artifact-frame');return !!f && f.getAttribute('sandbox')==='';})()`)
	if !u.evalBool(`document.querySelector('iframe.artifact-frame').contentDocument === null`) {
		t.Fatal("artifact frame is same-origin with the console: its document is readable")
	}
	if u.evalBool(`/allow-scripts|allow-same-origin/.test(document.querySelector('iframe.artifact-frame').getAttribute('sandbox'))`) {
		t.Fatal("artifact frame grants script or same-origin permission")
	}
	// Never rendered as text in the console.
	if u.evalBool(`document.querySelector('#evidenceBody pre') !== null`) {
		t.Fatal("HTML evidence was rendered as text in the console")
	}
	if errs := u.page.PageErrors(); len(errs) > 0 {
		t.Fatalf("dashboard JS errors: %v", errs)
	}
}

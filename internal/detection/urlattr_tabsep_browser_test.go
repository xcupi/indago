package detection_test

// Real-browser regression for the TAB-separated raw-query variants.
//
// The measured canonical-link lab reflects the whole query blob into a
// single-quoted href and PERCENT-ENCODES a space, so the canonical
// `accesskey=x onclick=MARKER x=` shape arrives as one attribute value
// (`accesskey` = `x%20onclick=MARKER%20x=`) with no onclick attribute at all:
// the verifier can activate nothing and the candidate stays Rejected. The same
// request with a TAB separator is reflected raw, the parser sees three separate
// attributes, and the access-key activation fires the handler.
//
// This fixture replicates exactly that escaping (spaces -> %20, tabs raw) with
// a local httptest server, so it is the regression that proves the tab variant
// fixes a genuinely vulnerable page the space variant cannot confirm.
//
// Skips quickly when no Chromium is available, matching the other real-browser
// tests in this package.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// tabSepPage is the measured lab position: the value lands inside a
// single-quoted canonical href in <head>.
const tabSepPage = `<!doctype html><html><head>` +
	`<link rel="canonical" href='https://lab.example/post?search=%s'>` +
	`<title>Post</title></head><body><h1>Post</h1></body></html>`

// tabSepServer reflects the query into tabSepPage with the measured escaping:
// a SPACE becomes the literal text %20 inside the attribute value, while a TAB
// is passed through raw.
func tabSepServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := strings.ReplaceAll(r.URL.Query().Get("q"), " ", "%20")
		fmt.Fprintf(w, tabSepPage, v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tabSepPlan plans the fixture exactly as the reflection step does for a
// raw-query injection point (see urlAttrPlanFor in urlattr_browser_test.go).
func tabSepPlan(t *testing.T, srv *httptest.Server) *detection.CandidatePlan {
	t.Helper()
	return urlAttrPlanFor(t, srv)
}

// TestTabSeparatedBreakoutConfirmsWhereSpaceStaysRejected is the regression:
// on the same page, the TAB-separated accesskey/onclick variant is Confirmed by
// the verifier's real access-key activation, while the space-separated variant
// — the shape that was planned before this slice — stays Rejected because the
// server's %20 leaves it as a single attribute value.
func TestTabSeparatedBreakoutConfirmsWhereSpaceStaysRejected(t *testing.T) {
	srv := tabSepServer(t)

	// Fixture control: prove the server really replicates the measured
	// escaping, so a GREEN below cannot come from a page that quietly keeps
	// the space intact.
	probeURL := urlAttrReplayURL(srv.URL+"/", "a b\tc")
	resp, err := http.Get(probeURL)
	if err != nil {
		t.Fatalf("fetch fixture control: %v", err)
	}
	controlBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(controlBody), "a%20b\tc") {
		t.Fatalf("fixture does not replicate the measured escaping (want a space percent-encoded and a tab raw): %s", controlBody)
	}

	m := urlAttrProbe.Token
	plan := tabSepPlan(t, srv)

	spaceValue := `'accesskey=x onclick=` + m + ` x='`
	tabValue := `'accesskey=x` + "\t" + `onclick=` + m + "\t" + `x='`
	spaceCand := findCandidate(plan, spaceValue)
	tabCand := findCandidate(plan, tabValue)
	if spaceCand == nil || tabCand == nil {
		t.Fatalf("fixture plan is missing the space (%v) or TAB (%v) accesskey variant: %+v",
			spaceCand != nil, tabCand != nil, plan.Candidates)
	}
	if tabCand.Trigger != detection.TriggerInteraction || tabCand.Delimiter != "single" {
		t.Fatalf("TAB variant = trigger %q delimiter %q, want the interaction-class single-quote shape", tabCand.Trigger, tabCand.Delimiter)
	}

	v := urlAttrVerifier(t)

	// The TAB variant: the separator survives URL encoding as %09, is
	// reflected raw, and the activation reaches the handler.
	tabRes, err := v.Verify(context.Background(), verification.Input{
		Candidate: *tabCand,
		Marker:    m,
		Method:    "GET",
		URL:       urlAttrReplayURL(srv.URL+"/", tabCand.Value),
		Scope:     domain.Scope{IncludeHosts: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("verify TAB variant: %v", err)
	}
	if tabRes.Report == nil {
		t.Fatal("TAB variant: no report")
	}
	if tabRes.Verdict != domain.VerdictConfirmed {
		t.Fatalf("TAB variant verdict = %s, want confirmed (the tab separator must parse into separate attributes); signal=%s inDOM=%v activation=%+v notes=%q",
			tabRes.Verdict, tabRes.Report.Signal, tabRes.Report.MarkerInDOM, tabRes.Report.Activation, tabRes.Notes)
	}
	if tabRes.Report.Signal != verification.SignalPageError {
		t.Fatalf("TAB variant signal = %s, want page_error", tabRes.Report.Signal)
	}
	act := tabRes.Report.Activation
	if act == nil || act.Class != verification.ActivationKeyboard || act.Status != verification.ActivationStatusDispatched {
		t.Fatalf("TAB variant activation = %+v, want one dispatched access-key chord", act)
	}
	if act.Method != "keyboard.press('Alt+Shift+x')" || act.Element != "link" {
		t.Fatalf("TAB variant activation = %q on %q, want the real chord on the box-less link", act.Method, act.Element)
	}
	if !strings.Contains(tabRes.Evidence.DOMHTML, `accesskey="x"`) || !strings.Contains(tabRes.Evidence.DOMHTML, `onclick="`+m+`"`) {
		t.Fatalf("TAB variant post-activation DOM does not carry the injected accesskey/onclick pair: %s", tabRes.Evidence.DOMHTML)
	}

	// The space variant on the SAME page: %20 is literal text, so no onclick
	// attribute exists, no activation can reach a handler, and the marker is
	// still reflected (this is a rejection, not a missing-reflection result).
	spaceRes, err := v.Verify(context.Background(), verification.Input{
		Candidate: *spaceCand,
		Marker:    m,
		Method:    "GET",
		URL:       urlAttrReplayURL(srv.URL+"/", spaceCand.Value),
		Scope:     domain.Scope{IncludeHosts: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("verify space variant: %v", err)
	}
	if spaceRes.Report == nil {
		t.Fatal("space variant: no report")
	}
	if spaceRes.Verdict != domain.VerdictRejected {
		t.Fatalf("space variant verdict = %s, want rejected (the percent-encoded space leaves ONE attribute value); signal=%s inDOM=%v activation=%+v notes=%q",
			spaceRes.Verdict, spaceRes.Report.Signal, spaceRes.Report.MarkerInDOM, spaceRes.Report.Activation, spaceRes.Notes)
	}
	if !spaceRes.Report.MarkerInDOM {
		t.Fatal("space variant: the marker must still be reflected, otherwise this is not the measured %20 regression")
	}
	if spaceRes.Report.Signal != verification.SignalNone {
		t.Fatalf("space variant signal = %s, want none", spaceRes.Report.Signal)
	}
	if act := spaceRes.Report.Activation; act != nil && act.Status == verification.ActivationStatusDispatched {
		t.Fatalf("space variant dispatched an activation even though no handler attribute exists: %+v", act)
	}
}

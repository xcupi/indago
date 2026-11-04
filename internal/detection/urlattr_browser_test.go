package detection_test

// Real-browser proof for the URL/href attribute-breakout shape: a page that
// reflects the raw query into <link rel="canonical" href="…"> must reach a
// marker-specific page error after the verifier's single click activation, and
// the same page with an HTML-encoded delimiter must stay Rejected.
//
// These tests drive a real Chromium exactly like the pipeline does (the same
// verifier the scan executor uses) and skip — quickly — when no Chromium is
// available, matching internal/verification's integration tests. The page is a
// local httptest fixture; no real host is contacted.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

// urlAttrPage is the canonical-link fixture. %s receives the reflected value;
// the head script counts click dispatches into a data attribute on <html> so
// the test can prove the activation itself ran exactly once.
const urlAttrPage = `<!doctype html><html><head>` +
	`<link rel="canonical" href="https://lab.example/post?search=%s">` +
	`<script>document.addEventListener('click',function(){` +
	`var n=parseInt(document.documentElement.getAttribute('data-clicks')||'0',10)+1;` +
	`document.documentElement.setAttribute('data-clicks',String(n));},true);</script>` +
	`<title>Post</title></head><body><h1>Post</h1></body></html>`

// urlAttrServer serves urlAttrPage, optionally HTML-encoding the reflected
// value (the escaping control).
func urlAttrServer(t *testing.T, encoded bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		v := r.URL.Query().Get("q")
		if encoded {
			v = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(v)
		}
		fmt.Fprintf(w, urlAttrPage, v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func urlAttrChromium() string {
	if p := os.Getenv("INDAGO_CHROMIUM_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"))
	sort.Strings(matches)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func urlAttrVerifier(t *testing.T) *verification.BrowserVerifier {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := urlAttrChromium()
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	cfg := browser.Config{Headless: true, ExecutablePath: exe}
	// Chromium's process sandbox stays ON unless the operator explicitly opts
	// out here, exactly like the production default.
	if os.Getenv("INDAGO_TEST_BROWSER_NO_SANDBOX") == "1" {
		cfg.DisableSandbox = true
	}
	m, err := browser.NewManager(cfg, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return verification.NewBrowserVerifier(m, verification.BrowserVerifierConfig{})
}

// urlAttrReplayURL builds ?q=<value> the same way the pipeline does (percent
// encoded, never string-concatenated). The fixture reflects that value into the
// canonical href byte-for-byte, which is the position the raw-query injection
// point reaches on the lab; the injection point's own shape (named vs raw) does
// not change the candidate bytes that land there.
func urlAttrReplayURL(base, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	q.Set("q", value)
	u.RawQuery = q.Encode()
	return u.String()
}

// urlAttrPlanFor serves the fixture once with the probe, classifies the served
// bytes, and plans exactly as the scan's reflection step does for a raw-query
// injection point.
func urlAttrPlanFor(t *testing.T, srv *httptest.Server) *detection.CandidatePlan {
	t.Helper()
	resp, err := http.Get(urlAttrReplayURL(srv.URL+"/", urlAttrProbe.Value()))
	if err != nil {
		t.Fatalf("fetch fixture: %v", err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rep := detection.AnalyzeReflection(urlAttrProbe, nil, buf)
	detection.ClassifyContexts(&rep, buf, detection.ContextOptions{ContentType: "text/html"})
	if !rep.Reflected || len(rep.Locations) == 0 || rep.Locations[0].Context == nil {
		t.Fatalf("fixture must reflect with a classified site; reflected=%v sites=%d", rep.Reflected, len(rep.Locations))
	}
	rep.Location = domain.LocationRawQuery
	return detection.PlanCandidates(&rep, detection.PlanOptions{Marker: urlAttrProbe.Token})
}

// TestURLHrefBreakoutConfirmsAfterOneClick is the positive fixture: the planned
// shape closes the href attribute value and installs the click-class handler, so
// the verifier's single activation reaches the marker as code.
func TestURLHrefBreakoutConfirmsAfterOneClick(t *testing.T) {
	srv := urlAttrServer(t, false)
	plan := urlAttrPlanFor(t, srv)

	m := urlAttrProbe.Token
	want := `"accesskey="x" onclick=` + m + ` y="`
	if strings.Contains(want, "'") {
		t.Fatalf("the double-quote variant must not depend on a raw single quote: %q", want)
	}
	var cand *detection.Candidate
	for i := range plan.Candidates {
		if plan.Candidates[i].Value == want {
			cand = &plan.Candidates[i]
		}
	}
	if cand == nil {
		t.Fatalf("plan has no href attribute breakout %q: %+v", want, plan.Candidates)
	}

	v := urlAttrVerifier(t)
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: *cand,
		Marker:    m,
		Method:    "GET",
		URL:       urlAttrReplayURL(srv.URL+"/", cand.Value),
		Scope:     domain.Scope{IncludeHosts: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Report == nil {
		t.Fatal("no report")
	}
	if res.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; signal=%s inDOM=%v activation=%+v notes=%q",
			res.Verdict, res.Report.Signal, res.Report.MarkerInDOM, res.Report.Activation, res.Notes)
	}
	if res.Report.Signal != verification.SignalPageError {
		t.Fatalf("signal = %s, want page_error", res.Report.Signal)
	}
	act := res.Report.Activation
	if act == nil || act.Class != verification.ActivationClick || act.Status != verification.ActivationStatusDispatched {
		t.Fatalf("activation = %+v, want one dispatched click", act)
	}
	if act.Attempts != 1 || act.Method != "element.click()" {
		t.Fatalf("activation attempts/method = %d/%q, want 1/element.click()", act.Attempts, act.Method)
	}
	// The activation itself ran exactly once (the fixture's own counter), and
	// the injected attributes are really on the element.
	if !strings.Contains(res.Evidence.DOMHTML, `data-clicks="1"`) {
		t.Fatal("post-activation DOM does not show exactly one click dispatch")
	}
	if !strings.Contains(res.Evidence.DOMHTML, `accesskey="x"`) || !strings.Contains(res.Evidence.DOMHTML, `onclick="`+m+`"`) {
		t.Fatalf("post-activation DOM does not carry the injected accesskey/onclick pair: %s", res.Evidence.DOMHTML)
	}
}

// TestURLHrefBreakoutEncodedDelimiterStaysRejected is the negative control: the
// same fixture HTML-encodes the quote, so the shape is not planned (the
// delimiter can never terminate the attribute) and, forced through anyway, it
// stays Rejected — nothing observes the marker as code.
func TestURLHrefBreakoutEncodedDelimiterStaysRejected(t *testing.T) {
	srv := urlAttrServer(t, true)
	plan := urlAttrPlanFor(t, srv)
	for _, c := range plan.Candidates {
		if hrefAccesskeyBreakout(c) {
			t.Fatalf("shape planned against an encoded delimiter: %+v", c)
		}
	}

	m := urlAttrProbe.Token
	forced := detection.Candidate{
		Source:   detection.SourceBuiltin,
		Category: detection.CatURL,
		Value:    `"accesskey="x" onclick=` + m + ` y="`,
		Trigger:  detection.TriggerInteraction,
	}
	v := urlAttrVerifier(t)
	res, err := v.Verify(context.Background(), verification.Input{
		Candidate: forced,
		Marker:    m,
		Method:    "GET",
		URL:       urlAttrReplayURL(srv.URL+"/", forced.Value),
		Scope:     domain.Scope{IncludeHosts: []string{"127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %s, want rejected (encoded quotes cannot break out); notes %q", res.Verdict, res.Notes)
	}
	if res.Report == nil || !res.Report.MarkerInDOM {
		t.Fatal("the marker should still be reflected in the DOM (encoded), proving this is not a no-reflection result")
	}
	if res.Report.Signal != verification.SignalNone {
		t.Fatalf("signal = %s, want none", res.Report.Signal)
	}
}

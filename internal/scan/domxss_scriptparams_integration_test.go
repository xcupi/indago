//go:build browser_integration

package scan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

// Real Chromium. The measured lab gap: /product?productId=1 reads a parameter
// whose name appears in NO URL and NO form, so discovery never registers it.
// The DOM pass must learn `storeId` from the page's own script, test it against
// location.search, reach the document.write sink inside a <select> and confirm
// with a real browser execution signal.
const scriptParamProductPage = `<!doctype html><html><body><p>product</p><script>
var storeId = (new URLSearchParams(window.location.search)).get('storeId') || '';
document.write('<select name="' + storeId + '"><option value="1">in stock</option></select>');
</script></body></html>`

// Same read, but the value is only rendered as text: a name the page reads is
// not itself a finding, and no sink is reached.
const scriptParamReaderOnlyPage = `<!doctype html><html><body><div id="out"></div><script>
var storeId = (new URLSearchParams(window.location.search)).get('storeId') || '';
document.getElementById('out').textContent = storeId;
</script></body></html>`

// get() with a variable, not a literal: no name may be invented, so storeId
// is never tested even though the sink would execute it.
const scriptParamVariablePage = `<!doctype html><html><body><div id="out"></div><script>
var which = 'storeId';
var value = new URLSearchParams(window.location.search).get(which) || '';
document.getElementById('out').innerHTML = '<b>' + value + '</b>';
</script></body></html>`

// The read lives in a same-origin external script; the sink is inline.
const scriptParamExternalPage = `<!doctype html><html><body><p>product</p><script src="/app.js"></script><script>
document.write('<select name="' + window.storeId + '"><option value="1">in stock</option></select>');
</script></body></html>`

const scriptParamExternalJS = `window.storeId = (new URLSearchParams(window.location.search)).get('storeId') || '';`

func newScriptParamLab(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/product":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, scriptParamProductPage)
		case "/reader":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, scriptParamReaderOnlyPage)
		case "/variable":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, scriptParamVariablePage)
		case "/external":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, scriptParamExternalPage)
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript")
			io.WriteString(w, scriptParamExternalJS)
		default:
			http.NotFound(w, r)
		}
	}))
}

// runScriptParamProbe registers ONLY productId on the endpoint — the lab's real
// discovery state — and runs the location.search DOM job.
func runScriptParamProbe(t *testing.T, manager *browser.Manager, labURL, path string) (*scanEnv, *domain.Endpoint, []*domain.Finding) {
	t.Helper()
	env := newScanEnv(t)
	ep := domXSSLabEndpoint(t, env, labURL+path+"?productId=1", "text/html; charset=utf-8")
	env.param(ep, "productId", domain.LocationQuery, "1")

	ex := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, labURL), execLog(), &sync.Mutex{})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := ex.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceQuery))); err != nil {
		t.Fatalf("%s DOM query job: %v", path, err)
	}
	return env, ep, sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
}

func TestDOMXSSScriptOnlyParameterIsLearnedAndConfirmed(t *testing.T) {
	lab := newScriptParamLab(t)
	defer lab.Close()
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	env, ep, findings := runScriptParamProbe(t, manager, lab.URL, "/product")

	// The name exists only in the page's script: nothing registered it.
	params, err := env.st.Parameters().ListByEndpoint(context.Background(), ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range params {
		if p.Name == "storeId" {
			t.Fatalf("storeId must not be a discovered parameter, got %+v", p)
		}
	}

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly one storeId finding", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %s, want confirmed; title=%q summary=%q", f.Verdict, f.Title, f.Summary)
	}
	d := decodeFindingDetail(f.Detail)
	if d.ParameterName != "storeId" || d.ParameterSource != detection.ParameterSourcePageScript {
		t.Fatalf("finding must carry storeId with page-script provenance: %+v", d)
	}
	if !strings.Contains(f.Title, `parameter "storeId"`) {
		t.Fatalf("title must name storeId: %q", f.Title)
	}
	var confirmed []string
	for _, attempt := range d.Attempts {
		if attempt.Verdict == domain.VerdictConfirmed {
			confirmed = append(confirmed, attempt.CandidateValue)
			if !strings.Contains(attempt.Notes, "is not defined") {
				t.Fatalf("confirmation must carry the marker execution signal, got %q", attempt.Notes)
			}
		}
	}
	if len(confirmed) != 1 {
		t.Fatalf("confirmed attempts = %v, want exactly one", confirmed)
	}
	if !strings.Contains(confirmed[0], "><img") && !strings.Contains(confirmed[0], "<script>") {
		t.Fatalf("confirmation must come from an HTML shape, got %q", confirmed[0])
	}
	t.Logf("storeId confirmed by shape %q", confirmed[0])

	notes := ""
	for _, c := range domXSSTestCases(t, env) {
		if c.Status == domain.TestCaseFailed {
			t.Fatalf("unexpected failed test case: %s (%s)", c.Note, c.Error)
		}
		if strings.Contains(c.Note, "page-script query-name discovery") {
			notes = c.Note
		}
	}
	if !strings.Contains(notes, "storeId (inline line") {
		t.Fatalf("discovery provenance must name storeId and its inline source, got %q", notes)
	}
}

func TestDOMXSSScriptReadWithoutSinkStaysNegative(t *testing.T) {
	lab := newScriptParamLab(t)
	defer lab.Close()
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	_, _, findings := runScriptParamProbe(t, manager, lab.URL, "/reader")
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("a page that only reads and renders as text must not confirm: %q", f.Title)
		}
	}
}

func TestDOMXSSNonLiteralScriptNameIsNotInvented(t *testing.T) {
	lab := newScriptParamLab(t)
	defer lab.Close()
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	env, _, findings := runScriptParamProbe(t, manager, lab.URL, "/variable")
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			t.Fatalf("get(variable) must not yield a name, but %q confirmed", f.Title)
		}
	}
	for _, c := range domXSSTestCases(t, env) {
		if strings.Contains(c.Note, "page-script query-name discovery") {
			t.Fatalf("no name may be learned from get(variable), got note %q", c.Note)
		}
	}
}

func TestDOMXSSScriptNameFromSameOriginExternalScript(t *testing.T) {
	lab := newScriptParamLab(t)
	defer lab.Close()
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	env, _, findings := runScriptParamProbe(t, manager, lab.URL, "/external")
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("external-script name must be learned and confirmed, got %+v", findings)
	}
	d := decodeFindingDetail(findings[0].Detail)
	if d.ParameterName != "storeId" || d.ParameterSource != detection.ParameterSourcePageScript {
		t.Fatalf("external name must carry page-script provenance: %+v", d)
	}
	note := ""
	for _, c := range domXSSTestCases(t, env) {
		if strings.Contains(c.Note, "page-script query-name discovery") {
			note = c.Note
		}
	}
	if !strings.Contains(note, "/app.js") {
		t.Fatalf("discovery provenance must name the external script, got %q", note)
	}
}

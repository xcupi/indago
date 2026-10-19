//go:build browser_integration

package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// These tests pin the DOM-XSS verdict-integrity contract: Confirmed means the
// browser engine saw the bare marker identifier execute in the main frame, not
// that a page printed a convincing error or console line, and each attempt is
// isolated from every other selector's state.

func domXSSProvenanceFindings(t *testing.T, code, source string) ([]*domain.Finding, error) {
	t.Helper()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><div id="real"></div><script>const raw=decodeURIComponent(location.hash.slice(1)); const sink=document.getElementById('sink');`+code+`</script>`)
	}))
	defer lab.Close()
	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/case", domain.MethodGET)
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, source))
	return sourceSelectionFindings(t, env.st, env.scanID, ep.ID), err
}

func TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed(t *testing.T) {
	findings, err := domXSSProvenanceFindings(t, `sink.innerHTML=raw;`, "location.hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("a genuine innerHTML sink must stay Confirmed (positive control for the forgery tests): %+v", findings)
	}
}

func TestDOMXSSForgedSignalsAreNotConfirmed(t *testing.T) {
	const reflectMarker = `const m=raw.match(/onerror=([^ >]+)/);`
	scenarios := []struct {
		name string
		code string
		// wantErr: the probe must surface as an error rather than a result.
		wantErr string
	}{
		{"console error naming the marker", `sink.innerHTML=raw.replaceAll('<','&lt;');` + reflectMarker + ` if(m) console.error('ReferenceError: '+m[1]+' is not defined');`, ""},
		{"thrown ReferenceError naming the marker on a safe sink", `sink.innerHTML=raw.replaceAll('<','&lt;');` + reflectMarker + ` if(m) throw new ReferenceError(m[1]+' is not defined');`, ""},
		{"forged reachability report and thrown error without a sink", `sink.textContent=raw; console.log('__INDAGO_DOMXSS__'+JSON.stringify({sink:'innerHTML',value:raw}));` + reflectMarker + ` if(m) throw new ReferenceError(m[1]+' is not defined');`, "untested"},
		{"execution inside a child frame on a safe top-level sink", `sink.innerHTML=raw.replaceAll('<','&lt;'); const f=document.createElement('iframe'); f.srcdoc='<img src=x onerror='+((raw.match(/onerror=([^ >]+)/)||[])[1]||'undefined')+'>';document.body.appendChild(f);`, ""},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			findings, err := domXSSProvenanceFindings(t, sc.code, "location.hash")
			if sc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), sc.wantErr) {
					t.Fatalf("forged harness output must surface as an untested error containing %q, got %v", sc.wantErr, err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if len(findings) != 1 {
				// Zero findings would pass the loop below vacuously.
				t.Fatalf("the probe must complete and record exactly one non-Confirmed finding, got %d", len(findings))
			}
			for _, f := range findings {
				if f.Verdict == domain.VerdictConfirmed {
					t.Fatalf("forged signal produced a Confirmed finding: %q %s", f.Title, f.Summary)
				}
			}
		})
	}
}

// A production page that silences console.log / JSON.stringify must not turn a
// genuinely reachable sink into a silent "negative": the harness captured the
// natives before any page script ran.
func TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON(t *testing.T) {
	findings, err := domXSSProvenanceFindings(t, `console.log=function(){}; JSON.stringify=function(){return '{}'}; sink.innerHTML=raw;`, "location.hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("a page that neutralizes console.log must not hide a reachable sink: %+v", findings)
	}
}

// A string timer that throws on every tick pauses the debugger once per tick.
// The first genuine hit must not be lost to evidence budgets.
func TestDOMXSSStringTimerThrowingEveryTickStillConfirms(t *testing.T) {
	findings, err := domXSSProvenanceFindings(t, `setInterval(raw, 1);`, "location.hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("setInterval string sink that throws every tick must be Confirmed: %+v", findings)
	}
}

func TestDOMXSSStorageKeysAreIsolatedPerAttempt(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/case" {
			fmt.Fprint(w, `<!doctype html><body>neutral</body>`)
			return
		}
		// Both keys are read, but only key "a" reaches an HTML sink.
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const a=localStorage.getItem('a');const b=localStorage.getItem('b');document.getElementById('sink').innerHTML=a||'';</script>`)
	}))
	defer lab.Close()
	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/case", domain.MethodGET)
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "localStorage")); err != nil {
		t.Fatal(err)
	}
	var confirmedA bool
	for _, f := range sourceSelectionFindings(t, env.st, env.scanID, ep.ID) {
		switch decodeFindingDetail(f.Detail).ParameterName {
		case "a":
			confirmedA = confirmedA || f.Verdict == domain.VerdictConfirmed
		case "b":
			t.Fatalf("key b never reaches a sink, but a leftover payload from key a produced a %s finding: %q", f.Verdict, f.Title)
		}
	}
	if !confirmedA {
		t.Fatal("key a reaches innerHTML and must be Confirmed (positive control)")
	}
}

func TestDOMXSSFragmentRouteSelectorsAreSeparateFindings(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const p=new URLSearchParams(location.hash.split('?')[1]||'');document.getElementById('sink').innerHTML=p.get('a')||p.get('b')||'';</script>`)
	}))
	defer lab.Close()
	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/case#/search?a=&b=", domain.MethodGET)
	env.param(ep, "a", domain.LocationFragment, "")
	env.param(ep, "b", domain.LocationFragment, "")
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.hash")); err != nil {
		t.Fatal(err)
	}
	seen := map[string]domain.Verdict{}
	for _, f := range sourceSelectionFindings(t, env.st, env.scanID, ep.ID) {
		seen[decodeFindingDetail(f.Detail).ParameterName] = f.Verdict
	}
	if len(seen) != 2 || seen["a"] != domain.VerdictConfirmed || seen["b"] != domain.VerdictConfirmed {
		t.Fatalf("each fragment route parameter must be its own Confirmed finding, got %+v", seen)
	}
}

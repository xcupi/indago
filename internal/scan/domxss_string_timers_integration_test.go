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

func TestDOMSetTimeoutExecution(t *testing.T) { testDOMStringTimerExecution(t, "setTimeout") }

func TestDOMSetIntervalExecution(t *testing.T) { testDOMStringTimerExecution(t, "setInterval") }

func testDOMStringTimerExecution(t *testing.T, name string) {
	t.Helper()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>const value=decodeURIComponent(location.hash.slice(1));document.getElementById('sink').textContent=value;window[`+goQuoteJS(name)+`](value,0);</script>`)
	}))
	defer lab.Close()
	env := newScanEnv(t)
	ep := env.endpoint(lab.URL, domain.MethodGET)
	ex := newDOMXSSExecutor(env.st, mgr, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, "location.hash")); err != nil {
		t.Fatal(err)
	}
	fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("native string %s must reach and confirm; findings=%+v", name, fs)
	}
	d := decodeFindingDetail(fs[0].Detail)
	if len(d.Candidates) != 1 || string(d.Candidates[0].Context) != name || strings.ContainsAny(d.Candidates[0].Value, "<>") {
		t.Fatalf("timer provenance/payload: %+v", d)
	}
	bodies := htmlSourceMatrixEvidence(t, env, fs[0], d.Attempts[1].VerifyTestCaseID)
	if !strings.Contains(bodies[domain.EvidenceBrowserLog], "playwright: "+d.Candidates[0].Value+" is not defined") {
		t.Fatal("marker page error absent")
	}
}

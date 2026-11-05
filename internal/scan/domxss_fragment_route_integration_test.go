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

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// Real Chromium. A single-page-app route parameter inside the fragment
// (#/search?q=) must be tested and confirmed; the same route written safely
// must not be confirmed. Before this change the hash source only ever replaced
// the whole fragment, which drops the route, so the sink was unreachable.
func TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms(t *testing.T) {
	routeScript := `<div id="sink"></div><script>
var m = location.hash.match(/^#\/search\?(.*)$/);
if (m) { var q = new URLSearchParams(m[1]).get('q'); document.getElementById('sink').%s = q || ''; }
</script>`
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/vuln":
			io.WriteString(w, strings.Replace(routeScript, "%s", "innerHTML", 1))
		case "/safe":
			io.WriteString(w, strings.Replace(routeScript, "%s", "textContent", 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer lab.Close()

	ctx := context.Background()
	env := newScanEnv(t)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	// Endpoint identity as discovery stores it: route kept, query moved to params.
	vuln := env.endpoint(lab.URL+"/vuln#/search", domain.MethodGET)
	env.param(vuln, "q", domain.LocationFragment, "hello")
	exec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, vuln, string(detection.DOMSourceHash))); err != nil {
		t.Fatalf("hash route job: %v", err)
	}
	findings := sourceSelectionFindings(t, env.st, env.scanID, vuln.ID)
	if len(findings) != 1 {
		t.Fatalf("route findings = %d, want one for q", len(findings))
	}
	f := findings[0]
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("route parameter q verdict = %s, want confirmed; title=%q summary=%q", f.Verdict, f.Title, f.Summary)
	}
	detail := decodeFindingDetail(f.Detail)
	if !strings.Contains(f.Title, `parameter "q"`) || detail.ParameterName != "q" {
		t.Fatalf("finding must name parameter q: title=%q detail=%+v", f.Title, detail)
	}

	// Control: the same route rendered as text must not be confirmed.
	safe := env.endpoint(lab.URL+"/safe#/search", domain.MethodGET)
	env.param(safe, "q", domain.LocationFragment, "hello")
	safeExec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := safeExec.Handle(ctx, sourceSelectionJob(t, env.scanID, safe, string(detection.DOMSourceHash))); err != nil {
		t.Fatalf("safe route job: %v", err)
	}
	for _, sf := range sourceSelectionFindings(t, env.st, env.scanID, safe.ID) {
		if sf.Verdict == domain.VerdictConfirmed {
			t.Fatalf("safe route confirmed (false positive): title=%q", sf.Title)
		}
	}
}

func TestDOMXSSFragmentRouteCapturesPostLoadSink(t *testing.T) {
	asyncPage := `<div id="sink"></div><script>
var params = new URLSearchParams(location.hash.substring(location.hash.indexOf('?') + 1));
var q = params.get('q');
setTimeout(function () { document.getElementById('sink').%s = q || ''; }, 600);
</script>`
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		hook := "innerHTML"
		if r.URL.Path == "/safe" {
			hook = "textContent"
		}
		io.WriteString(w, strings.Replace(asyncPage, "%s", hook, 1))
	}))
	defer lab.Close()

	ctx := context.Background()
	env := newScanEnv(t)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	exec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})

	for _, path := range []string{"/async", "/safe"} {
		ep := env.endpoint(lab.URL+path+"#/search", domain.MethodGET)
		env.param(ep, "q", domain.LocationFragment, "hello")
		if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceHash))); err != nil {
			t.Fatalf("%s hash-route job: %v", path, err)
		}
		confirmed := 0
		for _, finding := range sourceSelectionFindings(t, env.st, env.scanID, ep.ID) {
			if finding.Verdict == domain.VerdictConfirmed {
				confirmed++
			}
		}
		want := 0
		if path == "/async" {
			want = 1
		}
		if confirmed != want {
			t.Fatalf("%s delayed hash-route findings confirmed=%d, want %d", path, confirmed, want)
		}
	}
}

// Real Chromium. A parameter read only by a page's inline script is discovered
// as a script literal and then confirmed by the query-source DOM test, exactly
// the DVWA xss_d shape (document.location.href.indexOf("default=")).
func TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource(t *testing.T) {
	page := `<select id="language">
<script>
if (document.location.href.indexOf("default=") >= 0) {
  var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
  document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
}
</script>
</select>`
	safePage := `<div id="sink"></div><script>
if (document.location.href.indexOf("default=") >= 0) {
  var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
  document.getElementById("sink").textContent = decodeURIComponent(lang);
}
</script>`
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/xss_d/":
			io.WriteString(w, page)
		case "/safe/":
			io.WriteString(w, safePage)
		default:
			http.NotFound(w, r)
		}
	}))
	defer lab.Close()

	ctx := context.Background()
	env := newScanEnv(t)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()

	for _, path := range []string{"/xss_d/", "/safe/"} {
		// Discovery's job for this page: read the literal names from the body.
		resp, err := http.Get(lab.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		names := discovery.ExtractScriptParamNames(string(body))
		if len(names) != 1 || names[0] != "default" {
			t.Fatalf("%s script literals = %v, want [default]", path, names)
		}
		ep := env.endpoint(lab.URL+path, domain.MethodGET)
		env.param(ep, "default", domain.LocationQuery, "English")
		exec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
		if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceQuery))); err != nil {
			t.Fatalf("query job %s: %v", path, err)
		}
		confirmed := 0
		for _, f := range sourceSelectionFindings(t, env.st, env.scanID, ep.ID) {
			if f.Verdict == domain.VerdictConfirmed {
				confirmed++
				if !strings.Contains(f.Title, `parameter "default"`) {
					t.Fatalf("%s confirmed finding must name default: %q", path, f.Title)
				}
			}
		}
		want := 0
		if path == "/xss_d/" {
			want = 1
		}
		if confirmed != want {
			t.Fatalf("%s confirmed = %d, want %d", path, confirmed, want)
		}
	}
}

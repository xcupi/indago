package discovery_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// A user seed with a single-page-app route and a query inside the fragment
// must yield: the route endpoint (not the home page), its fragment parameter as
// a DOM-only parameter, and NO HTTP injection point for it (no HTTP engine may
// ever send it).
func TestManagerRouteSeedRegistersFragmentParamWithoutInjectionPoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<div id="sink"></div>`)
	}))
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()
	seed := srv.URL + "/#/search?q=hello"
	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{seed}}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	eps, err := st.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	var route *domain.Endpoint
	for _, e := range eps {
		if e.URL == srv.URL+"/#/search?q=" {
			route = e
		}
	}
	if route == nil {
		t.Fatalf("route endpoint %s/#/search not registered; endpoints=%v", srv.URL, endpointURLs(t, st, scanID))
	}

	params, err := st.Parameters().ListByEndpoint(ctx, route.ID)
	if err != nil {
		t.Fatal(err)
	}
	var q *domain.Parameter
	for _, p := range params {
		if p.Name == "q" {
			q = p
		}
	}
	if q == nil {
		t.Fatalf("fragment parameter q not registered on the route endpoint; params=%v", params)
	}
	if q.Location != domain.LocationFragment {
		t.Errorf("q location = %q, want %q", q.Location, domain.LocationFragment)
	}

	injection, err := st.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range injection {
		if ip.ParameterID == q.ID {
			t.Fatalf("fragment parameter q produced an HTTP injection point (%s); HTTP engines would send it", ip.Location)
		}
	}
}

// A parameter read only by a page's own inline script (DVWA xss_d reads
// document.location.href.indexOf("default=")) must be discovered by the crawler.
func TestManagerCrawlDiscoversScriptReadParameter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<a href="/xss_d/">d</a>`)
	})
	mux.HandleFunc("/xss_d/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<div id="sink"></div><script>
if (document.location.href.indexOf("default=") >= 0) {
  var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
  document.getElementById("sink").innerHTML = lang;
}
</script>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := discovery.DefaultConfig()
	m, st, _ := newManagerFor(t, cfg, nil)
	scanID := domain.NewID()
	if _, err := m.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL + "/"}}); err != nil {
		t.Fatal(err)
	}
	if !hasParam(t, st, scanID, "default") {
		t.Fatalf("parameter default read only by the page script was not discovered")
	}
	ctx := context.Background()
	params, _ := st.Parameters().ListByScan(ctx, scanID)
	for _, p := range params {
		if p.Name == "default" && p.Source != domain.SourceScriptLiteral {
			t.Errorf("default source = %q, want %q", p.Source, domain.SourceScriptLiteral)
		}
	}
}

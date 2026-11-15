package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

func TestHarvestRouteAPIsReadsMenuJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"link":"#lesson/HttpBasics.lesson"},{"link":"#/account?tab=1"}]}`))
	}))
	defer srv.Close()

	scope := domain.Scope{IncludeHosts: []string{"127.0.0.1"}}
	// IncludeHosts is host-only; the test server's port is intentionally
	// ignored by scope, matching the scanner's scope model.
	eng := httpengine.NewDefault()
	n := &networkSource{engine: eng, cfg: DefaultConfig()}
	routes := n.harvestRouteAPIs(t.Context(), Input{
		Scope: scope,
	}, nil, srv.URL+"/", []browser.NetworkEvent{{URL: srv.URL + "/menu", Method: "GET"}})
	if len(routes) != 2 || routes[0] != "lesson/HttpBasics.lesson" || routes[1] != "/account?tab=1" {
		t.Fatalf("routes = %v, want two menu routes", routes)
	}
}

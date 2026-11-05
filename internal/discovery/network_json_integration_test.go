//go:build browser_integration

package discovery_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func TestIntegrationNetworkJSONBodyDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script>
setTimeout(() => fetch('/api/search', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({query:'loopback-api-marker', page:2, options:{sort:'newest'}})}), 100);
</script>`)
	})
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	br, err := browser.NewManager(browser.DefaultConfig(), quiet())
	if err != nil {
		t.Fatalf("start Chromium for loopback API test: %v", err)
	}
	defer br.Close()

	cfg := discovery.DefaultConfig()
	registry := discovery.NewRegistry()
	registry.Register(discovery.NewNetworkSource(br, cfg))
	st, q := memory.New(), queue.NewMemory()
	manager := discovery.NewManager(st, q, registry, cfg, quiet())
	scanID := domain.NewID()
	if _, err := manager.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL}}); err != nil {
		t.Fatalf("run discovery: %v", err)
	}

	endpoints, err := st.Endpoints().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	var api *domain.Endpoint
	for _, endpoint := range endpoints {
		if endpoint.URL == srv.URL+"/api/search" {
			api = endpoint
			break
		}
	}
	if api == nil || api.Method != domain.MethodPOST || api.ContentType != "application/json" {
		t.Fatalf("loopback API endpoint not discovered: %#v", api)
	}
	params, err := st.Parameters().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, param := range params {
		if param.EndpointID == api.ID && param.Location == domain.LocationJSON {
			got[param.Name] = param.Example
		}
	}
	want := map[string]string{
		"query":   `"loopback-api-marker"`,
		"page":    `2`,
		"options": `{"sort":"newest"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("loopback JSON parameters = %#v, want %#v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("JSON field %q = %q, want raw value %q", name, got[name], value)
		}
	}
}

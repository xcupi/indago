package discovery_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/httpengine"
)

// Both spec dialects must be read: OpenAPI 3 names its base in `servers`,
// Swagger 2.0 in host/basePath/schemes. Templated paths are declarations, not
// requestable URLs, so they must not be registered.
func TestWellKnownDiscoversSwaggerAndOpenAPIVariants(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"openapi": "3.0.0",
			"servers": []any{map[string]any{"url": "/v2"}},
			"paths": map[string]any{
				"/users":      map[string]any{},
				"/users/{id}": map[string]any{},
				"/health":     map[string]any{},
			},
		})
	})
	mux.HandleFunc("/swagger/v1/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"swagger":  "2.0",
			"host":     strings.TrimPrefix(srv.URL, "http://"),
			"basePath": "/api",
			"schemes":  []any{"http"},
			"paths": map[string]any{
				"/orders":            map[string]any{},
				"/orders/{id}/items": map[string]any{},
			},
		})
	})
	mux.HandleFunc("/api-docs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"paths":{}}`)) // an empty spec yields nothing
	})

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	joined := strings.Join(sink.endpointURLs(), "\n")
	for _, want := range []string{"/v2/users", "/v2/health", "/api/orders"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s from discovered endpoints: %v", want, sink.endpointURLs())
		}
	}
	if strings.Contains(joined, "{") || strings.Contains(joined, "}") {
		t.Fatalf("templated spec path registered as a literal URL: %v", sink.endpointURLs())
	}
}

// A GraphQL API is identified by what it answers, not by its path: the probe
// must be the read-only `{__typename}` query, only a GraphQL-shaped response
// may register the endpoint, and a plain JSON API that lives at /query must be
// left alone.
func TestWellKnownDiscoversGraphQLByProtocol(t *testing.T) {
	var graphQLProbes atomic.Int64
	var wrongProbe atomic.Bool

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		graphQLProbes.Add(1)
		if r.Method != http.MethodGet || r.URL.Query().Get("query") != "{__typename}" {
			wrongProbe.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	})
	// A server that answers the probe with a protocol error still speaks
	// GraphQL, and says so in the message.
	mux.HandleFunc("/v1/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"errors":[{"message":"Must provide an operation to execute."}]}`))
	})
	// A generic JSON API that happens to answer at /query: not GraphQL.
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"errors":["field required"]}`))
	})
	// /api/graphql is left unregistered and 404s.

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	got := map[string]bool{}
	for _, u := range sink.endpointURLs() {
		got[u] = true
	}
	if !hasEndpointSuffix(got, "/graphql") {
		t.Fatalf("GraphQL endpoint not discovered: %v", sink.endpointURLs())
	}
	joined := strings.Join(sink.endpointURLs(), "\n")
	if !strings.Contains(joined, "/v1/graphql") {
		t.Fatalf("GraphQL error envelope did not register the path: %v", sink.endpointURLs())
	}
	if strings.Contains(joined, "/query") || strings.Contains(joined, "/api/graphql") {
		t.Fatalf("non-GraphQL path registered as an endpoint: %v", sink.endpointURLs())
	}
	if wrongProbe.Load() {
		t.Fatal("graphql probe was not a GET {__typename} query")
	}
	if probes := graphQLProbes.Load(); probes != 1 {
		t.Fatalf("/graphql probed %d times, want exactly 1", probes)
	}
}

// hasEndpointSuffix reports whether a recorded URL ends with the given path,
// so "/graphql" does not match "/v1/graphql".
func hasEndpointSuffix(urls map[string]bool, suffix string) bool {
	for u := range urls {
		if strings.HasSuffix(u, suffix) {
			return true
		}
	}
	return false
}

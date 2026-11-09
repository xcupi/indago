package discovery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

func runSource(t *testing.T, src discovery.Source, seed string) *recordingSink {
	t.Helper()
	sink := &recordingSink{}
	info, err := discovery.Normalize(seed)
	if err != nil {
		t.Fatalf("normalize seed: %v", err)
	}
	scope := domain.Scope{IncludeHosts: []string{info.Host}}
	if err := src.Run(context.Background(), discovery.Input{SeedURLs: []string{seed}, Scope: scope}, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	return sink
}

// A security.txt and an OpenAPI document name endpoints no page links to. The
// source must add the in-scope ones and drop external hosts.
func TestWellKnownReadsSelfDescribingDocuments(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	srv = httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Contact: mailto:security@example.test\nPolicy: " + srv.URL + "/security-policy\nCanonical: " + srv.URL + "/.well-known/security.txt\nPolicy: https://elsewhere.invalid/policy\n"))
	})
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"servers": []any{map[string]any{"url": srv.URL}},
			"paths":   map[string]any{"/api/users": map[string]any{}, "/api/orders": map[string]any{}},
		})
	})

	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconStandard
	sink := runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)

	got := map[string]bool{}
	for _, u := range sink.endpointURLs() {
		got[u] = true
	}
	for _, want := range []string{"/security-policy", "/api/users", "/api/orders"} {
		found := false
		for u := range got {
			if strings.HasSuffix(u, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing endpoint %s from %v", want, got)
		}
	}
	for u := range got {
		if strings.Contains(u, "elsewhere.invalid") || strings.Contains(u, "mailto:") {
			t.Fatalf("source kept an out-of-scope value: %s", u)
		}
	}
}

// Below standard, the source must send nothing: default scans stay unchanged.
func TestWellKnownIsOffBelowStandard(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("Contact: mailto:x@example.test"))
	}))
	defer srv.Close()
	for _, level := range []discovery.ReconLevel{discovery.ReconOff, discovery.ReconSafe} {
		cfg := discovery.DefaultConfig()
		cfg.ReconLevel = level
		runSource(t, discovery.NewWellKnownSource(&countingEngine{inner: httpengine.NewDefault()}, cfg), srv.URL)
	}
	if hits != 0 {
		t.Fatalf("well-known source sent %d requests below standard", hits)
	}
}

// The archive source is aggressive-only and keeps only same-host URLs.
func TestArchiveKeepsSameHostAndNeedsAggressive(t *testing.T) {
	var queries int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries++
		if got := r.URL.Query().Get("url"); got != "target.test" {
			t.Errorf("cdx url param = %q", got)
		}
		json.NewEncoder(w).Encode([][]string{
			{"original"},
			{"http://target.test/old-admin"},
			{"http://target.test/api/v1/users?id=1"},
			{"http://other.test/nope"},
		})
	}))
	defer srv.Close()

	seed := "http://target.test/"
	cfg := discovery.DefaultConfig()
	cfg.ReconLevel = discovery.ReconAggressive
	cfg.ArchiveEndpoint = srv.URL
	// Normalize/scope need a resolvable host; the sink here records only.
	sink := &recordingSink{}
	if err := discovery.NewArchiveSource(cfg).Run(context.Background(),
		discovery.Input{SeedURLs: []string{seed}, Scope: domain.Scope{IncludeHosts: []string{"target.test"}}}, sink); err != nil {
		t.Fatalf("archive run: %v", err)
	}
	urls := sink.endpointURLs()
	if len(urls) != 2 {
		t.Fatalf("archive endpoints = %v", urls)
	}
	for _, u := range urls {
		if !strings.Contains(u, "target.test") {
			t.Fatalf("archive kept an off-host URL: %s", u)
		}
	}

	// Standard level must not query the archive at all.
	before := queries
	cfg.ReconLevel = discovery.ReconStandard
	sink2 := &recordingSink{}
	if err := discovery.NewArchiveSource(cfg).Run(context.Background(),
		discovery.Input{SeedURLs: []string{seed}, Scope: domain.Scope{IncludeHosts: []string{"target.test"}}}, sink2); err != nil {
		t.Fatal(err)
	}
	if queries != before || len(sink2.endpointURLs()) != 0 {
		t.Fatalf("archive ran below aggressive (queries %d -> %d, eps %d)", before, queries, len(sink2.endpointURLs()))
	}
}

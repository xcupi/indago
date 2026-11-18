package web_test

// An imported bug-bounty scope is origin-restricted from the start: each asset
// row names a scheme and (sometimes) a port, and Indago must not silently widen
// that to "the host on any scheme and any port". The assets below use a
// non-default port, plain http and a wildcard so the three shapes are covered
// end to end: import -> stored scope -> Permits -> draft scan creation.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func TestImportScopeIsOriginRestricted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/acme-origins", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": "acme-origins", "title": "ACME Origins", "type": "bug-bounty"})
	})
	mux.HandleFunc("/programs/acme-origins/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AUTH-TOKEN") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			// https on a non-default port.
			{"scope": "app.acme.test", "scope_type": "web-application", "asset_value": "https://app.acme.test:8443"},
			// Plain http on another port.
			{"scope": "plain.acme.test", "scope_type": "web-application", "asset_value": "http://plain.acme.test:8080"},
			// Wildcard on a non-default port; its concrete asset is a seed on the
			// same port, so the wildcard and the exact entry are both exercised.
			{"scope": "https://*.wild.acme.test:9443", "scope_type": "web-application", "asset_value": "https://app.wild.acme.test:9443"},
		}})
	})
	ywh := httptest.NewServer(mux)
	defer ywh.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := web.NewServer(st, scan.NewController(st, queue.NewMemory(), log, "test", scan.Options{}), "test", log, nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	if err := tokens.Set("tok"); err != nil {
		t.Fatal(err)
	}
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	var resp struct {
		Imported []struct {
			ProjectID string   `json:"project_id"`
			Targets   []string `json:"targets"`
			ScanIDs   []string `json:"scan_ids"`
			ScanError string   `json:"scan_error"`
			Skipped   []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"acme-origins"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if want := []string{
		"http://plain.acme.test:8080/",
		"https://app.acme.test:8443/",
		"https://app.wild.acme.test:9443/",
	}; !slices.Equal(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	// Every seed is permitted by the imported scope, so every target gets its
	// draft scan. A scheme/port mismatch here would surface as scan_error.
	sc, err := st.Scopes().GetByProject(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ScanIDs) != len(got.Targets) {
		t.Fatalf("scan_ids = %v, scan_error = %q, origins = %v; every declared origin must be permitted", got.ScanIDs, got.ScanError, sc.AllowedOrigins)
	}

	if sc.AllowAnySchemePorts {
		t.Fatal("an imported scope must not opt into the legacy any-scheme-any-port behaviour")
	}
	wantOrigins := []string{
		"http://plain.acme.test:8080",
		"https://*.wild.acme.test:9443",
		"https://app.acme.test:8443",
		"https://app.wild.acme.test:9443",
	}
	if !slices.Equal(sc.AllowedOrigins, wantOrigins) {
		t.Fatalf("allowed_origins = %v, want %v", sc.AllowedOrigins, wantOrigins)
	}

	cases := []struct {
		url  string
		want bool
		why  string
	}{
		{"https://app.acme.test:8443/", true, "declared https origin"},
		{"https://app.acme.test:8443/x", true, "declared origin, other path"},
		{"https://app.acme.test/", false, "port 443 was not declared for this asset"},
		{"http://app.acme.test:8443/", false, "scheme differs from the declared origin"},
		{"http://plain.acme.test:8080/", true, "declared plain-http origin"},
		{"https://plain.acme.test/", false, "the host is in scope but https was not declared"},
		{"https://x.wild.acme.test:9443/", true, "wildcard subdomain on the declared port"},
		{"https://a.b.wild.acme.test:9443/", true, "wildcard subdomain, deeper"},
		{"https://app.wild.acme.test:9443/", true, "the concrete asset's exact origin"},
		{"https://wild.acme.test:9443/", false, "a wildcard never covers its apex"},
		{"http://x.wild.acme.test:9443/", false, "the wildcard row declared https only"},
		{"https://x.wild.acme.test/", false, "the wildcard row declared port 9443 only"},
		{"https://x.wild.acme.test:8443/", false, "a port from the exact asset must not attach to the wildcard"},
		{"https://plain.acme.test:8080/", false, "port from plain, but https was never declared for it"},
		{"http://app.acme.test:8080/", false, "port from plain must not attach to app"},
		{"https://app.acme.test:8080/", false, "port from plain, scheme from app"},
		{"https://unrelated.test/", false, "out of scope host"},
	}
	for _, c := range cases {
		if d := sc.Permits(c.url); d.Allowed != c.want {
			t.Errorf("Permits(%q) = %v (%s), want %v (%s)", c.url, d.Allowed, d.Reason, c.want, c.why)
		}
	}
}

package web_test

// End-to-end regression for the two bug-bounty scope shapes the importer used
// to widen:
//
//   - a wildcard asset ("*.acme.test") must authorize its subdomains and NOT
//     the apex ("acme.test");
//   - an exact asset ("shop.other.test", or the concrete asset of a wildcard
//     row) must authorize that host only, never a subdomain of it.
//
// It also pins the documented default profile of an imported draft scan:
// conservative (docs/bounty.md), not balanced.

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

func TestImportWildcardScopeDoesNotAuthorizeApexOrExactSubdomains(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/acme", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": "acme", "title": "ACME Program", "type": "bug-bounty"})
	})
	mux.HandleFunc("/programs/acme/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AUTH-TOKEN") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			// Wildcard row: subdomains of acme.test are in scope, the apex is not.
			{"scope": "https://*.acme.test", "scope_type": "web-application", "asset_value": "https://app.acme.test"},
			// Exact row: this host only.
			{"scope": "shop.other.test", "scope_type": "web-application", "asset_value": "https://shop.other.test"},
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
			ProjectID          string   `json:"project_id"`
			Hosts              []string `json:"hosts"`
			SubdomainOnlyHosts []string `json:"subdomain_only_hosts"`
			Targets            []string `json:"targets"`
			ScanIDs            []string `json:"scan_ids"`
			Skipped            []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"acme"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]

	// The concrete asset of the wildcard row is already authorized by the
	// wildcard, so it is kept as an exact host and a seed; the apex never is.
	if want := []string{"app.acme.test", "shop.other.test"}; !slices.Equal(got.Hosts, want) {
		t.Errorf("hosts = %v, want %v", got.Hosts, want)
	}
	if want := []string{"acme.test"}; !slices.Equal(got.SubdomainOnlyHosts, want) {
		t.Errorf("subdomain_only_hosts = %v, want %v", got.SubdomainOnlyHosts, want)
	}
	if want := []string{"https://app.acme.test/", "https://shop.other.test/"}; !slices.Equal(got.Targets, want) {
		t.Errorf("targets = %v, want %v", got.Targets, want)
	}
	if len(got.ScanIDs) != 2 {
		t.Fatalf("scan_ids = %v, want one draft per target", got.ScanIDs)
	}

	sc, err := st.Scopes().GetByProject(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	if sc.AllowSubdomains {
		t.Fatal("imported scope has allow_subdomains set; an import must never widen an exact asset")
	}
	if want := []string{"app.acme.test", "shop.other.test"}; !slices.Equal(sc.IncludeHosts, want) {
		t.Errorf("scope include_hosts = %v, want %v", sc.IncludeHosts, want)
	}
	if want := []string{"acme.test"}; !slices.Equal(sc.SubdomainOnlyHosts, want) {
		t.Errorf("scope subdomain_only_hosts = %v, want %v", sc.SubdomainOnlyHosts, want)
	}

	permits := []struct {
		url  string
		want bool
		why  string
	}{
		{"https://app.acme.test/", true, "concrete asset of the wildcard row"},
		{"https://x.acme.test/", true, "wildcard subdomain"},
		{"https://a.b.acme.test/", true, "wildcard subdomain, deeper"},
		{"https://acme.test/", false, "wildcard never includes the apex"},
		{"https://a.app.acme.test/", true, "the wildcard covers every depth, including names under its concrete asset"},
		{"https://shop.other.test/", true, "exact asset"},
		{"https://x.shop.other.test/", false, "an exact asset does not authorize its subdomains"},
		{"https://other.test/", false, "unrelated host"},
		{"https://evilexample.test/", false, "dot boundary"},
	}
	for _, c := range permits {
		if d := sc.Permits(c.url); d.Allowed != c.want {
			t.Errorf("Permits(%q) = %v (%s), want %v (%s)", c.url, d.Allowed, d.Reason, c.want, c.why)
		}
	}

	// The draft scan is the documented conservative preset.
	for _, scanID := range got.ScanIDs {
		rec, err := st.Scans().Get(context.Background(), domain.ID(scanID))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Profile != domain.ProfileConservative {
			t.Errorf("scan %s profile = %q, want conservative", scanID, rec.Profile)
		}
		if rec.Config.RequestsPerSecond != 2 {
			t.Errorf("scan %s requests_per_second = %v, want the conservative 2", scanID, rec.Config.RequestsPerSecond)
		}
	}
}

package web_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func TestBountyMultiProviderTokensAndList(t *testing.T) {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	h1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/hackers/programs":
			w.Write([]byte(`{
				"data":[{
					"id":"1",
					"type":"program",
					"attributes":{"handle":"acme","name":"ACME Corp","state":"public_mode","submission_state":"open","offers_bounties":true}
				}],
				"meta":{"total_count":1}
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer h1.Close()
	t.Setenv("INDAGO_HACKERONE_API", h1.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	// 1. GET /api/bounty/providers lists all 4 providers in order.
	var provResp struct {
		Providers []struct {
			ID           string `json:"id"`
			Label        string `json:"label"`
			Configured   bool   `json:"configured"`
			PublicBrowse bool   `json:"public_browse"`
			Note         string `json:"note"`
		} `json:"providers"`
	}
	a.mustJSON(a.do("GET", "/api/bounty/providers", nil), http.StatusOK, &provResp)
	if len(provResp.Providers) != 4 {
		t.Fatalf("providers count = %d, want 4", len(provResp.Providers))
	}
	wantIDs := []string{"yeswehack", "hackerone", "bugcrowd", "intigriti"}
	for i, wantID := range wantIDs {
		p := provResp.Providers[i]
		if p.ID != wantID {
			t.Fatalf("provider[%d].ID = %q, want %q", i, p.ID, wantID)
		}
		if p.Configured {
			t.Fatalf("provider %q should start unconfigured", p.ID)
		}
		if p.PublicBrowse != (wantID == "yeswehack") {
			t.Fatalf("provider %q PublicBrowse = %v", p.ID, p.PublicBrowse)
		}
		if p.Note == "" {
			t.Fatalf("provider %q Note must not be empty", p.ID)
		}
	}

	// 2. Listing HackerOne programs before configuring a token fails with 401.
	res := a.do("GET", "/api/bounty/programs?provider=hackerone", nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unconfigured hackerone programs status = %d, want 401", res.Code)
	}

	// 3. Invalid token is rejected with 400.
	res = a.do("PUT", "/api/bounty/providers/hackerone/token", map[string]any{"token": "bad:tok"})
	if res.Code != http.StatusBadRequest {
		t.Fatalf("invalid hackerone token status = %d, want 400", res.Code)
	}

	// 4. Unknown provider is rejected with 400.
	res = a.do("PUT", "/api/bounty/providers/unknown/token", map[string]any{"token": "tok"})
	if res.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider token status = %d, want 400", res.Code)
	}

	// 5. Valid token is stored and reflected by /api/bounty/providers.
	var setResp struct {
		Configured bool   `json:"configured"`
		Provider   string `json:"provider"`
	}
	a.mustJSON(a.do("PUT", "/api/bounty/providers/hackerone/token", map[string]any{"token": "user:secret"}), http.StatusOK, &setResp)
	if !setResp.Configured || setResp.Provider != "hackerone" {
		t.Fatalf("setResp = %+v", setResp)
	}

	a.mustJSON(a.do("GET", "/api/bounty/providers", nil), http.StatusOK, &provResp)
	if !provResp.Providers[1].Configured || provResp.Providers[0].Configured {
		t.Fatalf("providers after set = %+v", provResp.Providers)
	}

	// 6. GET /api/bounty/programs?provider=hackerone returns HackerOne programs.
	var listResp struct {
		Provider string           `json:"provider"`
		Count    int              `json:"count"`
		Items    []bounty.Program `json:"items"`
	}
	a.mustJSON(a.do("GET", "/api/bounty/programs?provider=hackerone", nil), http.StatusOK, &listResp)
	if listResp.Provider != "hackerone" || listResp.Count != 1 || len(listResp.Items) != 1 {
		t.Fatalf("listResp = %+v", listResp)
	}
	if listResp.Items[0].Slug != "acme" || listResp.Items[0].Title != "ACME Corp" {
		t.Fatalf("item[0] = %+v", listResp.Items[0])
	}

	// 7. DELETE /api/bounty/providers/hackerone/token clears the token.
	var clrResp struct {
		Configured bool   `json:"configured"`
		Provider   string `json:"provider"`
	}
	a.mustJSON(a.do("DELETE", "/api/bounty/providers/hackerone/token", nil), http.StatusOK, &clrResp)
	if clrResp.Configured || clrResp.Provider != "hackerone" {
		t.Fatalf("clrResp = %+v", clrResp)
	}
	if tokens.ConfiguredFor(bounty.ProviderHackerOne) {
		t.Fatal("hackerone token should be cleared")
	}
}

func TestImportBountyProgramHackerOne(t *testing.T) {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	h1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/hackers/programs/acme":
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"id":   "1",
					"type": "program",
					"attributes": map[string]any{
						"handle":           "acme",
						"name":             "ACME Corp",
						"state":            "public_mode",
						"submission_state": "open",
						"offers_bounties":  true,
					},
					"relationships": map[string]any{
						"structured_scopes": map[string]any{
							"data": []map[string]any{
								{
									"id":   "s1",
									"type": "structured-scope",
									"attributes": map[string]any{
										"asset_type":              "URL",
										"asset_identifier":        "https://app.acme.test",
										"eligible_for_submission": true,
									},
								},
								{
									"id":   "s2",
									"type": "structured-scope",
									"attributes": map[string]any{
										"asset_type":              "WILDCARD",
										"asset_identifier":        "https://*.acme.test",
										"eligible_for_submission": true,
									},
								},
								{
									"id":   "s3",
									"type": "structured-scope",
									"attributes": map[string]any{
										"asset_type":              "URL",
										"asset_identifier":        "https://oos.example.test",
										"eligible_for_submission": false,
									},
								},
							},
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer h1.Close()
	t.Setenv("INDAGO_HACKERONE_API", h1.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	if err := tokens.SetFor(bounty.ProviderHackerOne, "user:secret"); err != nil {
		t.Fatal(err)
	}
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	var resp struct {
		Imported []struct {
			Slug               string   `json:"slug"`
			Title              string   `json:"title"`
			ProjectID          string   `json:"project_id"`
			Hosts              []string `json:"hosts"`
			SubdomainOnlyHosts []string `json:"subdomain_only_hosts"`
			Targets            []string `json:"targets"`
			Skipped            []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{
		"provider": "hackerone",
		"slugs":    []string{"acme"},
	}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID == "" || got.Title != "ACME Corp" {
		t.Fatalf("got = %+v", got)
	}
	if len(got.Hosts) != 1 || got.Hosts[0] != "app.acme.test" {
		t.Fatalf("hosts = %v, want [app.acme.test]", got.Hosts)
	}
	if len(got.SubdomainOnlyHosts) != 1 || got.SubdomainOnlyHosts[0] != "acme.test" {
		t.Fatalf("subdomain_only_hosts = %v, want [acme.test]", got.SubdomainOnlyHosts)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://app.acme.test/" {
		t.Fatalf("targets = %v, want [https://app.acme.test/]", got.Targets)
	}

	proj, err := st.Projects().Get(context.Background(), domain.ID(got.ProjectID))
	if err != nil || proj.Name != "ACME Corp" {
		t.Fatalf("project = %+v err=%v", proj, err)
	}
	sc, err := st.Scopes().GetByProject(context.Background(), proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := sc.Permits("https://app.acme.test/login"); !d.Allowed {
		t.Fatalf("imported scope denies its own host: %+v", d)
	}
	if d := sc.Permits("https://sub.acme.test/"); !d.Allowed {
		t.Fatalf("imported scope denies wildcard subdomain: %+v", d)
	}
	if d := sc.Permits("https://oos.example.test/"); d.Allowed {
		t.Fatal("ineligible asset was not excluded")
	}
	if d := sc.Permits("https://other.test/"); d.Allowed {
		t.Fatal("imported scope allows an unrelated host")
	}

	// Re-importing the same program skips with existing project ID.
	var second struct {
		Imported []struct {
			ProjectID string   `json:"project_id"`
			Skipped   []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{
		"provider": "hackerone",
		"slugs":    []string{"acme"},
	}), http.StatusOK, &second)
	if len(second.Imported) != 1 || second.Imported[0].ProjectID != got.ProjectID {
		t.Fatalf("duplicate import = %+v", second.Imported)
	}
}

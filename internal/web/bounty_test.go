package web_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

// Importing a program must create a project whose scope is the program's own
// web-application assets, plus one draft scan for the first in-scope target.
func TestImportBountyProgramCreatesScopedProject(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/acme", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": "acme", "title": "ACME Program", "type": "bug-bounty", "rules": "Add header X-Bug-Bounty"})
	})
	mux.HandleFunc("/programs/acme/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AUTH-TOKEN") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			{"scope": "*.acme.test", "scope_type": "web-application", "asset_value": "https://app.acme.test"},
			{"scope": "api.acme.test", "scope_type": "api", "asset_value": "https://api.acme.test"},
		}})
	})
	ywh := httptest.NewServer(mux)
	defer ywh.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	if err := tokens.Set("tok"); err != nil {
		t.Fatal(err)
	}
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	var resp struct {
		Imported []struct {
			Slug      string   `json:"slug"`
			ProjectID string   `json:"project_id"`
			Hosts     []string `json:"hosts"`
			Targets   []string `json:"targets"`
			Skipped   []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"acme"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID == "" || len(got.Hosts) != 1 || got.Hosts[0] != "app.acme.test" {
		t.Fatalf("hosts = %v (api scope must be skipped)", got.Hosts)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://app.acme.test/" {
		t.Fatalf("targets = %v", got.Targets)
	}
	if len(got.Skipped) != 1 {
		t.Fatalf("skipped = %v", got.Skipped)
	}

	// The project and its scope exist; the scope allows the imported host and
	// denies another one.
	proj, err := st.Projects().Get(context.Background(), domain.ID(got.ProjectID))
	if err != nil || proj.Name != "ACME Program" {
		t.Fatalf("project = %+v err=%v", proj, err)
	}
	sc, err := st.Scopes().GetByProject(context.Background(), proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d := sc.Permits("https://app.acme.test/login"); !d.Allowed {
		t.Fatalf("imported scope denies its own host: %+v", d)
	}
	if d := sc.Permits("https://other.test/"); d.Allowed {
		t.Fatal("imported scope allows an unrelated host")
	}
}

func TestBountyProgramsAreNotFetchedImplicitly(t *testing.T) {
	var calls int
	ywh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"items":[]}`))
	}))
	defer ywh.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	srv.SetBountyStore(bounty.NewStore(t.TempDir()))
	a := api{t: t, h: srv.Handler(), st: st}

	// Providers endpoint is configuration only: it must not contact the API.
	var prov struct {
		Providers []struct {
			ID         string `json:"id"`
			Configured bool   `json:"configured"`
		} `json:"providers"`
	}
	a.mustJSON(a.do("GET", "/api/bounty/providers", nil), http.StatusOK, &prov)
	if calls != 0 {
		t.Fatalf("providers endpoint contacted the platform %d times", calls)
	}
	if len(prov.Providers) != 1 || prov.Providers[0].ID != "yeswehack" || prov.Providers[0].Configured {
		t.Fatalf("providers = %+v", prov.Providers)
	}

	// The explicit Load path does contact it.
	var list struct {
		Count int `json:"count"`
	}
	a.mustJSON(a.do("GET", "/api/bounty/programs?refresh=1", nil), http.StatusOK, &list)
	if calls != 1 {
		t.Fatalf("programs endpoint calls = %d, want 1", calls)
	}
}

// Hunter accounts cannot create a token; import must work from the public
// program page, where asset_value is the severity and scope is the asset.
func TestImportUsesPublicScopesWithoutToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/acme", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": "acme", "title": "ACME Program", "type": "bug-bounty"})
	})
	ywh := httptest.NewServer(mux)
	defer ywh.Close()

	webStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/programs/acme" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`<script>state = {"scopes":[{"scope":"https://shop.acme.test","scope_type":"web-application","asset_value":"MEDIUM"},{"scope":"api.acme.test","scope_type":"api","asset_value":"HIGH"}]}</script>`))
	}))
	defer webStub.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)
	t.Setenv("INDAGO_YESWEHACK_WEB", webStub.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	srv.SetBountyStore(bounty.NewStore(t.TempDir())) // no token
	a := api{t: t, h: srv.Handler(), st: st}

	var resp struct {
		Imported []struct {
			ProjectID string   `json:"project_id"`
			Hosts     []string `json:"hosts"`
			Targets   []string `json:"targets"`
			Skipped   []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"acme"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if len(got.Hosts) != 1 || got.Hosts[0] != "shop.acme.test" {
		t.Fatalf("hosts = %v (severity must never become a host)", got.Hosts)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://shop.acme.test/" {
		t.Fatalf("targets = %v", got.Targets)
	}
	if len(got.Skipped) != 1 {
		t.Fatalf("skipped = %v", got.Skipped)
	}
}

// A program asset can be a path, not just a host. The imported scope must
// restrict to that path and the seed target must be the asset itself.
func TestImportKeepsPathScopedAsset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/pathprog", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": "pathprog", "title": "Path Program", "type": "bug-bounty"})
	})
	ywh := httptest.NewServer(mux)
	defer ywh.Close()
	webStub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script>state={"scopes":[{"scope":"https://target.test/challenge/one","scope_type":"web-application","asset_value":"MEDIUM"}]}</script>`))
	}))
	defer webStub.Close()
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)
	t.Setenv("INDAGO_YESWEHACK_WEB", webStub.URL)

	st := memory.New()
	srv := web.NewServer(st, nil, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), nil, t.TempDir())
	srv.SetBountyStore(bounty.NewStore(t.TempDir()))
	a := api{t: t, h: srv.Handler(), st: st}

	var resp struct {
		Imported []struct {
			ProjectID string   `json:"project_id"`
			Targets   []string `json:"targets"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"pathprog"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if len(got.Targets) != 1 || got.Targets[0] != "https://target.test/challenge/one" {
		t.Fatalf("targets = %v", got.Targets)
	}
	sc, err := st.Scopes().GetByProject(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.IncludePathPrefixes) != 1 || sc.IncludePathPrefixes[0] != "/challenge/one" {
		t.Fatalf("include paths = %v", sc.IncludePathPrefixes)
	}
	if d := sc.Permits("https://target.test/challenge/one/page"); !d.Allowed {
		t.Fatalf("asset path denied: %+v", d)
	}
	if d := sc.Permits("https://target.test/other"); d.Allowed {
		t.Fatal("scope allowed a path outside the program asset")
	}
}

func TestImportCreatesBalancedScanWithUsableDefaults(t *testing.T) {
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
			{"scope": "app.acme.test", "scope_type": "web-application", "asset_value": "https://app.acme.test"},
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
			ScanID    string `json:"scan_id"`
			ScanError string `json:"scan_error"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"acme"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 || resp.Imported[0].ScanID == "" {
		t.Fatalf("import = %+v, want a created scan", resp.Imported)
	}
	sc, err := st.Scans().Get(context.Background(), domain.ID(resp.Imported[0].ScanID))
	if err != nil {
		t.Fatal(err)
	}
	if sc.Profile != domain.ProfileBalanced {
		t.Fatalf("profile = %q, want balanced", sc.Profile)
	}
	if sc.Config.MaxDepth != 3 || sc.Config.MaxPages != 200 || sc.Config.MaxEndpoints != 500 {
		t.Fatalf("crawl defaults = depth %d pages %d endpoints %d, want 3/200/500",
			sc.Config.MaxDepth, sc.Config.MaxPages, sc.Config.MaxEndpoints)
	}
	if sc.Config.CandidateProfile != "standard" || sc.Config.MaxCandidates != 8 {
		t.Fatalf("candidate defaults = %q/%d, want standard/8", sc.Config.CandidateProfile, sc.Config.MaxCandidates)
	}
	if sc.State != domain.ScanCreated {
		t.Fatalf("state = %q, want an unstarted draft", sc.State)
	}
}

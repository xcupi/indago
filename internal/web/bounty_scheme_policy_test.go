package web_test

// An imported scope is origin-restricted from the first request, so the importer
// must read the scheme from the program's own asset row and never guess one:
//
//   - a row that states http(s) contributes exactly that origin (existing
//     coverage lives in bounty_origins_test.go);
//   - a WILDCARD row with no scheme is skipped as a whole — it is never
//     downgraded to its asset_value host by falling through to the exact-asset
//     reader, which would silently narrow a wildcard authorization into a
//     single host and hide the problem;
//   - a bare host with no scheme is skipped, because "https on 443" is not in
//     the source;
//   - if every row is unusable, no project is created and the reasons are
//     reported instead of an origin-less (any scheme/any port) scope.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

type importedProgramDTO struct {
	ProjectID string   `json:"project_id"`
	Hosts     []string `json:"hosts"`
	Targets   []string `json:"targets"`
	Skipped   []string `json:"skipped"`
}

type importResponseDTO struct {
	Imported []importedProgramDTO `json:"imported"`
}

// importProgram serves one program's scopes and runs the import through the real
// HTTP handler, returning the decoded response and the store it wrote to.
func importProgram(t *testing.T, slug string, items []map[string]any) (importResponseDTO, *memory.Store) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/"+slug, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": slug, "title": "ACME " + slug, "type": "bug-bounty"})
	})
	mux.HandleFunc("/programs/"+slug+"/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AUTH-TOKEN") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	})
	ywh := httptest.NewServer(mux)
	t.Cleanup(ywh.Close)
	t.Setenv("INDAGO_YESWEHACK_API", ywh.URL)

	st := memory.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := web.NewServer(st, nil, "test", log, nil, t.TempDir())
	tokens := bounty.NewStore(t.TempDir())
	if err := tokens.Set("tok"); err != nil {
		t.Fatal(err)
	}
	srv.SetBountyStore(tokens)
	a := api{t: t, h: srv.Handler(), st: st}

	var resp importResponseDTO
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{slug}}), http.StatusOK, &resp)
	return resp, st
}

func TestImportNeverGuessesAScheme(t *testing.T) {
	resp, st := importProgram(t, "scheme-policy", []map[string]any{
		// Wildcard with no scheme: unusable even though asset_value states one.
		{"scope": "*.noscheme.test", "scope_type": "web-application", "asset_value": "https://app.noscheme.test"},
		// Bare host with no scheme and no scheme anywhere in the row.
		{"scope": "bare.noscheme.test", "scope_type": "web-application", "asset_value": "MEDIUM"},
		// The one row that states its scheme is imported exactly.
		{"scope": "https://ok.test", "scope_type": "web-application", "asset_value": "MEDIUM"},
	})
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if want := []string{"ok.test"}; !slices.Equal(got.Hosts, want) {
		t.Fatalf("hosts = %v, want %v (a row with no scheme authorizes no host)", got.Hosts, want)
	}
	joined := strings.Join(got.Skipped, "\n")
	for _, want := range []string{
		"wildcard asset states no http(s) scheme",
		"asset states no http(s) scheme",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped = %v, want a reason containing %q", got.Skipped, want)
		}
	}

	sc, err := st.Scopes().GetByProject(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://ok.test"}; !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want exactly %v", sc.AllowedOrigins, want)
	}
	if sc.AllowAnySchemePorts {
		t.Fatal("an import must never opt into the legacy any-scheme-any-port behaviour")
	}
	if d := sc.Permits("http://ok.test/"); d.Allowed {
		t.Fatalf("the imported scope authorized plain http on a host declared https: %+v", d)
	}
	if d := sc.Permits("https://ok.test/"); !d.Allowed {
		t.Fatalf("the declared origin was denied: %+v", d)
	}
}

func TestImportRefusesAProgramWithNoStatedScheme(t *testing.T) {
	resp, st := importProgram(t, "no-scheme", []map[string]any{
		{"scope": "*.noscheme.test", "scope_type": "web-application", "asset_value": "https://app.noscheme.test"},
		{"scope": "bare.noscheme.test", "scope_type": "web-application", "asset_value": "HIGH"},
	})
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID != "" {
		t.Fatalf("a program with no stated scheme created project %q", got.ProjectID)
	}
	if len(got.Skipped) == 0 {
		t.Fatal("the skip reasons are missing")
	}
	projects, err := st.Projects().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 0 {
		t.Fatalf("projects = %+v, want none", projects)
	}
}

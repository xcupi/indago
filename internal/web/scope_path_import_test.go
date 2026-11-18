package web_test

// Import-time regression: a program asset whose path encodes traversal must be
// skipped, not stored as a scope prefix. Storing the host without a usable
// prefix would widen the imported scope to the whole host.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

func TestImportSkipsAmbiguousAssetPathAndKeepsValidPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/programs/pathprog", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"slug": "pathprog", "title": "Path Program", "type": "bug-bounty",
		})
	})
	mux.HandleFunc("/programs/pathprog/scopes", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AUTH-TOKEN") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{
			// Must be skipped: the decoded path is /app/../admin.
			{"scope": "https://app.example/app/%2e%2e/admin", "scope_type": "web-application", "asset_value": "MEDIUM"},
			// Must be skipped: encoded slash.
			{"scope": "https://app.example/app%2fadmin", "scope_type": "web-application", "asset_value": "MEDIUM"},
			// Must be skipped: double-encoded dot.
			{"scope": "https://app.example/app/%252e%252e/admin", "scope_type": "web-application", "asset_value": "MEDIUM"},
			// Must survive and remain the only stored prefix.
			{"scope": "https://app.example/app/", "scope_type": "web-application", "asset_value": "MEDIUM"},
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
			ProjectID string   `json:"project_id"`
			Hosts     []string `json:"hosts"`
			Targets   []string `json:"targets"`
			Skipped   []string `json:"skipped"`
		} `json:"imported"`
	}
	a.mustJSON(a.do("POST", "/api/bounty/import", map[string]any{"slugs": []string{"pathprog"}}), http.StatusOK, &resp)
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID == "" {
		t.Fatalf("valid asset should create a project, got %+v", got)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://app.example/app/" {
		t.Fatalf("targets = %v, want the valid path asset only", got.Targets)
	}
	skipCount := 0
	for _, reason := range got.Skipped {
		if strings.Contains(reason, "canonical scope path") {
			skipCount++
		}
	}
	if skipCount != 3 {
		t.Fatalf("skipped = %v, want three ambiguous-path reasons", got.Skipped)
	}

	proj, err := st.Projects().Get(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	sc, err := st.Scopes().GetByProject(context.Background(), proj.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.IncludePathPrefixes) != 1 || sc.IncludePathPrefixes[0] != "/app/" {
		t.Fatalf("stored prefixes = %v, want only /app/", sc.IncludePathPrefixes)
	}
	if d := sc.Permits("https://app.example/app/page"); !d.Allowed {
		t.Fatalf("valid imported path denied: %+v", d)
	}
	if d := sc.Permits("https://app.example/outside"); d.Allowed {
		t.Fatal("imported scope allowed the host root outside the asset path")
	}
	if d := sc.Permits("https://app.example/app/%2e%2e/outside"); d.Allowed {
		t.Fatal("imported scope allowed encoded traversal")
	}
}

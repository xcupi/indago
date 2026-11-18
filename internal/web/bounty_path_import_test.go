package web_test

// End-to-end import of path-scoped assets.
//
// A project scope has ONE global include_path_prefixes list, so an import that
// binds different paths to different hosts/origins cannot be stored without
// authorizing the cross product. The importer refuses such a program instead:
// no project, no scope, no scan, and the reason is reported to the caller (the
// UI shows it in the import summary). A program whose origins all share the
// same path is imported exactly.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestImportRefusesCrossHostPathBindings(t *testing.T) {
	resp, st := importProgram(t, "cross-paths", []map[string]any{
		{"scope": "https://a.test/app", "scope_type": "web-application", "asset_value": "MEDIUM"},
		{"scope": "https://b.test/api", "scope_type": "web-application", "asset_value": "MEDIUM"},
	})
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID != "" {
		t.Fatalf("a cross-host path program created project %q", got.ProjectID)
	}
	if len(got.Hosts) != 0 || len(got.Targets) != 0 {
		t.Fatalf("a refused import returned hosts %v targets %v", got.Hosts, got.Targets)
	}
	joined := strings.Join(got.Skipped, "\n")
	for _, want := range []string{"apply to every host", "https://a.test is scoped to /app", "https://b.test is scoped to /api"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped = %v, want a reason containing %q", got.Skipped, want)
		}
	}
	projects, err := st.Projects().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 0 {
		t.Fatalf("projects = %+v, want none", projects)
	}
}

func TestImportKeepsASharedPathExactly(t *testing.T) {
	resp, st := importProgram(t, "shared-path", []map[string]any{
		{"scope": "https://a.test/app", "scope_type": "web-application", "asset_value": "MEDIUM"},
		{"scope": "https://b.test/app", "scope_type": "web-application", "asset_value": "MEDIUM"},
	})
	if len(resp.Imported) != 1 {
		t.Fatalf("imported = %+v", resp.Imported)
	}
	got := resp.Imported[0]
	if got.ProjectID == "" {
		t.Fatalf("a representable program was not imported: %v", got.Skipped)
	}
	sc, err := st.Scopes().GetByProject(context.Background(), domain.ID(got.ProjectID))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/app"}; !slices.Equal(sc.IncludePathPrefixes, want) {
		t.Fatalf("include_path_prefixes = %v, want %v", sc.IncludePathPrefixes, want)
	}
	// Exactly the authorized origin+path pairs, and nothing else.
	for _, u := range []string{"https://a.test/app", "https://b.test/app", "https://a.test/app/x"} {
		if d := sc.Permits(u); !d.Allowed {
			t.Errorf("Permits(%q) denied (%s), want allowed", u, d.Reason)
		}
	}
	for _, u := range []string{
		"https://a.test/api", "https://b.test/api",
		"https://a.test/", "https://b.test/",
		"http://a.test/app",
	} {
		if d := sc.Permits(u); d.Allowed {
			t.Errorf("Permits(%q) allowed, want denied", u)
		}
	}
}

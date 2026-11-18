package web_test

// The project-scope API is how an operator edits what a scan may touch, so the
// wildcard list has to behave like the rest of the scope:
//
//   - a PUT that omits subdomain_only_hosts keeps it (the bundled UI does not
//     render the field yet, and saving the form must not silently drop an
//     imported program's wildcard authorization);
//   - an explicit empty array clears it;
//   - a wildcard-only scope is saveable (no include hosts, one wildcard host);
//   - spellings that would be reinterpreted are refused.

import (
	"slices"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestScopeSubdomainOnlyHostsAPI(t *testing.T) {
	a := newAPI(t, nil)
	var p map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "p"}), 201, &p)
	pid := p["id"].(string)

	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":        []string{"www.example.com"},
		"subdomain_only_hosts": []string{"example.com"},
		// The scheme/port statement is explicit: the exact host on https, and
		// the wildcard on https for the subdomains-only list.
		"allowed_origins": []string{"https://www.example.com", "https://*.example.com"},
	}), 201, &sc)
	if want := []string{"www.example.com"}; !slices.Equal(sc.IncludeHosts, want) {
		t.Fatalf("include_hosts = %v, want %v", sc.IncludeHosts, want)
	}
	if want := []string{"example.com"}; !slices.Equal(sc.SubdomainOnlyHosts, want) {
		t.Fatalf("subdomain_only_hosts = %v, want %v", sc.SubdomainOnlyHosts, want)
	}

	// A plain UI save (no subdomain_only_hosts field) must preserve it.
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"www.example.com"},
	}), 200, &sc)
	if want := []string{"example.com"}; !slices.Equal(sc.SubdomainOnlyHosts, want) {
		t.Fatalf("omitted field cleared the wildcard list: %v", sc.SubdomainOnlyHosts)
	}

	// An explicit empty array clears it.
	var cleared domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":        []string{"www.example.com"},
		"subdomain_only_hosts": []string{},
	}), 200, &cleared)
	if len(cleared.SubdomainOnlyHosts) != 0 {
		t.Fatalf("explicit empty array did not clear the list: %v", cleared.SubdomainOnlyHosts)
	}

	// A wildcard-only scope is a real scope: no include hosts, one wildcard.
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":        []string{},
		"subdomain_only_hosts": []string{"example.com"},
		"allowed_origins":      []string{"https://*.example.com"},
	}), 200, &sc)
	if d := sc.Permits("https://a.example.com/"); !d.Allowed {
		t.Fatalf("wildcard-only scope denies its subdomain: %+v", d)
	}
	if d := sc.Permits("https://example.com/"); d.Allowed {
		t.Fatal("wildcard-only scope allowed the apex")
	}

	// Both shapes are still required to be spellable: an entry that would be
	// reinterpreted is refused and the previous scope stays.
	for _, entry := range []string{".example.com", "*.example.com", "https://example.com"} {
		if rec := a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
			"subdomain_only_hosts": []string{entry},
		}); rec.Code != 400 {
			t.Errorf("subdomain_only_hosts %q: status %d, want 400 (%s)", entry, rec.Code, rec.Body.String())
		}
	}
	var after domain.Scope
	a.mustJSON(a.do("GET", "/api/projects/"+pid+"/scope", nil), 200, &after)
	if want := []string{"example.com"}; !slices.Equal(after.SubdomainOnlyHosts, want) {
		t.Fatalf("a rejected save changed the scope: %v", after.SubdomainOnlyHosts)
	}
}

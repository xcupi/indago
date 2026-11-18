package web_test

// The project-scope API is where an operator declares what a scan may touch, so
// the scheme/port rules are part of that contract:
//
//   - an origin list is an operator STATEMENT. A save never derives one, so a
//     new scope must name the origins it may reach or explicitly choose the
//     legacy any-scheme/any-port behaviour;
//   - every stored entry keeps its exact scheme and port across saves: editing
//     a path prefix, an exclusion, or an unrelated field can never widen an
//     https-only scope to plain http or to another port (the regression this
//     file exists for);
//   - adding a host never authorizes it on a guessed scheme/port: the save is
//     refused and names the host until the operator declares its origin;
//   - a stored legacy scope (no origin list, saved before this feature) keeps
//     its behaviour on a save that grants no new authority, and displays as
//     legacy instead of pretending a rule exists;
//   - a shape that cannot mean an origin is refused with a 400 that names the
//     field, and the previous scope stays.

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func newOriginProject(t *testing.T) (api, string) {
	t.Helper()
	a := newAPI(t, nil)
	var p map[string]any
	a.mustJSON(a.do("POST", "/api/projects", map[string]string{"name": "origins"}), 201, &p)
	return a, p["id"].(string)
}

func getScope(t *testing.T, a api, projectID string) domain.Scope {
	t.Helper()
	var sc domain.Scope
	a.mustJSON(a.do("GET", "/api/projects/"+projectID+"/scope", nil), 200, &sc)
	return sc
}

func TestScopeAPINewScopeNeverGuessesSchemePort(t *testing.T) {
	a, pid := newOriginProject(t)
	// A brand-new scope with hosts but no policy is refused: "no origins" means
	// "every scheme and port" to the matcher, so accepting it would authorize
	// far more than the host list says.
	code, body := scopePut(a, pid, map[string]any{"include_hosts": []string{"app.example.com"}})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (%s)", code, body)
	}
	if !strings.Contains(body, "state the scheme/port policy") {
		t.Fatalf("error should explain what is missing, got %q", body)
	}
	// Nothing was stored: a refused save never leaves a half-created scope.
	if rec := a.do("GET", "/api/projects/"+pid+"/scope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a refused save stored a scope: %d", rec.Code)
	}

	// The same declaration with an explicit statement is accepted, and the
	// stored rule is exactly the one the operator wrote — no second scheme, no
	// second port.
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com"},
	}), http.StatusCreated, &sc)
	if want := []string{"https://app.example.com"}; !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want exactly %v", sc.AllowedOrigins, want)
	}
	if d := sc.Permits("https://app.example.com/"); !d.Allowed {
		t.Fatalf("declared origin denied: %+v", d)
	}
	if d := sc.Permits("http://app.example.com/"); d.Allowed {
		t.Fatalf("the https-only statement authorized plain http: %+v", d)
	}
}

func TestScopeAPIExplicitOriginsAreCanonicalAndExact(t *testing.T) {
	a, pid := newOriginProject(t)
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com:8443", "https://APP.example.com:8443"},
	}), http.StatusCreated, &sc)
	if want := []string{"https://app.example.com:8443"}; !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want the deduplicated canonical list %v", sc.AllowedOrigins, want)
	}
	if d := sc.Permits("https://app.example.com:8443/x"); !d.Allowed {
		t.Fatalf("declared origin denied: %+v", d)
	}
	if d := sc.Permits("https://app.example.com/x"); d.Allowed {
		t.Fatal("443 was not declared")
	}

	// A save that omits the field preserves the stored restriction.
	var kept domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"app.example.com"},
	}), http.StatusOK, &kept)
	if want := []string{"https://app.example.com:8443"}; !slices.Equal(kept.AllowedOrigins, want) {
		t.Fatalf("an omitted allowed_origins must preserve the list, got %v", kept.AllowedOrigins)
	}
}

// TestScopeAPIPathEditNeverWidensOrigins is the regression QA reported: an
// https-only scope whose path prefixes were edited used to be re-derived to
// http+https on the standard ports, silently widening 443-only to plain http.
func TestScopeAPIPathEditNeverWidensOrigins(t *testing.T) {
	a, pid := newOriginProject(t)
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com"},
	}), http.StatusCreated, nil)

	// A path-only edit, a new exclusion, and a changed include path together.
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":         []string{"app.example.com"},
		"exclude_hosts":         []string{"admin.example.com"},
		"include_path_prefixes": []string{"/app/"},
		"exclude_path_prefixes": []string{"/app/logout"},
	}), http.StatusOK, &sc)

	if want := []string{"https://app.example.com"}; !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("a path/exclusion edit changed the origin list to %v, want %v", sc.AllowedOrigins, want)
	}
	for _, u := range []string{"http://app.example.com/app/", "http://app.example.com:80/app/", "https://app.example.com:8443/app/"} {
		if d := sc.Permits(u); d.Allowed {
			t.Fatalf("the path edit authorized %q: %+v", u, d)
		}
	}
	if d := sc.Permits("https://app.example.com/app/"); !d.Allowed {
		t.Fatalf("the declared origin stopped working: %+v", d)
	}
	// Persisted, not just returned.
	if got := getScope(t, a, pid); !slices.Equal(got.AllowedOrigins, []string{"https://app.example.com"}) {
		t.Fatalf("stored allowed_origins = %v, want the https-only rule", got.AllowedOrigins)
	}
}

func TestScopeAPIAddingAHostRequiresItsOrigin(t *testing.T) {
	a, pid := newOriginProject(t)
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com"},
	}), http.StatusCreated, nil)

	// Adding a host without restating the origins is refused, and the error
	// names the host instead of quietly authorizing it on http and https.
	code, body := scopePut(a, pid, map[string]any{
		"include_hosts": []string{"app.example.com", "api.example.com"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("adding a host without an origin: status %d, want 400 (%s)", code, body)
	}
	if !strings.Contains(body, "api.example.com") || !strings.Contains(body, "does not cover") {
		t.Fatalf("error should name the uncovered host, got %q", body)
	}
	// The refused save left the scope alone: no new host, no new origin.
	after := getScope(t, a, pid)
	if !slices.Equal(after.IncludeHosts, []string{"app.example.com"}) {
		t.Fatalf("a rejected save changed include_hosts: %v", after.IncludeHosts)
	}
	if !slices.Equal(after.AllowedOrigins, []string{"https://app.example.com"}) {
		t.Fatalf("a rejected save changed allowed_origins: %v", after.AllowedOrigins)
	}

	// Declaring the new host's origin explicitly works, and the old entry keeps
	// its exact scheme and port.
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com", "api.example.com"},
		"allowed_origins": []string{"https://app.example.com", "https://api.example.com:8443"},
	}), http.StatusOK, &sc)
	want := []string{"https://api.example.com:8443", "https://app.example.com"}
	if !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want %v", sc.AllowedOrigins, want)
	}
	if d := sc.Permits("http://api.example.com:8443/"); d.Allowed {
		t.Fatal("the new host was authorized on a scheme it was not declared with")
	}

	// Removing a host drops the origin that can no longer match, and the save
	// still succeeds: dropping authority is always allowed.
	var narrowed domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"app.example.com"},
	}), http.StatusOK, &narrowed)
	if want := []string{"https://app.example.com"}; !slices.Equal(narrowed.AllowedOrigins, want) {
		t.Fatalf("removing a host left origins %v, want %v", narrowed.AllowedOrigins, want)
	}
}

func TestScopeAPIExplicitEmptyOriginsIsRefused(t *testing.T) {
	a, pid := newOriginProject(t)
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com"},
	}), http.StatusCreated, nil)

	code, body := scopePut(a, pid, map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{},
	})
	if code != http.StatusBadRequest || !strings.Contains(body, "allow_any_scheme_ports") {
		t.Fatalf("explicit empty list: status %d body %q, want a 400 pointing at the explicit opt-out", code, body)
	}
	if got := getScope(t, a, pid); !slices.Equal(got.AllowedOrigins, []string{"https://app.example.com"}) {
		t.Fatalf("a refused save changed the scope: %v", got.AllowedOrigins)
	}
}

func TestScopeAPIExplicitAnySchemePort(t *testing.T) {
	a, pid := newOriginProject(t)
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":          []string{"app.example.com"},
		"allow_any_scheme_ports": true,
	}), http.StatusCreated, &sc)
	if len(sc.AllowedOrigins) != 0 || !sc.AllowAnySchemePorts {
		t.Fatalf("explicit legacy scope = origins %v any %v, want none/true", sc.AllowedOrigins, sc.AllowAnySchemePorts)
	}
	if sc.LegacySchemePorts() {
		t.Fatal("an explicit opt-out must not read as the legacy shape")
	}
	if d := sc.Permits("http://app.example.com:8443/"); !d.Allowed {
		t.Fatalf("explicit any-scheme-port scope denied its host: %+v", d)
	}
	// An omitted-field save keeps the explicit legacy choice instead of
	// silently materialising (or losing) a restriction.
	var kept domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"app.example.com"},
	}), http.StatusOK, &kept)
	if len(kept.AllowedOrigins) != 0 || !kept.AllowAnySchemePorts {
		t.Fatalf("omitted-field save changed the explicit legacy choice: origins %v any %v", kept.AllowedOrigins, kept.AllowAnySchemePorts)
	}

	// Turning the opt-out off is a restriction, so it needs a list: an empty
	// list would be legacy again, which is never chosen implicitly.
	code, body := scopePut(a, pid, map[string]any{
		"include_hosts":          []string{"app.example.com"},
		"allowed_origins":        []string{},
		"allow_any_scheme_ports": false,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("turning the opt-out off without origins: status %d, want 400 (%s)", code, body)
	}

	// Stating the list is the supported way to restrict it, and it clears the
	// opt-out so the stored row cannot carry both.
	var restricted domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":          []string{"app.example.com"},
		"allowed_origins":        []string{"https://app.example.com"},
		"allow_any_scheme_ports": false,
	}), http.StatusOK, &restricted)
	if want := []string{"https://app.example.com"}; !slices.Equal(restricted.AllowedOrigins, want) {
		t.Fatalf("allowed_origins = %v, want %v", restricted.AllowedOrigins, want)
	}
	if restricted.AllowAnySchemePorts {
		t.Fatal("the opt-out was not cleared by the explicit list")
	}
}

func TestScopeAPILegacyScopeKeepsLegacyBehaviourUntilSaved(t *testing.T) {
	a, pid := newOriginProject(t)
	ctx := context.Background()
	now := time.Now().UTC()
	legacy := &domain.Scope{
		ID: domain.NewID(), ProjectID: domain.ID(pid),
		IncludeHosts: []string{"app.example.com"}, CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.Scopes().Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if !getScope(t, a, pid).LegacySchemePorts() {
		t.Fatal("a stored scope with no origin list must read as legacy")
	}
	// A save that changes nothing (or only narrows) keeps the stored (legacy)
	// behaviour: the upgrade never narrows an existing scope behind the
	// operator's back, and it never widens it either.
	var kept domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts": []string{"app.example.com"},
	}), http.StatusOK, &kept)
	if len(kept.AllowedOrigins) != 0 || kept.AllowAnySchemePorts {
		t.Fatalf("a no-op save changed a legacy scope: origins %v any %v", kept.AllowedOrigins, kept.AllowAnySchemePorts)
	}
	if d := kept.Permits("http://app.example.com:8443/"); !d.Allowed {
		t.Fatalf("the legacy compatibility promise was broken: %+v", d)
	}
	// A path-only edit is still a no-op for the scheme/port question.
	var pathOnly domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":         []string{"app.example.com"},
		"include_path_prefixes": []string{"/app/"},
	}), http.StatusOK, &pathOnly)
	if len(pathOnly.AllowedOrigins) != 0 || pathOnly.AllowAnySchemePorts {
		t.Fatalf("a path edit materialised a policy on a legacy scope: origins %v any %v", pathOnly.AllowedOrigins, pathOnly.AllowAnySchemePorts)
	}

	// Extending a legacy scope to a NEW host demands a statement: the stored
	// scope never authorized that host on any port, so inheriting "any scheme
	// and port" would be a widening nobody asked for.
	code, body := scopePut(a, pid, map[string]any{"include_hosts": []string{"app.example.com", "api.example.com"}})
	if code != http.StatusBadRequest || !strings.Contains(body, "state the scheme/port policy") {
		t.Fatalf("adding a host to a legacy scope: status %d body %q, want 400", code, body)
	}

	// Saving it with an explicit list is the supported path and narrows it.
	var changed domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com", "api.example.com"},
		"allowed_origins": []string{"https://app.example.com", "https://api.example.com"},
	}), http.StatusOK, &changed)
	if len(changed.AllowedOrigins) == 0 {
		t.Fatal("the explicit list was not stored")
	}
	if d := changed.Permits("http://app.example.com:8443/"); d.Allowed {
		t.Fatal("the explicit list still allowed a non-standard port")
	}
}

func TestScopeAPIRejectsUnusableOriginShapes(t *testing.T) {
	a, pid := newOriginProject(t)
	var first domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"app.example.com"},
		"allowed_origins": []string{"https://app.example.com"},
	}), http.StatusCreated, &first)

	cases := []struct {
		name string
		body map[string]any
		hint string
	}{
		{
			name: "port without a scheme",
			body: map[string]any{"include_hosts": []string{"app.example.com"}, "allowed_origins": []string{"app.example.com:8443"}},
			hint: "scheme://host",
		},
		{
			name: "path in an origin",
			body: map[string]any{"include_hosts": []string{"app.example.com"}, "allowed_origins": []string{"https://app.example.com/app"}},
			hint: "path",
		},
		{
			name: "unsupported scheme",
			body: map[string]any{"include_hosts": []string{"app.example.com"}, "allowed_origins": []string{"ftp://app.example.com"}},
			hint: "not supported",
		},
		{
			name: "origin host not in the host lists",
			body: map[string]any{"include_hosts": []string{"app.example.com"}, "allowed_origins": []string{"https://other.example.com"}},
			hint: "not authorized",
		},
		{
			name: "explicit any plus an origin list",
			body: map[string]any{
				"include_hosts":          []string{"app.example.com"},
				"allowed_origins":        []string{"https://app.example.com"},
				"allow_any_scheme_ports": true,
			},
			hint: "mutually exclusive",
		},
		{
			name: "apex of a subdomains-only host",
			body: map[string]any{
				"include_hosts":        []string{},
				"subdomain_only_hosts": []string{"example.com"},
				"allowed_origins":      []string{"https://example.com"},
			},
			hint: "not authorized",
		},
		{
			name: "explicit empty list",
			body: map[string]any{
				"include_hosts":   []string{"app.example.com"},
				"allowed_origins": []string{},
			},
			hint: "allow_any_scheme_ports",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := scopePut(a, pid, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", code, body)
			}
			if !strings.Contains(body, "allowed_origins") && !strings.Contains(body, "mutually exclusive") && !strings.Contains(body, "scheme/port policy") {
				t.Errorf("error should name the field, got %q", body)
			}
			if !strings.Contains(body, tc.hint) {
				t.Errorf("error %q should mention %q", body, tc.hint)
			}
			// A refused save leaves the stored scope untouched.
			if got := getScope(t, a, pid); !slices.Equal(got.AllowedOrigins, []string{"https://app.example.com"}) {
				t.Fatalf("a rejected save changed the scope: %v", got.AllowedOrigins)
			}
		})
	}
}

func TestScanCreationEnforcesTheDeclaredOrigin(t *testing.T) {
	a, pid := newOriginProject(t)
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"127.0.0.1"},
		"allowed_origins": []string{"https://127.0.0.1"},
	}), http.StatusCreated, nil)
	var tg map[string]any
	a.mustJSON(a.do("POST", "/api/projects/"+pid+"/targets", map[string]string{
		"name": "t", "base_url": "http://127.0.0.1:8080/",
	}), http.StatusCreated, &tg)

	// The target host is in scope, but the origin was never authorized: a new
	// scan must refuse at creation, not discover it mid-scan.
	rec := a.do("POST", "/api/scans", map[string]any{"project_id": pid, "target_id": tg["id"]})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scan creation on an undeclared origin = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "origin not authorized") {
		t.Fatalf("error should name the origin problem: %s", rec.Body.String())
	}
	// The same target on the declared scheme/port is accepted.
	var tgHTTPS map[string]any
	a.mustJSON(a.do("POST", "/api/projects/"+pid+"/targets", map[string]string{
		"name": "t2", "base_url": "https://127.0.0.1/",
	}), http.StatusCreated, &tgHTTPS)
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{"project_id": pid, "target_id": tgHTTPS["id"]}), http.StatusCreated, nil)
}

// One entry, one permission: the API stores the operator's exact origin list,
// and the matcher requires scheme AND port AND host to come from the SAME entry.
// A port declared for one asset must never attach to another asset's host.
func TestScopeAPIOriginsDoNotCrossAssets(t *testing.T) {
	a, pid := newOriginProject(t)
	var sc domain.Scope
	a.mustJSON(a.do("PUT", "/api/projects/"+pid+"/scope", map[string]any{
		"include_hosts":   []string{"a.example.com", "b.example.com"},
		"allowed_origins": []string{"https://a.example.com:8443", "http://b.example.com:8080"},
	}), http.StatusCreated, &sc)

	if want := []string{"http://b.example.com:8080", "https://a.example.com:8443"}; !slices.Equal(sc.AllowedOrigins, want) {
		t.Fatalf("stored origins = %v, want exactly the two declared entries %v (no scheme/port cross-product)", sc.AllowedOrigins, want)
	}
	for _, u := range []string{
		"http://a.example.com:8443/",  // scheme borrowed from b
		"https://a.example.com:8080/", // port borrowed from b
		"https://b.example.com:8443/", // port borrowed from a
		"https://b.example.com:8080/", // scheme borrowed from a
		"https://a.example.com/",      // 443 never declared
		"http://b.example.com/",       // 80 never declared
	} {
		if d := sc.Permits(u); d.Allowed {
			t.Errorf("cross-asset widening: %q allowed (%s)", u, d.Reason)
		}
	}
	// The CONNECT boundary has only host:port, so it matches the port against
	// the SAME host's entries; it cannot borrow a sibling's port.
	for _, h := range []string{"a.example.com:8080", "b.example.com:8443", "a.example.com"} {
		if sc.PermitsHost(h) {
			t.Errorf("CONNECT authority %q was allowed across assets", h)
		}
	}
	if !sc.PermitsHost("a.example.com:8443") || !sc.PermitsHost("b.example.com:8080") {
		t.Fatal("a declared host+port was refused at the CONNECT boundary")
	}
}

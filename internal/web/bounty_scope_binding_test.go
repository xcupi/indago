package web

// Path binding for the importer.
//
// domain.Scope.IncludePathPrefixes is GLOBAL: Scope.Permits matches a URL's
// path against every stored prefix without looking at the host. A program that
// scopes "/app" to https://a.test and "/api" to https://b.test therefore cannot
// be flattened into one scope — doing so would also permit https://a.test/api
// and https://b.test/app, which the program never authorized.
//
// The importer now checks the per-origin bindings before it returns a plan:
// every imported origin must authorize the same prefix set, otherwise the whole
// program is refused (blocked) with a reason and nothing is stored. These tests
// pin both sides: the cross-product shapes are refused, and the shapes that ARE
// representable keep exactly the authorized paths.

import (
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
)

const webAsset = "web-application"

func scopeFromPlan(hosts, subdomainOnly, prefixes, origins []string) domain.Scope {
	return domain.Scope{
		IncludeHosts:        hosts,
		SubdomainOnlyHosts:  subdomainOnly,
		IncludePathPrefixes: prefixes,
		AllowedOrigins:      origins,
	}
}

func TestImporterRefusesCrossOriginPathBindings(t *testing.T) {
	cases := []struct {
		name string
		in   []bounty.Scope
		hint []string
	}{
		{
			name: "two hosts, two different paths (the QA case)",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test/api", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hint: []string{"https://a.test is scoped to /app", "https://b.test is scoped to /api", "apply to every host"},
		},
		{
			name: "same host, different scheme",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "http://a.test/api", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hint: []string{"https://a.test is scoped to /app", "http://a.test is scoped to /api"},
		},
		{
			name: "same host, different port",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://a.test:8443/api", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hint: []string{"https://a.test is scoped to /app", "https://a.test:8443 is scoped to /api"},
		},
		{
			name: "path-scoped asset plus an unrestricted host",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hint: []string{"https://b.test is scoped to the whole origin"},
		},
		{
			name: "wildcard scoped to a path, exact host scoped elsewhere",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test/app", ScopeType: webAsset, AssetValue: "https://x.acme.test/app"},
				{Scope: "https://api.other.test/api", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hint: []string{"https://*.acme.test is scoped to /app", "https://api.other.test is scoped to /api"},
		},
		{
			name: "wildcard's concrete asset is scoped differently from the wildcard",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test/app", ScopeType: webAsset, AssetValue: "https://x.acme.test/other"},
			},
			hint: []string{"https://*.acme.test is scoped to /app", "https://x.acme.test is scoped to /other"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hosts, subdomainOnly, targets, prefixes, origins, _, blocked := webScopeTargets(c.in)
			if blocked == "" {
				t.Fatalf("expected the program to be refused; plan = hosts %v sub %v targets %v prefixes %v origins %v",
					hosts, subdomainOnly, targets, prefixes, origins)
			}
			t.Logf("refused: %s", blocked)
			// A refused plan must be empty, so a caller that ignores the reason
			// still cannot store a widened scope.
			if len(hosts) != 0 || len(subdomainOnly) != 0 || len(targets) != 0 || len(prefixes) != 0 || len(origins) != 0 {
				t.Fatalf("a refused plan returned lists: hosts %v sub %v targets %v prefixes %v origins %v",
					hosts, subdomainOnly, targets, prefixes, origins)
			}
			for _, want := range c.hint {
				if !strings.Contains(blocked, want) {
					t.Errorf("reason %q should mention %q", blocked, want)
				}
			}
		})
	}
}

func TestImporterKeepsRepresentablePathBindings(t *testing.T) {
	cases := []struct {
		name          string
		in            []bounty.Scope
		hosts         []string
		subdomainOnly []string
		targets       []string
		prefixes      []string
		allowed       []string
		denied        []string
	}{
		{
			name: "one path-scoped asset",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"a.test"},
			targets:  []string{"https://a.test/app"},
			prefixes: []string{"/app"},
			allowed:  []string{"https://a.test/app", "https://a.test/app/x"},
			denied:   []string{"https://a.test/api", "https://a.test/", "http://a.test/app"},
		},
		{
			name: "the same path on two hosts",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"a.test", "b.test"},
			targets:  []string{"https://a.test/app", "https://b.test/app"},
			prefixes: []string{"/app"},
			allowed:  []string{"https://a.test/app/x", "https://b.test/app/x"},
			denied:   []string{"https://a.test/api", "https://b.test/api"},
		},
		{
			name: "the same path on two ports",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test:8443/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"a.test", "b.test"},
			targets:  []string{"https://a.test/app", "https://b.test:8443/app"},
			prefixes: []string{"/app"},
			allowed:  []string{"https://a.test/app", "https://b.test:8443/app"},
			denied:   []string{"https://b.test/app", "http://a.test/app"},
		},
		{
			name: "two paths on the same origin",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://a.test/api", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"a.test"},
			targets:  []string{"https://a.test/api", "https://a.test/app"},
			prefixes: []string{"/api", "/app"},
			allowed:  []string{"https://a.test/app/x", "https://a.test/api/x"},
			denied:   []string{"https://a.test/other", "https://b.test/app"},
		},
		{
			name: "nested paths reduce to the same set on every origin",
			in: []bounty.Scope{
				{Scope: "https://a.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test/app", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test/app/admin", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"a.test", "b.test"},
			targets:  []string{"https://a.test/app", "https://b.test/app", "https://b.test/app/admin"},
			prefixes: []string{"/app"},
			allowed:  []string{"https://a.test/app/admin", "https://b.test/app/x"},
			denied:   []string{"https://a.test/admin", "https://b.test/admin"},
		},
		{
			name: "no path at all stays unrestricted",
			in: []bounty.Scope{
				{Scope: "https://a.test", ScopeType: webAsset, AssetValue: "MEDIUM"},
				{Scope: "https://b.test:8443", ScopeType: webAsset, AssetValue: "MEDIUM"},
			},
			hosts:   []string{"a.test", "b.test"},
			targets: []string{"https://a.test/", "https://b.test:8443/"},
			allowed: []string{"https://a.test/any/path", "https://b.test:8443/any/path"},
			denied:  []string{"https://a.test:8443/", "http://b.test:8443/"},
		},
		{
			name: "an unrestricted wildcard already authorizes its subdomain's path",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test", ScopeType: webAsset, AssetValue: "https://x.acme.test/app"},
			},
			hosts:         []string{"x.acme.test"},
			subdomainOnly: []string{"acme.test"},
			targets:       []string{"https://x.acme.test/app"},
			// The wildcard states the whole origin, so the concrete asset's
			// "/app" adds nothing and must not narrow either entry.
			prefixes: nil,
			allowed:  []string{"https://x.acme.test/anything", "https://y.acme.test/anything"},
			denied:   []string{"https://acme.test/anything", "http://x.acme.test/anything"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hosts, subdomainOnly, targets, prefixes, origins, _, blocked := webScopeTargets(c.in)
			if blocked != "" {
				t.Fatalf("webScopeTargets refused a representable program: %s", blocked)
			}
			if !slices.Equal(hosts, c.hosts) {
				t.Errorf("hosts = %v, want %v", hosts, c.hosts)
			}
			if !slices.Equal(subdomainOnly, c.subdomainOnly) {
				t.Errorf("subdomainOnly = %v, want %v", subdomainOnly, c.subdomainOnly)
			}
			if !slices.Equal(targets, c.targets) {
				t.Errorf("targets = %v, want %v", targets, c.targets)
			}
			if !slices.Equal(prefixes, c.prefixes) {
				t.Errorf("prefixes = %v, want %v", prefixes, c.prefixes)
			}
			sc := scopeFromPlan(hosts, subdomainOnly, prefixes, origins)
			for _, u := range c.allowed {
				if d := sc.Permits(u); !d.Allowed {
					t.Errorf("Permits(%q) denied (%s), want allowed", u, d.Reason)
				}
			}
			for _, u := range c.denied {
				if d := sc.Permits(u); d.Allowed {
					t.Errorf("Permits(%q) allowed, want denied", u)
				}
			}
		})
	}
}

func TestReduceScopePathPrefixesMirrorsTheMatcher(t *testing.T) {
	cases := map[string][]string{
		"empty input":                      nil,
		"whole origin wins":                nil,
		"whole origin from a / entry":      nil,
		"nested":                           {"/app"},
		"a sibling segment is not covered": {"/app", "/application"},
		"distinct":                         {"/api", "/app"},
		"mixed":                            {"/api", "/app"},
		"trailing slash is covered":        {"/app"},
	}
	in := map[string][]string{
		"empty input":                      {},
		"whole origin wins":                {"", "/app"},
		"whole origin from a / entry":      {"/"},
		"nested":                           {"/app", "/app/admin", "/app/admin/users"},
		"a sibling segment is not covered": {"/application", "/app"},
		"distinct":                         {"/app", "/api"},
		"mixed":                            {"/app/admin", "/api", "/app"},
		"trailing slash is covered":        {"/app/", "/app"},
	}
	for name, want := range cases {
		if got := reduceScopePathPrefixes(in[name]); !slices.Equal(got, want) {
			t.Errorf("%s: reduceScopePathPrefixes(%v) = %v, want %v", name, in[name], got, want)
		}
	}
}

// A binding whose restriction is redundant because the same program authorizes
// the wider path must not narrow the imported scope.
func TestNormalizeScopePathBindingsDropsOnlyRedundantRestrictions(t *testing.T) {
	got := normalizeScopePathBindings([]scopePathBinding{
		{Origin: "https://*.acme.test", Path: ""},
		{Origin: "https://x.acme.test", Path: "/app"},
		// Not covered by the wildcard: different port.
		{Origin: "https://y.acme.test:8443", Path: "/app"},
		// Not covered: the wildcard never covers its apex.
		{Origin: "https://acme.test", Path: "/app"},
		// Not covered by an unrestricted wildcard: its own wildcard is scoped.
		{Origin: "https://*.other.test", Path: "/app"},
	})
	want := []scopePathBinding{
		{Origin: "https://*.acme.test", Path: ""},
		{Origin: "https://x.acme.test", Path: ""},
		{Origin: "https://y.acme.test:8443", Path: "/app"},
		{Origin: "https://acme.test", Path: "/app"},
		{Origin: "https://*.other.test", Path: "/app"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("normalized bindings = %v, want %v", got, want)
	}
}

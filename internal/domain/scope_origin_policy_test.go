package domain

// The write-side half of the scheme/port feature: an origin list is an operator
// statement, so these helpers only ever keep, narrow, or report what is missing.
// Nothing here invents an origin, which is what keeps "editing a path prefix"
// from silently widening an https-only scope to plain http.

import (
	"slices"
	"testing"
)

func TestLegacySchemePortsIsOnlyThePreexistingShape(t *testing.T) {
	cases := []struct {
		name string
		sc   Scope
		want bool
	}{
		{"no list, no annotation", Scope{IncludeHosts: []string{"app.example.com"}}, true},
		{"explicit origins", Scope{IncludeHosts: []string{"app.example.com"}, AllowedOrigins: []string{"https://app.example.com"}}, false},
		{"explicit any-scheme-port", Scope{IncludeHosts: []string{"app.example.com"}, AllowAnySchemePorts: true}, false},
		// A hand-edited row that carries both is enforced by the list, so it is
		// not legacy either.
		{"both", Scope{IncludeHosts: []string{"app.example.com"}, AllowedOrigins: []string{"https://app.example.com"}, AllowAnySchemePorts: true}, false},
	}
	for _, tc := range cases {
		if got := tc.sc.LegacySchemePorts(); got != tc.want {
			t.Errorf("%s: LegacySchemePorts() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterScopeOriginsByHostsOnlyDrops(t *testing.T) {
	include := []string{"app.example.com"}
	subOnly := []string{"wild.example.com"}
	got := FilterScopeOriginsByHosts([]string{
		"https://app.example.com",
		"https://APP.example.com:443", // duplicate after canonicalisation
		"https://gone.example.com",    // host left the scope
		"https://a.wild.example.com",  // authorized by the wildcard list
		"app.example.com",             // never an origin: dropped, not repaired
		"http://app.example.com:8080",
	}, include, subOnly, false)
	want := []string{
		"http://app.example.com:8080",
		"https://a.wild.example.com",
		"https://app.example.com",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("filtered origins = %v, want %v", got, want)
	}

	// A wildcard entry needs a host rule that covers a concrete subdomain; with
	// allow_subdomains off and no matching wildcard list it is dropped rather
	// than left in a list that can never match.
	if got := FilterScopeOriginsByHosts([]string{"https://*.example.com"}, []string{"example.com"}, nil, false); len(got) != 0 {
		t.Fatalf("filtered = %v, want none", got)
	}
	if got := FilterScopeOriginsByHosts([]string{"https://*.example.com"}, []string{"example.com"}, nil, true); !slices.Equal(got, []string{"https://*.example.com"}) {
		t.Fatalf("filtered = %v, want the wildcard kept under allow_subdomains", got)
	}
}

func TestUncoveredScopeHosts(t *testing.T) {
	cases := []struct {
		name      string
		origins   []string
		include   []string
		subOnly   []string
		uncovered []string
	}{
		{
			name:    "exact origin covers its host",
			origins: []string{"https://app.example.com"},
			include: []string{"app.example.com"},
		},
		{
			name:      "added host has no origin",
			origins:   []string{"https://app.example.com"},
			include:   []string{"app.example.com", "api.example.com"},
			uncovered: []string{"api.example.com"},
		},
		{
			name:      "a wildcard origin never covers its apex",
			origins:   []string{"https://*.example.com"},
			include:   []string{"example.com"},
			uncovered: []string{"example.com"},
		},
		{
			name:    "a leading-dot include needs an apex origin",
			origins: []string{"https://*.example.com", "https://example.com"},
			include: []string{".example.com"},
		},
		{
			name:    "wildcard list covered by a wildcard origin",
			origins: []string{"https://*.example.com"},
			subOnly: []string{"example.com"},
		},
		{
			name:    "an ancestor wildcard covers a nested wildcard list",
			origins: []string{"https://*.example.com"},
			subOnly: []string{"api.example.com"},
		},
		{
			name:      "wildcard list with no origin at all",
			origins:   []string{"https://other.test"},
			subOnly:   []string{"example.com"},
			uncovered: []string{"example.com"},
		},
		{
			name:    "wildcard list covered by an exact subdomain",
			origins: []string{"https://app.example.com"},
			subOnly: []string{"example.com"},
		},
		{
			name:    "IPv6 include covered",
			origins: []string{"http://[::1]:8080"},
			include: []string{"::1"},
		},
		{
			name:      "nothing covers anything",
			origins:   []string{"garbage"},
			include:   []string{"a.example.com"},
			subOnly:   []string{"b.example.com"},
			uncovered: []string{"a.example.com", "b.example.com"},
		},
	}
	for _, tc := range cases {
		got := UncoveredScopeHosts(tc.origins, tc.include, tc.subOnly)
		if !slices.Equal(got, tc.uncovered) {
			t.Errorf("%s: UncoveredScopeHosts = %v, want %v", tc.name, got, tc.uncovered)
		}
	}
}

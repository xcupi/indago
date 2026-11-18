package web

// Regression table for the bug-bounty scope importer.
//
// The importer must never widen what a program authorized. Two shapes are the
// dangerous ones and are pinned here:
//
//   - an exact asset must not become "host + every subdomain";
//   - a wildcard asset ("*.example.com") must not become "example.com + every
//     subdomain" — the apex is not part of a wildcard.
//
// Exclusions and path prefixes that a scope already carries are not touched by
// this function; the cases below also pin that a path asset still contributes
// its prefix.

import (
	"slices"
	"strings"
	"testing"

	"github.com/indago/indago/internal/bounty"
)

func TestWebScopeTargetsKeepsExactAndWildcardApart(t *testing.T) {
	web := "web-application"
	cases := []struct {
		name          string
		in            []bounty.Scope
		hosts         []string
		subdomainOnly []string
		targets       []string
		prefixes      []string
		skippedNote   string
	}{
		{
			name: "exact host authorizes only itself",
			in: []bounty.Scope{
				{Scope: "app.acme.test", ScopeType: web, AssetValue: "https://app.acme.test"},
			},
			hosts:   []string{"app.acme.test"},
			targets: []string{"https://app.acme.test/"},
		},
		{
			name: "exact host with a path keeps the prefix",
			in: []bounty.Scope{
				{Scope: "https://target.test/challenge/one", ScopeType: web, AssetValue: "MEDIUM"},
			},
			hosts:    []string{"target.test"},
			targets:  []string{"https://target.test/challenge/one"},
			prefixes: []string{"/challenge/one"},
		},
		{
			name: "wildcard authorizes subdomains and keeps the concrete asset as a seed",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test", ScopeType: web, AssetValue: "https://app.acme.test"},
			},
			hosts:         []string{"app.acme.test"},
			subdomainOnly: []string{"acme.test"},
			targets:       []string{"https://app.acme.test/"},
		},
		{
			name: "wildcard with no concrete asset authorizes subdomains but seeds nothing",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test", ScopeType: web, AssetValue: "MEDIUM"},
			},
			subdomainOnly: []string{"acme.test"},
			skippedNote:   "no seed host",
		},
		{
			name: "wildcard whose asset is the apex does not authorize the apex",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test", ScopeType: web, AssetValue: "https://acme.test"},
			},
			subdomainOnly: []string{"acme.test"},
			skippedNote:   "names no subdomain of acme.test",
		},
		{
			name: "wildcard whose asset is outside it is not adopted",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test", ScopeType: web, AssetValue: "https://evil.test"},
			},
			subdomainOnly: []string{"acme.test"},
			skippedNote:   "names no subdomain of acme.test",
		},
		{
			name: "wildcard with a path keeps both the wildcard and the prefix",
			in: []bounty.Scope{
				{Scope: "https://*.acme.test/app", ScopeType: web, AssetValue: "https://x.acme.test/app"},
			},
			hosts:         []string{"x.acme.test"},
			subdomainOnly: []string{"acme.test"},
			targets:       []string{"https://x.acme.test/app"},
			prefixes:      []string{"/app"},
		},
		{
			name: "mixed exact and wildcard rows keep both meanings",
			in: []bounty.Scope{
				{Scope: "shop.other.test", ScopeType: web, AssetValue: "https://shop.other.test"},
				{Scope: "https://*.acme.test", ScopeType: web, AssetValue: "https://app.acme.test"},
			},
			hosts:         []string{"app.acme.test", "shop.other.test"},
			subdomainOnly: []string{"acme.test"},
			targets:       []string{"https://app.acme.test/", "https://shop.other.test/"},
		},
		{
			name: "non-web assets stay skipped",
			in: []bounty.Scope{
				{Scope: "api.acme.test", ScopeType: "api", AssetValue: "https://api.acme.test"},
			},
			skippedNote: "api:api.acme.test",
		},
		{
			name: "a leading-dot asset is not guessed at",
			in: []bounty.Scope{
				{Scope: ".acme.test", ScopeType: web, AssetValue: "MEDIUM"},
			},
			skippedNote: "leading-dot",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hosts, subdomainOnly, targets, prefixes, _, skipped, blocked := webScopeTargets(c.in)
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
			if c.skippedNote == "" {
				return
			}
			joined := strings.Join(skipped, "|")
			if !strings.Contains(joined, c.skippedNote) {
				t.Errorf("skipped = %v, want a note containing %q", skipped, c.skippedNote)
			}
		})
	}
}

// The wildcard parent and its concrete asset are parsed by different helpers;
// check the wildcard spellings that actually reach the importer.
func TestWildcardAssetSpellings(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		port   int
		path   string
		ok     bool
	}{
		// A wildcard without an explicit http(s) scheme is refused: the asset
		// text does not state a scheme or port, and the importer never guesses
		// one (the operator declares the origin themselves).
		{"*.example.com", "", "", 0, "", false},
		{"*.example.com/", "", "", 0, "", false},
		{"*.example.com/app", "", "", 0, "", false},
		{"https://*.example.com", "https", "example.com", 443, "", true},
		{"https://*.example.com/", "https", "example.com", 443, "", true},
		{"https://*.example.com/app", "https", "example.com", 443, "/app", true},
		{"https://*.Example.COM/app", "https", "example.com", 443, "/app", true},
		{"http://*.example.com:8443/app", "http", "example.com", 8443, "/app", true},
		{"example.com", "", "", 0, "", false},
		{".example.com", "", "", 0, "", false},
		{"*", "", "", 0, "", false},
		{"*.", "", "", 0, "", false},
	}
	for _, c := range cases {
		scheme, host, port, path, ok := wildcardAsset(c.raw)
		if ok != c.ok || scheme != c.scheme || host != c.host || port != c.port || path != c.path {
			t.Errorf("wildcardAsset(%q) = (%q, %q, %d, %q, %v), want (%q, %q, %d, %q, %v)",
				c.raw, scheme, host, port, path, ok, c.scheme, c.host, c.port, c.path, c.ok)
		}
	}
}

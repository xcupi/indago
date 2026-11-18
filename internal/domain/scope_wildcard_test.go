package domain

// The two shapes a bug-bounty program uses to authorize a host are NOT the same
// permission, and the scope model keeps them apart:
//
//   - an exact asset ("www.example.com") authorizes that host only;
//   - a wildcard asset ("*.example.com") authorizes subdomains of example.com
//     and not example.com itself.
//
// These cases pin that difference at the matcher, which is what every other
// layer (scan creation, the scope-enforcing HTTP engine, the browser gate, the
// proxy CONNECT check) ultimately relies on. They are the evidence behind
// docs/scope-semantics.md §3.

import "testing"

func subdomains(h ...string) Scope {
	return Scope{SubdomainOnlyHosts: h}
}

func TestScopeSubdomainOnlyHosts(t *testing.T) {
	cases := []scopeCase{
		// An exact host authorizes itself and never a subdomain of itself.
		{"exact host permits itself", hosts("www.example.com"), "https://www.example.com/", true, ""},
		{"exact host denies its subdomain", hosts("www.example.com"), "https://a.www.example.com/", false, "an exact asset is not a wildcard"},
		{"exact host denies a deep subdomain", hosts("www.example.com"), "https://a.b.www.example.com/", false, ""},
		{"exact host denies a sibling", hosts("www.example.com"), "https://api.example.com/", false, ""},

		// A wildcard authorizes a strict subdomain, at any depth, and nothing else.
		{"wildcard permits a subdomain", subdomains("example.com"), "https://a.example.com/", true, ""},
		{"wildcard permits a deep subdomain", subdomains("example.com"), "https://a.b.example.com/", true, ""},
		{"wildcard denies the apex", subdomains("example.com"), "https://example.com/", false, "*.example.com does not scope example.com"},
		{"wildcard denies a suffix lookalike", subdomains("example.com"), "https://evilexample.com/", false, "dot boundary required"},
		{"wildcard denies a prefix lookalike", subdomains("example.com"), "https://example.com.evil.net/", false, ""},
		{"wildcard denies a trailing-dot host", subdomains("example.com"), "https://a.example.com./", false, "matcher never normalises"},

		// Mixed: exact + wildcard in one scope.
		{"mixed permits the exact host", Scope{IncludeHosts: []string{"shop.example.com"}, SubdomainOnlyHosts: []string{"example.com"}}, "https://shop.example.com/", true, ""},
		{"mixed permits a wildcard subdomain", Scope{IncludeHosts: []string{"shop.example.com"}, SubdomainOnlyHosts: []string{"example.com"}}, "https://api.example.com/", true, ""},
		{"mixed keeps the wildcard apex out", Scope{IncludeHosts: []string{"shop.example.com"}, SubdomainOnlyHosts: []string{"example.com"}}, "https://example.com/", false, "the exact asset is shop, not the apex"},
		{"mixed denies an unrelated host", Scope{IncludeHosts: []string{"shop.example.com"}, SubdomainOnlyHosts: []string{"example.com"}}, "https://other.test/", false, ""},

		// Exclusions still win, on both lists.
		{"exclusion beats the wildcard", Scope{SubdomainOnlyHosts: []string{"example.com"}, ExcludeHosts: []string{"admin.example.com"}}, "https://admin.example.com/", false, ""},
		{"exclusion keeps wildcard siblings", Scope{SubdomainOnlyHosts: []string{"example.com"}, ExcludeHosts: []string{"admin.example.com"}}, "https://app.example.com/", true, ""},
		{"excluded path still applies", Scope{SubdomainOnlyHosts: []string{"example.com"}, ExcludePathPrefixes: []string{"/admin"}}, "https://a.example.com/admin/x", false, ""},

		// Path prefixes restrict what the wildcard authorizes.
		{"wildcard honours an include path", Scope{SubdomainOnlyHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/app"}}, "https://a.example.com/app/x", true, ""},
		{"wildcard denies outside the include path", Scope{SubdomainOnlyHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/app"}}, "https://a.example.com/other", false, ""},

		// Fail-closed and case behaviour follow the rest of the matcher.
		{"subdomain-only alone is a usable scope", subdomains("example.com"), "https://a.example.com/x", true, ""},
		{"empty scope still denies", Scope{}, "https://example.com/", false, ""},
		{"allow_subdomains does not lift the apex rule", Scope{SubdomainOnlyHosts: []string{"example.com"}, AllowSubdomains: true}, "https://example.com/", false, "the wildcard list never matches its own host"},
		{"entry and host compare case-insensitively", subdomains("Example.COM"), "https://A.example.com/", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.scope.Permits(c.url); got.Allowed != c.want {
				t.Fatalf("Permits(%q) = %v (%s), want %v %s", c.url, got.Allowed, got.Reason, c.want, c.note)
			}
		})
	}
}

// The proxy CONNECT boundary sees only host[:port]. It must apply the same
// subdomains-only rule, or the two boundaries would disagree about the apex.
func TestScopeSubdomainOnlyHostsPermitsHost(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"shop.example.com"}, SubdomainOnlyHosts: []string{"example.com"}, ExcludeHosts: []string{"admin.example.com"}}
	cases := []struct {
		host string
		want bool
	}{
		{"shop.example.com", true},
		{"shop.example.com:8443", true},
		{"a.example.com:443", true},
		{"example.com:443", false},   // wildcard apex
		{"admin.example.com", false}, // excluded
		{"evilexample.com", false},
		{"other.test", false},
		{"", false},
	}
	for _, c := range cases {
		if got := sc.PermitsHost(c.host); got != c.want {
			t.Errorf("PermitsHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestValidateScopeSubdomainHost(t *testing.T) {
	for _, entry := range []string{"example.com", "a.example.com", "127.0.0.1", "::1"} {
		if err := ValidateScopeSubdomainHost(entry); err != nil {
			t.Errorf("ValidateScopeSubdomainHost(%q) = %v, want nil", entry, err)
		}
	}
	for _, entry := range []string{"", ".example.com", "*.example.com", "https://example.com", "example.com:8443"} {
		if err := ValidateScopeSubdomainHost(entry); err == nil {
			t.Errorf("ValidateScopeSubdomainHost(%q) = nil, want an error", entry)
		}
	}
}

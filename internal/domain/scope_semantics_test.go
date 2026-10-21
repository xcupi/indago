package domain

// Characterization of what Scope.Permits does and does not decide. These cases
// are the factual basis of docs/scope-semantics.md: each row is one statement in
// that document. They pin CURRENT behaviour, including behaviour that is
// surprising or loose, so that changing the matcher (for example to compare
// ports) is a deliberate decision that updates the document, not an accident.
//
// "want" is the Allowed verdict. A few rows are marked unsafe: they are cases
// where the matcher is more permissive than an operator might assume.

import "testing"

type scopeCase struct {
	name  string
	scope Scope
	url   string
	want  bool
	note  string
}

func hosts(h ...string) Scope { return Scope{IncludeHosts: h} }

func TestScopeSemanticsHostsAndPorts(t *testing.T) {
	cases := []scopeCase{
		// The decision uses the HOSTNAME only. Scheme and port are ignored.
		{"any port", hosts("example.com"), "http://example.com:1/", true, "port ignored"},
		{"high port", hosts("example.com"), "https://example.com:65535/x", true, "port ignored"},
		{"other scheme", hosts("example.com"), "ftp://example.com/x", true, "scheme ignored"},
		{"scheme http vs https", hosts("example.com"), "http://example.com/", true, "scheme ignored"},
		// An include entry is compared as a bare hostname. Anything else matches nothing.
		{"entry with scheme never matches", hosts("https://example.com"), "https://example.com/", false, "entry must be a bare host"},
		{"entry with port never matches", hosts("example.com:8443"), "https://example.com:8443/", false, "entry must be a bare host"},
		{"entry with wildcard never matches", hosts("*.example.com"), "https://a.example.com/", false, "use .example.com or allow_subdomains"},
		{"entry with trailing slash never matches", hosts("example.com/"), "https://example.com/", false, ""},
		// Case.
		{"host case-insensitive (url)", hosts("example.com"), "http://EXAMPLE.com/", true, ""},
		{"host case-insensitive (entry)", hosts("Example.COM"), "http://example.com/", true, ""},
		// Forms of the same host that do not string-match fail closed.
		{"trailing dot host", hosts("example.com"), "http://example.com./", false, "FQDN form is a different string"},
		{"decimal IPv4", hosts("127.0.0.1"), "http://2130706433/", false, "no numeric normalisation"},
		{"hex IPv4", hosts("127.0.0.1"), "http://0x7f.0.0.1/", false, ""},
		{"ipv4-mapped ipv6", hosts("127.0.0.1"), "http://[::ffff:127.0.0.1]/", false, ""},
		{"bracketed ipv6 entry bare", hosts("::1"), "http://[::1]:8080/", true, "write the IPv6 entry without brackets"},
		{"unicode vs punycode", hosts("xn--bcher-kva.example"), "http://bücher.example/", false, "enter the punycode form the browser will send"},
		// Userinfo: the host is what follows '@'.
		{"userinfo decoy before in-scope host", hosts("127.0.0.1"), "http://evil.example@127.0.0.1/", true, "real host is 127.0.0.1"},
		{"in-scope name as userinfo of other host", hosts("127.0.0.1"), "http://127.0.0.1@evil.example/", false, "real host is evil.example"},
		// No host at all.
		{"hostless", hosts("example.com"), "/just/a/path", false, ""},
		{"empty scope", Scope{}, "http://example.com/", false, "fail closed"},
		{"unparseable", hosts("example.com"), "http://exa mple.com/", false, ""},
	}
	runScopeCases(t, cases)
}

func TestScopeSemanticsSubdomains(t *testing.T) {
	sub := Scope{IncludeHosts: []string{"example.com"}, AllowSubdomains: true}
	dot := Scope{IncludeHosts: []string{".example.com"}}
	cases := []scopeCase{
		{"subdomain off by default", hosts("example.com"), "http://a.example.com/", false, ""},
		{"subdomain on", sub, "http://a.example.com/", true, ""},
		{"deep subdomain on", sub, "http://a.b.example.com/", true, ""},
		{"base itself with subdomains on", sub, "http://example.com/", true, ""},
		{"suffix lookalike", sub, "http://evilexample.com/", false, "requires the dot boundary"},
		{"prefix lookalike", sub, "http://example.com.evil.net/", false, ""},
		{"leading-dot entry: subdomain", dot, "http://a.example.com/", true, ""},
		{"leading-dot entry: base", dot, "http://example.com/", true, ""},
		{"leading-dot entry: lookalike", dot, "http://evilexample.com/", false, ""},
		{"excluded host beats included", Scope{IncludeHosts: []string{"example.com"}, ExcludeHosts: []string{"admin.example.com"}, AllowSubdomains: true}, "http://admin.example.com/", false, "exclusion wins"},
		{"exclude host ignores port", Scope{IncludeHosts: []string{"example.com"}, ExcludeHosts: []string{"example.com"}}, "http://example.com:8443/", false, ""},
	}
	runScopeCases(t, cases)
}

func TestScopeSemanticsPaths(t *testing.T) {
	inc := func(p ...string) Scope {
		return Scope{IncludeHosts: []string{"example.com"}, IncludePathPrefixes: p}
	}
	exc := func(p ...string) Scope {
		return Scope{IncludeHosts: []string{"example.com"}, ExcludePathPrefixes: p}
	}
	cases := []scopeCase{
		// Prefixes are plain string prefixes, with no segment boundary.
		{"include /app matches /app", inc("/app"), "http://example.com/app", true, ""},
		{"include /app matches /app/x", inc("/app"), "http://example.com/app/x", true, ""},
		{"include /app matches /application (unsafe)", inc("/app"), "http://example.com/application", true, "no segment boundary: WIDER than intended"},
		{"include /app/ rejects /app", inc("/app/"), "http://example.com/app", false, "no trailing-slash equivalence"},
		{"include /app/ matches /app/x", inc("/app/"), "http://example.com/app/x", true, ""},
		{"include is case-sensitive", inc("/app"), "http://example.com/App", false, "paths are case-sensitive; hosts are not"},
		{"empty path is /", inc("/"), "http://example.com", true, ""},
		// Exclusions use the same prefix rule.
		{"exclude /admin blocks /administrator", exc("/admin"), "http://example.com/administrator", false, "over-blocks: safe direction"},
		{"exclude /admin/ does not block /admin (unsafe)", exc("/admin/"), "http://example.com/admin", true, "trailing slash makes the exclusion NARROWER"},
		{"exclude is case-sensitive (unsafe)", exc("/admin"), "http://example.com/Admin", true, "case variants are not excluded"},
		{"exclude beats include", Scope{IncludeHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/app"}, ExcludePathPrefixes: []string{"/app/private"}}, "http://example.com/app/private/x", false, ""},
		// The matcher does not canonicalise the path: dot-segments are not collapsed.
		{"dot-segments are not collapsed (unsafe)", inc("/app"), "http://example.com/app/../secret", true, "Permits sees /app/../secret; discovery.Normalize collapses it before requests are built, browsers canonicalise before the gate"},
		{"encoded dot-segments are decoded, not collapsed (unsafe)", inc("/app"), "http://example.com/app/%2e%2e/secret", true, "same; a server may decode %2e%2e itself"},
		{"encoded slash is not a prefix break", inc("/app"), "http://example.com/app%2fx", true, "u.Path is the decoded path"},
		// Query and fragment never take part.
		{"query ignored", inc("/app"), "http://example.com/other?next=/app", false, ""},
		{"fragment ignored", inc("/app"), "http://example.com/other#/app", false, ""},
	}
	runScopeCases(t, cases)
}

func runScopeCases(t *testing.T, cases []scopeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.scope.Permits(tc.url)
			if got.Allowed != tc.want {
				t.Fatalf("Permits(%q) = %v (%s), want %v  [%s]", tc.url, got.Allowed, got.Reason, tc.want, tc.note)
			}
		})
	}
}

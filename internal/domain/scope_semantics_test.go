package domain

// Characterization of what Scope.Permits does and does not decide. These cases
// are the factual basis of docs/scope-semantics.md: each row is one statement in
// that document. They pin CURRENT behaviour, including the fail-closed path
// rules (segment-bound includes and over-blocking exclusions), so changing the
// matcher is a deliberate decision, not an accident.
//
// "want" is the Allowed verdict.

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
		// Includes are segment-bounded: "/app" is a directory, not a string
		// prefix. This is narrower than the historical matcher on purpose.
		{"include /app matches /app", inc("/app"), "http://example.com/app", true, ""},
		{"include /app matches /app/x", inc("/app"), "http://example.com/app/x", true, ""},
		{"include /app rejects /application", inc("/app"), "http://example.com/application", false, "segment boundary"},
		{"include /app rejects /app-admin", inc("/app"), "http://example.com/app-admin", false, "segment boundary"},
		{"include /app/ rejects /app", inc("/app/"), "http://example.com/app", false, "no trailing-slash equivalence"},
		{"include /app/ matches /app/x", inc("/app/"), "http://example.com/app/x", true, ""},
		{"include is case-sensitive", inc("/app"), "http://example.com/App", false, "paths are case-sensitive; hosts are not"},
		{"empty path is /", inc("/"), "http://example.com", true, ""},
		// Exclusions deliberately over-block. A trailing slash no longer
		// narrows an exclusion, and the comparison is ASCII case-insensitive.
		{"exclude /admin blocks /administrator", exc("/admin"), "http://example.com/administrator", false, "over-blocks: safe direction"},
		{"exclude /admin/ blocks /admin", exc("/admin/"), "http://example.com/admin", false, "trailing slash is ignored"},
		{"exclude /admin blocks /Admin", exc("/admin"), "http://example.com/Admin", false, "ASCII case-insensitive exclusion"},
		{"exclude beats include", Scope{IncludeHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/app"}, ExcludePathPrefixes: []string{"/app/private"}}, "http://example.com/app/private/x", false, ""},
		// Ambiguous traversal/encoding is denied before include/exclude rules.
		{"literal dot segment rejected", inc("/app"), "http://example.com/app/../secret", false, "SafeScopePath rejects dot segments"},
		{"encoded dot segment rejected", inc("/app"), "http://example.com/app/%2e%2e/secret", false, "SafeScopePath rejects %2e"},
		{"encoded slash rejected", inc("/app"), "http://example.com/app%2fx", false, "SafeScopePath rejects %2f"},
		{"encoded backslash rejected", inc("/app"), "http://example.com/app/%5c..%5csecret", false, "SafeScopePath rejects %5c"},
		{"double encoded dot rejected", inc("/app"), "http://example.com/app/%252e%252e/secret", false, "residual %XX is double encoding"},
		{"duplicate slash rejected", inc("/app"), "http://example.com/app//x", false, "ambiguous slash"},
		{"dot path parameter rejected", inc("/app"), "http://example.com/app/..;/secret", false, "path parameter can change routing"},
		{"host-only still rejects ambiguous path", hosts("example.com"), "http://example.com/app/%2e%2e/secret", false, "SafeScopePath applies even without include prefixes"},
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

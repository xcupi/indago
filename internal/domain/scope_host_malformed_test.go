package domain

import "testing"

// A host-only boundary sees an authority string, not a URL. Anything that is
// not a well-formed host, host:port, bare IPv6 or [IPv6][:port] must be refused
// outright, never normalized into an included host: lenient bracket trimming
// would turn "[example.com" or "[[example.com]]" into a permitted example.com.
func TestPermitsHostRefusesMalformedAuthorities(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"example.com", "::1", "127.0.0.1"}, AllowSubdomains: true}
	for _, h := range []string{
		"[example.com", "example.com]", "[[example.com]]", "[example.com]", "[example.com]:443",
		"[::1", "::1]", "[[::1]]", "[::1]x", "[::1]:", "[::1]:99999", "[::1]:abc", "[::1]::443",
		"example.com:", "example.com:abc", "example.com:99999", "example.com:443:443",
		"example.com:-1", ":443", "[]", "[]:443", ":", "::",
		"exa mple.com", " example.com ", "example.com\t", "example.com/", "example.com/path",
		"user@example.com", "example.com?x", "example.com#x", "example.com\\", "http://example.com",
		"127.0.0.1:80:80", "1:2:3",
	} {
		if sc.PermitsHost(h) {
			t.Errorf("malformed authority %q accepted", h)
		}
	}
}

// Parity controls: the well-formed spellings keep their pre-existing behavior.
func TestPermitsHostAcceptsWellFormedAuthorities(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"example.com", "::1", "127.0.0.1"}, ExcludeHosts: []string{"admin.example.com"}, AllowSubdomains: true}
	for h, want := range map[string]bool{
		"example.com": true, "EXAMPLE.com": true, "example.com:443": true, "a.example.com:8443": true,
		"127.0.0.1": true, "127.0.0.1:8080": true, "127.0.0.2:8080": false,
		"::1": true, "[::1]": true, "[::1]:443": true, "[::2]:443": false,
		"admin.example.com": false, "admin.example.com:443": false,
		"evilexample.com": false, "example.com.evil.net:443": false, "other.example:443": false,
	} {
		if got := sc.PermitsHost(h); got != want {
			t.Errorf("PermitsHost(%q) = %v, want %v", h, got, want)
		}
	}
}

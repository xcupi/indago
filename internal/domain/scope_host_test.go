package domain

import "testing"

// PermitsHost is the host-only half of Permits, for a boundary that sees only
// host:port (a proxy CONNECT carries no path). It must agree with Permits on every
// host rule, and must NOT be stricter than Permits for a scope with path rules.

func TestPermitsHostAgreesWithPermitsOnHostRules(t *testing.T) {
	scopes := map[string]Scope{
		"single":        {IncludeHosts: []string{"example.com"}},
		"subdomains":    {IncludeHosts: []string{"example.com"}, AllowSubdomains: true},
		"leading-dot":   {IncludeHosts: []string{".example.com"}},
		"excluded":      {IncludeHosts: []string{"example.com"}, ExcludeHosts: []string{"admin.example.com"}, AllowSubdomains: true},
		"ip":            {IncludeHosts: []string{"127.0.0.1"}},
		"ipv6":          {IncludeHosts: []string{"::1"}},
		"mixed-case":    {IncludeHosts: []string{"Example.COM"}},
		"empty":         {},
		"only-excluded": {ExcludeHosts: []string{"example.com"}},
	}
	hosts := []string{
		"example.com", "EXAMPLE.com", "a.example.com", "a.b.example.com", "admin.example.com",
		"evilexample.com", "example.com.evil.net", "example.com.", "127.0.0.1", "127.0.0.2",
		"::1", "localhost", "", "2130706433", "xn--bcher-kva.example",
	}
	for name, sc := range scopes {
		for _, h := range hosts {
			urlHost := h
			if len(h) > 0 && h[0] == ':' {
				urlHost = "[" + h + "]"
			}
			want := sc.Permits("http://" + urlHost + "/").Allowed
			if got := sc.PermitsHost(h); got != want {
				t.Errorf("scope %q host %q: PermitsHost=%v but Permits(root)=%v", name, h, got, want)
			}
		}
	}
}

func TestPermitsHostIgnoresPathRulesThatPermitsEnforces(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/app/"}, ExcludePathPrefixes: []string{"/app/private"}}
	if sc.Permits("https://example.com/").Allowed {
		t.Fatal("setup: the root path is outside the include prefix")
	}
	// A CONNECT to example.com:443 carries no path. Refusing it would make the
	// in-scope /app/ unreachable, so the host-level boundary must allow it.
	if !sc.PermitsHost("example.com") {
		t.Fatal("a host with an in-scope path prefix must be reachable at the network boundary")
	}
	if sc.PermitsHost("other.example") {
		t.Fatal("a host that is not included must stay refused")
	}
}

func TestPermitsHostExcludedHostBeatsIncludedAndPathRules(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"example.com"}, ExcludeHosts: []string{"example.com"}, IncludePathPrefixes: []string{"/"}}
	if sc.PermitsHost("example.com") {
		t.Fatal("an excluded host is never reachable")
	}
}

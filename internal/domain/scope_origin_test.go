package domain

// Scheme/port restriction: what an explicit origin list adds on top of the
// historical hostname-only decision. The legacy behaviour (any scheme, any
// port) is pinned separately in scope_semantics_test.go; this file pins the
// narrowing and its fail-closed edges.

import (
	"slices"
	"strings"
	"testing"
)

func originScope(origins ...string) Scope {
	return Scope{IncludeHosts: []string{"app.example.com"}, AllowedOrigins: origins}
}

func TestScopeOriginAllowsOnlyTheDeclaredOrigin(t *testing.T) {
	sc := originScope("https://app.example.com")
	cases := []struct {
		url  string
		want bool
	}{
		{"https://app.example.com/", true},
		{"https://app.example.com:443/x?q=1", true},
		{"https://APP.EXAMPLE.COM/", true},
		{"HTTPS://app.example.com/", true},
		{"https://user:pass@app.example.com/", true}, // origin is the host
		{"http://app.example.com/", false},           // scheme differs
		{"https://app.example.com:8443/", false},     // port differs
		{"https://app.example.com:80/", false},
		{"ftp://app.example.com/", false}, // not an http(s) origin
		{"wss://app.example.com/", false},
	}
	for _, tc := range cases {
		if got := sc.Permits(tc.url).Allowed; got != tc.want {
			t.Errorf("Permits(%q) = %v, want %v (reason: %s)", tc.url, got, tc.want, sc.Permits(tc.url).Reason)
		}
	}
}

func TestScopeOriginHonoursExplicitNonDefaultPort(t *testing.T) {
	sc := originScope("https://app.example.com:8443")
	if d := sc.Permits("https://app.example.com:8443/"); !d.Allowed {
		t.Fatalf("declared origin denied: %+v", d)
	}
	if d := sc.Permits("https://app.example.com/"); d.Allowed {
		t.Fatal("the default 443 must not be authorized when only :8443 is declared")
	}
	if d := sc.Permits("http://app.example.com:8443/"); d.Allowed {
		t.Fatal("the scheme must still match; http on the same port is a different origin")
	}

	// An origin list is per entry: one explicit port plus the default port for
	// another scheme is two entries.
	both := originScope("https://app.example.com:8443", "http://app.example.com")
	if d := both.Permits("http://app.example.com/"); !d.Allowed {
		t.Fatalf("http entry denied: %+v", d)
	}
	if d := both.Permits("https://app.example.com:8443/"); !d.Allowed {
		t.Fatalf("https entry denied: %+v", d)
	}
	if d := both.Permits("https://app.example.com/"); d.Allowed {
		t.Fatal("https 443 was never declared")
	}
}

func TestScopeOriginWildcardIsStrictSubdomainsOnly(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"example.com"}, AllowSubdomains: true, AllowedOrigins: []string{"https://*.example.com"}}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://a.example.com/", true},
		{"https://a.b.example.com/", true},
		{"https://example.com/", false}, // a wildcard never covers its apex
		{"https://evilexample.com/", false},
		{"https://a.example.com.evil.net/", false},
		{"http://a.example.com/", false},
		{"https://a.example.com:8443/", false},
	}
	for _, tc := range cases {
		if got := sc.Permits(tc.url).Allowed; got != tc.want {
			t.Errorf("Permits(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
	// The apex is authorized by adding an exact entry, not by rewriting the
	// wildcard.
	sc.AllowedOrigins = append(sc.AllowedOrigins, "https://example.com")
	if d := sc.Permits("https://example.com/"); !d.Allowed {
		t.Fatalf("explicit apex entry denied: %+v", d)
	}
}

func TestScopeOriginIsAdditiveToHostAndPathRules(t *testing.T) {
	sc := originScope("https://app.example.com")
	sc.IncludePathPrefixes = []string{"/app"}
	if d := sc.Permits("https://app.example.com/app/x"); !d.Allowed {
		t.Fatalf("/app denied: %+v", d)
	}
	if d := sc.Permits("https://app.example.com/other"); d.Allowed {
		t.Fatal("origin rules must not bypass the include path prefix")
	}

	// An origin for a host the host rules deny can never match: the host check
	// runs first, exactly as before.
	other := Scope{IncludeHosts: []string{"app.example.com"}, AllowedOrigins: []string{"https://api.example.com"}}
	if d := other.Permits("https://api.example.com/"); d.Allowed {
		t.Fatal("an origin entry must not authorize a host the scope never included")
	}

	// Exclusions still win over an authorized origin.
	excluded := Scope{
		IncludeHosts:   []string{"app.example.com"},
		ExcludeHosts:   []string{"app.example.com"},
		AllowedOrigins: []string{"https://app.example.com"},
	}
	if d := excluded.Permits("https://app.example.com/"); d.Allowed {
		t.Fatal("an exclusion must beat an origin entry")
	}
}

func TestScopeOriginLegacyCompatibility(t *testing.T) {
	// No origin list: the historical hostname-only decision, including another
	// port and another scheme. This is what every pre-existing scope has.
	sc := Scope{IncludeHosts: []string{"app.example.com"}}
	for _, u := range []string{
		"http://app.example.com/",
		"https://app.example.com:8443/",
		"ftp://app.example.com/",
	} {
		if d := sc.Permits(u); !d.Allowed {
			t.Errorf("legacy scope denied %q: %+v", u, d)
		}
	}
	// AllowAnySchemePorts records the same legacy choice explicitly; it must
	// not change the answer.
	sc.AllowAnySchemePorts = true
	if d := sc.Permits("http://app.example.com:8080/"); !d.Allowed {
		t.Fatalf("explicit any-scheme-port scope denied its host: %+v", d)
	}
}

func TestScopeOriginWinsOverAllowAnySchemePorts(t *testing.T) {
	// A hand-edited row could carry both. Fail closed: the origin list is the
	// narrower statement and is always enforced.
	sc := originScope("https://app.example.com")
	sc.AllowAnySchemePorts = true
	if d := sc.Permits("https://app.example.com:8443/"); d.Allowed {
		t.Fatal("a conflicting any-scheme flag must not disable the origin list")
	}
	if d := sc.Permits("https://app.example.com/"); !d.Allowed {
		t.Fatalf("the declared origin was denied: %+v", d)
	}
}

func TestScopeOriginIPv6(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"::1"}, AllowedOrigins: []string{"http://[::1]:8080"}}
	if d := sc.Permits("http://[::1]:8080/x"); !d.Allowed {
		t.Fatalf("IPv6 origin denied: %+v", d)
	}
	if d := sc.Permits("http://[::1]/x"); d.Allowed {
		t.Fatal("the default port was not declared")
	}
	if d := sc.Permits("https://[::1]:8080/x"); d.Allowed {
		t.Fatal("the scheme was not declared")
	}
}

func TestPermitsHostAppliesOriginPorts(t *testing.T) {
	sc := originScope("https://app.example.com", "http://app.example.com:8080")
	if !sc.PermitsHost("app.example.com:443") {
		t.Fatal("the https default port should be authorized at the authority boundary")
	}
	if !sc.PermitsHost("app.example.com:8080") {
		t.Fatal("the explicit http port should be authorized at the authority boundary")
	}
	if sc.PermitsHost("app.example.com:8443") {
		t.Fatal("an undeclared port must be refused at the authority boundary")
	}
	if sc.PermitsHost("app.example.com") {
		t.Fatal("a bare authority has no port to check; with origin rules it must fail closed")
	}
	if sc.PermitsHost("other.example.com:443") {
		t.Fatal("an undeclared host must still be refused")
	}
}

func TestPermitsHostLegacyKeepsIgnoringPort(t *testing.T) {
	sc := Scope{IncludeHosts: []string{"app.example.com"}}
	if !sc.PermitsHost("app.example.com:8443") || !sc.PermitsHost("app.example.com") {
		t.Fatal("a legacy scope must keep its host-only authority behaviour")
	}
}

func TestParseScopeOriginAcceptsAndCanonicalises(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com":        "https://app.example.com",
		"HTTPS://App.Example.COM/":       "https://app.example.com",
		"https://app.example.com:443":    "https://app.example.com",
		"http://app.example.com:80":      "http://app.example.com",
		"https://app.example.com:8443":   "https://app.example.com:8443",
		"http://*.example.com":           "http://*.example.com",
		"https://*.example.com:9443":     "https://*.example.com:9443",
		"http://[::1]:8080":              "http://[::1]:8080",
		"https://127.0.0.1":              "https://127.0.0.1",
		"https://example.com:1":          "https://example.com:1",
		"https://example.com:65535":      "https://example.com:65535",
		"https://sub.example.com:8443/":  "https://sub.example.com:8443",
		"http://xn--bcher-kva.example":   "http://xn--bcher-kva.example",
		"https://under_score.example.co": "https://under_score.example.co",
	}
	for raw, want := range cases {
		o, ok := ParseScopeOrigin(raw)
		if !ok {
			t.Errorf("ParseScopeOrigin(%q) rejected a valid origin", raw)
			continue
		}
		if got := o.String(); got != want {
			t.Errorf("ParseScopeOrigin(%q).String() = %q, want %q", raw, got, want)
		}
		if err := ValidateScopeOrigin(raw); err != nil {
			t.Errorf("ValidateScopeOrigin(%q) = %v", raw, err)
		}
	}
}

func TestValidateScopeOriginRejectsShapesThatCannotMatch(t *testing.T) {
	cases := []struct{ entry, hint string }{
		{"", "empty"},
		{"app.example.com", "scheme://host"},
		{"app.example.com:8443", "scheme://host"},
		{"ftp://app.example.com", "not supported"},
		{"file://app.example.com", "not supported"},
		{"https://app.example.com/path", "path"},
		{"https://app.example.com/?x=1", "query"},
		{"https://app.example.com/#frag", "fragment"},
		{"https://user:pass@app.example.com", "credentials"},
		{"https://app.example.com:", "empty port"},
		{"https://app.example.com:0", "port"},
		{"https://app.example.com:65536", "port"},
		{"https://app.example.com:abc", "valid origin"},
		{"https://*", "wildcard"},
		{"https://*.example.*", "wildcard"},
		{"https://*example.com", "wildcard"},
		{"https://.example.com", "subdomains only"},
		{"https://*.127.0.0.1", "IP address"},
		{"https://app.example.com.", "trailing dot"},
		{"https://app example.com", "valid origin"},
		{" https://app.example.com", "whitespace"},
		{"https://app.example.com ", "whitespace"},
	}
	for _, tc := range cases {
		err := ValidateScopeOrigin(tc.entry)
		if err == nil {
			t.Errorf("ValidateScopeOrigin(%q) accepted an entry that cannot match", tc.entry)
			continue
		}
		if !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("ValidateScopeOrigin(%q) message %q should mention %q", tc.entry, err.Error(), tc.hint)
		}
	}
}

func TestValidateScopeOriginsRequiresAnAuthorizedHost(t *testing.T) {
	include := []string{"app.example.com", ".svc.example.com"}
	subOnly := []string{"wild.example.com"}
	ok := []string{
		"https://app.example.com",
		"http://app.example.com:8080",
		"https://svc.example.com",   // leading-dot include: apex
		"https://x.svc.example.com", // leading-dot include: subdomain
		"https://a.wild.example.com",
		"https://*.wild.example.com",
		"https://*.svc.example.com",
	}
	if err := ValidateScopeOrigins(ok, include, subOnly, false); err != nil {
		t.Fatalf("valid origins rejected: %v", err)
	}
	bad := []struct{ entry, hint string }{
		{"https://other.example.com", "not authorized"},
		{"https://example.com", "not authorized"},
		{"https://wild.example.com", "not authorized"}, // subdomain-only never covers the apex
		{"https://a.b.example.com:8443", "not authorized"},
	}
	for _, tc := range bad {
		err := ValidateScopeOrigins([]string{tc.entry}, include, subOnly, false)
		if err == nil {
			t.Errorf("ValidateScopeOrigins accepted %q for a host the scope never authorizes", tc.entry)
			continue
		}
		if !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("ValidateScopeOrigins(%q) message %q should mention %q", tc.entry, err.Error(), tc.hint)
		}
	}
	// A wildcard origin needs a host rule that covers a concrete subdomain.
	if err := ValidateScopeOrigins([]string{"https://*.example.com"}, []string{"app.example.com"}, nil, false); err == nil {
		t.Error("a wildcard origin over an unrelated base must be refused")
	}
	// allow_subdomains makes a bare include host cover subdomains too.
	if err := ValidateScopeOrigins([]string{"https://a.example.com"}, []string{"example.com"}, nil, true); err != nil {
		t.Errorf("allow_subdomains should authorize the derived subdomain origin: %v", err)
	}
}

func TestNormalizeScopeOriginsDedupesAndSorts(t *testing.T) {
	got, err := NormalizeScopeOrigins([]string{
		"https://app.example.com:443",
		"https://APP.example.com",
		"http://app.example.com",
		"",
		"  ",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://app.example.com", "https://app.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("normalised origins = %v, want %v", got, want)
	}
	if _, err := NormalizeScopeOrigins([]string{"app.example.com"}); err == nil {
		t.Fatal("a bare host is not an origin")
	} else if !strings.Contains(err.Error(), "allowed_origins[0]") {
		t.Fatalf("error should name the field and index: %v", err)
	}
}

func TestDeclaredOriginsRoundTripThroughValidation(t *testing.T) {
	// An operator-declared list must validate against its own host lists and
	// permit exactly what it names. There is no derived default to test: the
	// write surfaces never invent an origin (see docs/scope-semantics.md).
	for _, tc := range []struct {
		include   []string
		subOnly   []string
		subs      bool
		origins   []string
		permitted string
		denied    string
	}{
		{[]string{"example.com"}, nil, false, []string{"https://example.com"}, "https://example.com/", "https://example.com:8443/"},
		{[]string{".example.com"}, nil, false, []string{"https://*.example.com", "https://example.com"}, "https://a.example.com/", "http://a.example.com/"},
		{nil, []string{"example.com"}, false, []string{"https://*.example.com"}, "https://a.example.com/", "https://example.com/"},
		{[]string{"::1"}, nil, false, []string{"http://[::1]:8080"}, "http://[::1]:8080/", "http://[::1]/"},
	} {
		if err := ValidateScopeOrigins(tc.origins, tc.include, tc.subOnly, tc.subs); err != nil {
			t.Fatalf("declared origins %v do not validate: %v", tc.origins, err)
		}
		sc := Scope{IncludeHosts: tc.include, SubdomainOnlyHosts: tc.subOnly, AllowSubdomains: tc.subs, AllowedOrigins: tc.origins}
		if d := sc.Permits(tc.permitted); !d.Allowed {
			t.Errorf("scope denied %q: %+v", tc.permitted, d)
		}
		if d := sc.Permits(tc.denied); d.Allowed {
			t.Errorf("scope allowed %q", tc.denied)
		}
	}
}

// Each permission is bound to ONE host pattern. A scheme or port declared for
// one asset must never combine with another asset's host, and two assets must
// never cross-multiply into a shape neither of them declared.
func TestScopeOriginNeverCrossesHostsOrAssets(t *testing.T) {
	sc := Scope{
		IncludeHosts: []string{"a.example.com", "b.example.com"},
		AllowedOrigins: []string{
			"https://a.example.com:8443",
			"http://b.example.com:8080",
		},
	}
	allowed := []string{
		"https://a.example.com:8443/",
		"http://b.example.com:8080/x",
	}
	for _, u := range allowed {
		if d := sc.Permits(u); !d.Allowed {
			t.Errorf("declared origin %q denied: %+v", u, d)
		}
	}
	denied := []string{
		"http://a.example.com:8443/",  // scheme borrowed from b
		"https://a.example.com:8080/", // port borrowed from b
		"https://a.example.com/",      // 443 was never declared
		"http://b.example.com:8443/",  // port declared for a, not b
		"https://b.example.com:8080/", // scheme declared for a, not b
		"https://b.example.com:8443/", // both borrowed from a
		"http://b.example.com/",       // 80 was never declared
	}
	for _, u := range denied {
		if d := sc.Permits(u); d.Allowed {
			t.Errorf("cross-asset widening: %q was allowed (%s)", u, d.Reason)
		}
	}
}

// A wildcard origin is bound to its own base: it must not authorize an exact
// origin declared for a different host, or a port declared for that host.
func TestScopeOriginWildcardDoesNotBorrowSiblingOrigins(t *testing.T) {
	sc := Scope{
		IncludeHosts:    []string{"example.com", "other.test"},
		AllowSubdomains: true,
		AllowedOrigins: []string{
			"https://*.example.com",
			"http://other.test:8080",
		},
	}
	if d := sc.Permits("https://a.example.com/"); !d.Allowed {
		t.Fatalf("wildcard subdomain denied: %+v", d)
	}
	for _, u := range []string{
		"http://a.example.com:8080/",  // port from other.test
		"https://a.example.com:8080/", // port from other.test, https
		"https://other.test/",         // scheme/port declared for example.com's wildcard? no
	} {
		if d := sc.Permits(u); d.Allowed {
			t.Errorf("cross-asset widening through a wildcard: %q allowed", u)
		}
	}
}

// The CONNECT boundary sees only host:port: it can enforce the port but not the
// scheme. A port declared for the host under EITHER scheme is accepted; a port
// declared for a different host is not, and a bare authority cannot prove a
// declared origin.
func TestPermitsHostConnectBoundaryIsPortBound(t *testing.T) {
	sc := Scope{
		IncludeHosts: []string{"a.example.com", "b.example.com"},
		AllowedOrigins: []string{
			"https://a.example.com:8443",
			"http://b.example.com",
		},
	}
	allowed := []string{"a.example.com:8443", "b.example.com:80"}
	for _, h := range allowed {
		if !sc.PermitsHost(h) {
			t.Errorf("CONNECT authority %q denied although its host+port is declared", h)
		}
	}
	denied := []string{
		"a.example.com:443",  // default port of a was never declared
		"a.example.com:80",   // port declared for b, not a
		"b.example.com:443",  // scheme blind spot does not invent 443
		"b.example.com:8443", // port declared for a, not b
		"a.example.com",      // no port to check → fail closed
		"c.example.com:8443", // host not in scope
	}
	for _, h := range denied {
		if sc.PermitsHost(h) {
			t.Errorf("CONNECT authority %q allowed although no origin declares its host+port", h)
		}
	}
}

func TestScopeOriginNormalisesDefaultPorts(t *testing.T) {
	sc := Scope{
		IncludeHosts:   []string{"a.example.com"},
		AllowedOrigins: []string{"https://a.example.com", "http://a.example.com:8080"},
	}
	for _, u := range []string{"https://a.example.com/", "https://a.example.com:443/x"} {
		if d := sc.Permits(u); !d.Allowed {
			t.Errorf("default https port %q denied: %+v", u, d)
		}
	}
	for _, u := range []string{"https://a.example.com:80/", "http://a.example.com/"} {
		if d := sc.Permits(u); d.Allowed {
			t.Errorf("un-normalised origin %q allowed", u)
		}
	}
	o, ok := ParseScopeOrigin("https://a.example.com:443")
	if !ok || o.String() != "https://a.example.com" || o.Port != 443 {
		t.Fatalf("default-port entry not normalised: %+v (%q)", o, o.String())
	}
}

// The empty origin list is a real stored MODE, not an unconfigured field. The
// matcher must keep it as the legacy any-scheme/any-port authority (so old
// scopes survive an upgrade); the write surfaces are what refuse to create a
// new one. This pins the matcher half so a refactor cannot turn "empty" into
// "deny everything" or into a guessed standard-port rule.
func TestScopeOriginEmptyListIsLegacyMode(t *testing.T) {
	legacy := Scope{IncludeHosts: []string{"a.example.com"}}
	if !legacy.LegacySchemePorts() {
		t.Fatal("an empty list with no opt-out must read as the legacy shape")
	}
	for _, u := range []string{
		"http://a.example.com/",
		"http://a.example.com:8443/",
		"https://a.example.com:65535/",
		"ftp://a.example.com/",
	} {
		if d := legacy.Permits(u); !d.Allowed {
			t.Errorf("legacy empty-list scope denied %q: %+v", u, d)
		}
	}
	// The host-only boundary keeps the same answer, including a bare authority
	// and an arbitrary port. It has no scheme to check either.
	for _, h := range []string{"a.example.com", "a.example.com:1", "a.example.com:8443"} {
		if !legacy.PermitsHost(h) {
			t.Errorf("legacy empty-list scope denied authority %q", h)
		}
	}

	// The explicit annotation is the same authority but is not the legacy
	// stored shape; a write surface created it on purpose.
	explicit := Scope{IncludeHosts: []string{"a.example.com"}, AllowAnySchemePorts: true}
	if explicit.LegacySchemePorts() {
		t.Fatal("an explicit any-scheme/port scope must not read as legacy")
	}
	if d := explicit.Permits("http://a.example.com:8443/"); !d.Allowed {
		t.Fatalf("explicit any-scheme/port scope denied its host: %+v", d)
	}

	// A non-empty list is never legacy, and it enforces even if the annotation
	// was hand-edited onto the row.
	restricted := Scope{
		IncludeHosts:        []string{"a.example.com"},
		AllowedOrigins:      []string{"https://a.example.com"},
		AllowAnySchemePorts: true,
	}
	if restricted.LegacySchemePorts() {
		t.Fatal("a scope with an origin list is not legacy")
	}
	if d := restricted.Permits("http://a.example.com/"); d.Allowed {
		t.Fatalf("the origin list was ignored in favour of the annotation: %+v", d)
	}
}

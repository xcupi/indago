package domain

// Scheme/port restriction for a scope.
//
// Historically a scope compared the HOSTNAME only: a host that was in scope was
// in scope on every scheme and every port (docs/scope-semantics.md). That is too
// wide for a bug-bounty program whose asset list authorizes one web origin
// (https://app.example.com) while the same machine may also expose an internal
// admin service on another port, or plaintext HTTP.
//
// A scope may now carry an explicit origin list. An entry is
// "scheme://host[:port]":
//
//   - scheme is http or https (the only schemes Indago requests);
//   - an omitted port means the scheme's default (80 for http, 443 for https);
//   - host is a bare hostname/IP, or "*.example.com" for STRICT subdomains
//     (never the apex; use an additional exact entry for the apex).
//
// When the list is non-empty it is an ADDITIONAL requirement on top of the
// existing host/path rules: a URL must pass the host and path checks AND its
// scheme + effective port must match an entry whose host pattern covers it.
// The origin list can therefore only narrow a scope, never widen it, and it
// never changes the path-prefix rules.
//
// Precedence, deliberately fail-closed:
//
//	AllowedOrigins non-empty          -> enforce it (even if AllowAnySchemePorts
//	                                     was also set by a hand-edited row)
//	AllowedOrigins empty              -> legacy host-only behaviour: any scheme,
//	                                     any port. This is what every scope
//	                                     saved before this feature has, and it is
//	                                     preserved so an upgrade cannot loosen or
//	                                     silently break an existing scope.
//
// AllowAnySchemePorts does not widen the matcher; it is the explicit annotation
// the write surfaces (API/CLI/UI/importer) record when an operator knowingly
// chose the legacy behaviour.
//
// WRITE POLICY — Indago never derives an origin. No write surface guesses a
// scheme or port for a host:
//
//   - a new scope must state either the exact origins it may be reached on or
//     AllowAnySchemePorts; an empty origin list is refused, because "no list"
//     means "every scheme and port" to the matcher;
//   - adding a host to an existing scope never inherits, expands or re-derives
//     an origin; the host must be covered by a declared origin (or the scope
//     must carry the explicit any-scheme/any-port statement), and an uncovered
//     host is refused at save time instead of being silently unreachable;
//   - editing a path prefix, an exclusion or any other non-host field never
//     touches the origin list, so an https-only scope cannot widen to plain
//     http (or to another port) because some unrelated field changed;
//   - an entry whose host left the scope is dropped, which can only narrow.
//
// The empty-list shape therefore survives only as the LEGACY state of a scope
// saved before origin rules existed (see Scope.LegacySchemePorts).

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ScopeOrigin is one parsed allowed-origin entry.
type ScopeOrigin struct {
	Scheme   string // "http" or "https" (lowercase)
	Host     string // lowercase bare hostname; for Wildcard, the base host
	Port     int    // effective port: explicit, or 80/443 when omitted
	Wildcard bool   // "*.base": strict subdomains of Host, never Host itself
}

// String renders the canonical form: the default port is omitted, an IPv6
// literal is bracketed, and a wildcard host keeps its "*." prefix.
func (o ScopeOrigin) String() string {
	host := o.Host
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		host = "[" + host + "]"
	}
	if o.Wildcard {
		host = "*." + host
	}
	s := o.Scheme + "://" + host
	if o.Port != defaultSchemePort(o.Scheme) {
		s += ":" + strconv.Itoa(o.Port)
	}
	return s
}

// permitsHost reports whether this origin's host pattern covers host. The
// comparison is exact for a normal entry and a strict-dot-boundary subdomain
// test for a wildcard, so "*.example.com" never covers "example.com" or
// "evilexample.com".
func (o ScopeOrigin) permitsHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if o.Wildcard {
		return IsStrictSubdomain(host, o.Host)
	}
	return host == o.Host
}

func defaultSchemePort(scheme string) int {
	if strings.EqualFold(scheme, "http") {
		return 80
	}
	return 443
}

// ParseScopeOrigin parses one allowed-origin entry. It is strict: a shape that
// cannot be matched exactly as written (a path, query, fragment, credentials,
// a non-http(s) scheme, a bad port, a bare "*", a trailing dot) is refused
// rather than being normalised into something the operator did not write.
func ParseScopeOrigin(entry string) (ScopeOrigin, bool) {
	o, err := parseScopeOrigin(entry)
	return o, err == nil
}

// ValidateScopeOrigin reports why entry cannot be an allowed-origin entry, or
// nil. Every accepted entry can match its own origin (tested).
func ValidateScopeOrigin(entry string) error {
	_, err := parseScopeOrigin(entry)
	return err
}

func parseScopeOrigin(entry string) (ScopeOrigin, error) {
	raw := strings.TrimSpace(entry)
	if raw == "" {
		return ScopeOrigin{}, fmt.Errorf("origin is empty")
	}
	if raw != entry {
		return ScopeOrigin{}, fmt.Errorf("%q has leading or trailing whitespace", entry)
	}
	if !strings.Contains(raw, "://") {
		return ScopeOrigin{}, fmt.Errorf("%q must be written scheme://host[:port], for example %q", entry, "https://"+strings.TrimPrefix(raw, "//"))
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ScopeOrigin{}, fmt.Errorf("%q is not a valid origin (scheme://host[:port])", entry)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ScopeOrigin{}, fmt.Errorf("%q: scheme %q is not supported; an origin is http or https", entry, u.Scheme)
	}
	if u.User != nil {
		return ScopeOrigin{}, fmt.Errorf("%q must not contain credentials", entry)
	}
	if u.RawQuery != "" {
		return ScopeOrigin{}, fmt.Errorf("%q contains a query string; an origin has no path, query or fragment", entry)
	}
	if u.Fragment != "" {
		return ScopeOrigin{}, fmt.Errorf("%q contains a fragment; an origin has no path, query or fragment", entry)
	}
	if u.Path != "" && u.Path != "/" {
		return ScopeOrigin{}, fmt.Errorf("%q contains a path; an origin is scheme://host[:port] only", entry)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ScopeOrigin{}, fmt.Errorf("%q has no host", entry)
	}
	// A trailing colon writes an empty port; it is not the same spelling as
	// "host", so refuse it rather than silently treating it as the default.
	if strings.HasSuffix(u.Host, ":") {
		return ScopeOrigin{}, fmt.Errorf("%q has an empty port; write the port or omit it entirely", entry)
	}
	wildcard := false
	if strings.HasPrefix(host, "*.") {
		wildcard = true
		host = strings.TrimPrefix(host, "*.")
	}
	if strings.Contains(host, "*") {
		return ScopeOrigin{}, fmt.Errorf("%q: a wildcard is only supported as a single leading %q label", entry, "*.")
	}
	if strings.HasPrefix(host, ".") {
		return ScopeOrigin{}, fmt.Errorf("%q: write %q for subdomains only", entry, "*."+strings.TrimPrefix(host, "."))
	}
	if err := ValidateScopeHost(host); err != nil {
		return ScopeOrigin{}, fmt.Errorf("%q: %v", entry, err)
	}
	if wildcard && net.ParseIP(host) != nil {
		return ScopeOrigin{}, fmt.Errorf("%q: %q is an IP address, which has no subdomains", entry, host)
	}
	port := 0
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return ScopeOrigin{}, fmt.Errorf("%q: port must be a number between 1 and 65535", entry)
		}
		port = n
	}
	if port == 0 {
		port = defaultSchemePort(scheme)
	}
	return ScopeOrigin{Scheme: scheme, Host: host, Port: port, Wildcard: wildcard}, nil
}

// NormalizeScopeOrigins validates every entry, drops duplicates and returns the
// canonical spellings. The empty slice is returned as an empty (non-nil) slice
// so callers can store it as [] rather than null.
func NormalizeScopeOrigins(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		o, err := parseScopeOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("allowed_origins[%d]: %v", i, err)
		}
		s := o.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// ValidateScopeOrigins validates every origin and proves that the scope's own
// host lists authorize the origin's host. An origin for a host the scope never
// authorizes would be dead weight at best and a misleading declaration at
// worst, so it is refused at save time instead of being stored.
//
// Path rules are intentionally not consulted: an origin is about scheme, host
// and port only, and path-prefix semantics are unchanged by this feature.
func ValidateScopeOrigins(entries, includeHosts, subdomainOnlyHosts []string, allowSubdomains bool) error {
	probe := Scope{
		IncludeHosts:       includeHosts,
		SubdomainOnlyHosts: subdomainOnlyHosts,
		AllowSubdomains:    allowSubdomains,
	}
	for i, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		o, err := parseScopeOrigin(raw)
		if err != nil {
			return fmt.Errorf("allowed_origins[%d]: %v", i, err)
		}
		host := o.Host
		if o.Wildcard {
			// A strict-subdomain pattern is only authorized when the scope's
			// host rules cover a concrete subdomain of it.
			host = "scope-probe." + host
		}
		authority := host + ":" + strconv.Itoa(o.Port)
		if net.ParseIP(host) != nil && strings.Contains(host, ":") {
			authority = "[" + host + "]:" + strconv.Itoa(o.Port)
		}
		if !probe.PermitsHost(authority) {
			return fmt.Errorf("allowed_origins[%d]: %q: host %q is not authorized by include_hosts or subdomain_only_hosts", i, raw, o.Host)
		}
	}
	return nil
}

// LegacySchemePorts reports whether this scope predates origin rules: it has no
// origin list and no explicit any-scheme/any-port annotation. Such a scope
// authorizes every scheme and port of its in-scope hosts (the historical
// behaviour), and it is the only state in which "no origins" is legal.
//
// Write surfaces never create this state: a save states an origin list or sets
// AllowAnySchemePorts. It is preserved for scopes saved before the feature so an
// upgrade cannot narrow (or widen) them behind the operator's back, and the UI
// shows it as legacy instead of pretending a scheme/port rule exists.
func (s Scope) LegacySchemePorts() bool {
	return len(s.AllowedOrigins) == 0 && !s.AllowAnySchemePorts
}

// FilterScopeOriginsByHosts keeps only the entries that still parse and whose
// host pattern is authorized by the given host lists. It is how a save that
// preserves the stored list reacts to a host leaving the scope (or to an
// allow_subdomains flip that no longer covers a wildcard entry): the entry is
// dropped instead of making the whole save fail, and dropping can only narrow.
//
// A malformed entry is dropped for the same reason: it already grants nothing at
// match time (see Scope.permitsOriginURL), so keeping it would only make the
// stored list disagree with what the scope actually permits.
func FilterScopeOriginsByHosts(entries, includeHosts, subdomainOnlyHosts []string, allowSubdomains bool) []string {
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if err := ValidateScopeOrigins([]string{raw}, includeHosts, subdomainOnlyHosts, allowSubdomains); err != nil {
			continue
		}
		o, ok := ParseScopeOrigin(raw)
		if !ok {
			continue
		}
		s := o.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// UncoveredScopeHosts returns the hosts the scope names that no declared origin
// can reach, in declaration order and without duplicates. It answers "would this
// host list be silently dead?" — the question a save must refuse rather than
// guess a scheme or port for.
//
//   - an include host (a leading dot keeps its historical meaning) is covered
//     when some origin matches the host itself; a wildcard origin never covers
//     its apex;
//   - a subdomain-only host is covered when some origin can match a strict
//     subdomain of it (a wildcard on or below it, or an exact/wildcard entry
//     that is itself a subdomain of it).
//
// An unparseable entry is ignored: it grants nothing, so it covers nothing.
func UncoveredScopeHosts(entries, includeHosts, subdomainOnlyHosts []string) []string {
	parsed := make([]ScopeOrigin, 0, len(entries))
	for _, raw := range entries {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if o, ok := ParseScopeOrigin(raw); ok {
			parsed = append(parsed, o)
		}
	}
	var out []string
	seen := map[string]bool{}
	report := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	for _, raw := range includeHosts {
		host := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "."))
		if host == "" {
			continue
		}
		covered := false
		for _, o := range parsed {
			if o.permitsHost(host) {
				covered = true
				break
			}
		}
		if !covered {
			report(host)
		}
	}
	for _, raw := range subdomainOnlyHosts {
		base := strings.ToLower(strings.TrimSpace(raw))
		if base == "" {
			continue
		}
		covered := false
		for _, o := range parsed {
			// A wildcard entry covers a subdomain of base when the pattern is
			// base itself or an ancestor of it ("*.example.com" also covers
			// a.api.example.com). An exact entry covers one when it sits below
			// base.
			if o.Wildcard && (o.Host == base || IsStrictSubdomain(base, o.Host)) {
				covered = true
				break
			}
			if !o.Wildcard && IsStrictSubdomain(o.Host, base) {
				covered = true
				break
			}
		}
		if !covered {
			report(base)
		}
	}
	return out
}

// originRulesActive reports whether this scope restricts scheme and port.
func (s Scope) originRulesActive() bool {
	return len(s.AllowedOrigins) > 0
}

// permitsOriginURL applies the origin list to a parsed URL. It returns a
// ScopeDecision so callers can report the same human-readable reason the rest of
// Permits uses. Callers must only invoke it when originRulesActive.
func (s Scope) permitsOriginURL(host string, u *url.URL) ScopeDecision {
	scheme := strings.ToLower(u.Scheme)
	port, ok := scopeURLPort(u)
	if !ok {
		return ScopeDecision{false, fmt.Sprintf("scheme %q is not authorized: origin rules allow http and https only", u.Scheme)}
	}
	for _, raw := range s.AllowedOrigins {
		o, ok := ParseScopeOrigin(raw)
		if !ok {
			continue // a malformed stored entry grants nothing
		}
		if o.Scheme == scheme && o.Port == port && o.permitsHost(host) {
			return ScopeDecision{true, "in scope"}
		}
	}
	return ScopeDecision{false, fmt.Sprintf("origin not authorized: %s://%s:%d", scheme, host, port)}
}

// permitsOriginAuthority applies the origin list at a boundary that sees only
// host[:port] (a proxy CONNECT). The scheme is unknown there, so an authority
// is permitted when its port is an authorized port for a matching origin host,
// under either scheme. It is narrower than the legacy host-only answer and can
// never authorize a port no origin entry names.
func (s Scope) permitsOriginAuthority(host, port string) bool {
	if port == "" {
		// Without a port the boundary cannot prove the authority is one of the
		// declared origins; fail closed.
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	for _, raw := range s.AllowedOrigins {
		o, ok := ParseScopeOrigin(raw)
		if !ok {
			continue
		}
		if o.Port == n && o.permitsHost(host) {
			return true
		}
	}
	return false
}

// scopeURLPort returns the effective port of a URL: its explicit port, or the
// default for http/https. A scheme without a port has no effective port here
// (and origin rules only authorize http/https).
func scopeURLPort(u *url.URL) (int, bool) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, false
		}
		return n, true
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80, true
	case "https":
		return 443, true
	default:
		return 0, false
	}
}

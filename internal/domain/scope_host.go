package domain

import (
	"net"
	"strings"
)

// PermitsHost is the host-only half of Permits, for a boundary that sees only
// host[:port] (a proxy CONNECT carries no path). It applies exactly Permits'
// host rules (include, exclude, subdomains, leading dot, subdomains-only) and
// FAILS CLOSED the same way: an empty scope, an empty host or an unmatched host
// is denied, and an excluded host always wins. Path rules are not evaluated,
// because the caller cannot know the path; a host with an in-scope path prefix
// is therefore reachable at this boundary, and every request that follows is
// still checked against the full Permits (path included) by the scope-enforcing
// engine. It is never more permissive than Permits on host rules.
//
// When the scope has an origin list, the authority's port must also be an
// authorized port for a matching origin host. The scheme is unknown here, so an
// authority is accepted when its port is declared for EITHER http or https; a
// bare host with no port cannot be proven to be a declared origin and is
// denied. This is narrower than the legacy answer and never wider.
func (s Scope) PermitsHost(host string) bool {
	name, port, ok := splitAuthorityHost(host)
	if !ok || (len(s.IncludeHosts) == 0 && len(s.SubdomainOnlyHosts) == 0) {
		return false
	}
	for _, ex := range s.ExcludeHosts {
		if hostMatches(name, strings.ToLower(ex), s.AllowSubdomains) {
			return false
		}
	}
	for _, in := range s.IncludeHosts {
		if hostMatches(name, strings.ToLower(in), s.AllowSubdomains) {
			return s.permitsAuthorityOriginOrLegacy(name, port)
		}
	}
	// A SubdomainOnlyHosts entry authorizes a strict subdomain and never the
	// host itself, exactly as Scope.Permits does (same helper, so the two
	// boundaries cannot disagree).
	for _, in := range s.SubdomainOnlyHosts {
		if IsStrictSubdomain(name, in) {
			return s.permitsAuthorityOriginOrLegacy(name, port)
		}
	}
	return false
}

// permitsAuthorityOriginOrLegacy applies the origin list at the host-only
// boundary; with no origin list it keeps the historical host-only answer.
func (s Scope) permitsAuthorityOriginOrLegacy(host, port string) bool {
	if !s.originRulesActive() {
		return true
	}
	return s.permitsOriginAuthority(host, port)
}

// splitAuthorityHost validates a bare authority and returns its lower-cased
// host and its port (empty when none was written). Accepted forms are exactly:
// name, name:port, IPv4, IPv4:port, a bare IPv6 literal, [IPv6] and
// [IPv6]:port. Everything else (unbalanced or nested brackets, a bracketed
// non-IPv6, empty or non-numeric ports, extra colons, whitespace, userinfo,
// paths, schemes) is refused rather than normalized, so a malformed string can
// never be reinterpreted as an included host.
func splitAuthorityHost(raw string) (host, port string, ok bool) {
	if raw == "" || strings.ContainsAny(raw, " 	\r\n/\\@?#%") {
		return "", "", false
	}
	host = raw
	switch {
	case strings.HasPrefix(raw, "["):
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", "", false
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", "", false
			}
			port = rest[1:]
			if port == "" {
				return "", "", false
			}
		}
		ip := net.ParseIP(host)
		if ip == nil || !strings.Contains(host, ":") {
			return "", "", false
		}
	case strings.ContainsAny(raw, "[]"):
		return "", "", false
	case strings.Count(raw, ":") == 1:
		i := strings.IndexByte(raw, ':')
		host, port = raw[:i], raw[i+1:]
		if port == "" {
			return "", "", false
		}
	case strings.Count(raw, ":") > 1:
		// A bare IPv6 literal carries no port.
		if net.ParseIP(raw) == nil {
			return "", "", false
		}
	}
	if host == "" {
		return "", "", false
	}
	if port != "" {
		n := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", "", false
			}
			if n = n*10 + int(c-'0'); n > 65535 {
				return "", "", false
			}
		}
	}
	return strings.ToLower(host), port, true
}

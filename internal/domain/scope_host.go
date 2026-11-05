package domain

import (
	"net"
	"strings"
)

// PermitsHost is the host-only half of Permits, for a boundary that sees only
// host[:port] (a proxy CONNECT carries no path). It applies exactly Permits'
// host rules (include, exclude, subdomains, leading dot) and FAILS CLOSED the
// same way: an empty scope, an empty host or an unmatched host is denied, and
// an excluded host always wins. Path rules are not evaluated, because the
// caller cannot know the path; a host with an in-scope path prefix is
// therefore reachable at this boundary, and every request that follows is
// still checked against the full Permits (path included) by the scope-enforcing
// engine. It is never more permissive than Permits on host rules.
func (s Scope) PermitsHost(host string) bool {
	host, ok := splitAuthorityHost(host)
	if !ok || len(s.IncludeHosts) == 0 {
		return false
	}
	for _, ex := range s.ExcludeHosts {
		if hostMatches(host, strings.ToLower(ex), s.AllowSubdomains) {
			return false
		}
	}
	for _, in := range s.IncludeHosts {
		if hostMatches(host, strings.ToLower(in), s.AllowSubdomains) {
			return true
		}
	}
	return false
}

// splitAuthorityHost validates a bare authority and returns its lower-cased
// host. Accepted forms are exactly: name, name:port, IPv4, IPv4:port, a bare
// IPv6 literal, [IPv6] and [IPv6]:port. Everything else (unbalanced or nested
// brackets, a bracketed non-IPv6, empty or non-numeric ports, extra colons,
// whitespace, userinfo, paths, schemes) is refused rather than normalized, so a
// malformed string can never be reinterpreted as an included host.
func splitAuthorityHost(raw string) (string, bool) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n/\\@?#%") {
		return "", false
	}
	host, port := raw, ""
	switch {
	case strings.HasPrefix(raw, "["):
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", false
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", false
			}
			port = rest[1:]
			if port == "" {
				return "", false
			}
		}
		ip := net.ParseIP(host)
		if ip == nil || !strings.Contains(host, ":") {
			return "", false
		}
	case strings.ContainsAny(raw, "[]"):
		return "", false
	case strings.Count(raw, ":") == 1:
		i := strings.IndexByte(raw, ':')
		host, port = raw[:i], raw[i+1:]
		if port == "" {
			return "", false
		}
	case strings.Count(raw, ":") > 1:
		// A bare IPv6 literal carries no port.
		if net.ParseIP(raw) == nil {
			return "", false
		}
	}
	if host == "" {
		return "", false
	}
	if port != "" {
		n := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", false
			}
			if n = n*10 + int(c-'0'); n > 65535 {
				return "", false
			}
		}
	}
	return strings.ToLower(host), true
}

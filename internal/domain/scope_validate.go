package domain

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"
)

// Scope entries are compared as plain strings against what a URL parses to
// (see Scope.Permits and docs/scope-semantics.md): include/exclude HOSTS against
// the URL's lowercase hostname, PATH prefixes against its decoded path. An entry
// written in any other shape does not error at match time; it just never
// matches, so the scope silently denies the host the operator meant. These
// validators reject such entries when the scope is SAVED, with a message that
// says how to write it.
//
// The rule is: reject exactly what cannot match. Anything accepted here can
// match its own host or path (tested), though it may still be broader or
// narrower than the operator expects (ports are ignored, path prefixes have no
// segment boundary): that is documented, not rejected.

// useHint renders ` use "x"` when an obvious canonical form exists.
func useHint(entry string) string {
	if s, ok := ScopeHostSuggestion(entry); ok {
		return fmt.Sprintf("; use %q", s)
	}
	return ""
}

// ValidateScopeHost reports why entry cannot be a scope host entry, or nil.
func ValidateScopeHost(entry string) error {
	if entry == "" {
		return fmt.Errorf("host entry is empty")
	}
	for _, r := range entry {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%q contains whitespace or a control character; write the bare hostname", entry)
		}
	}
	if strings.Contains(entry, "*") {
		return fmt.Errorf("%q: wildcards are not supported (a leading dot matches the host and all its subdomains, or enable allow_subdomains)%s", entry, useHint(entry))
	}
	if strings.ContainsAny(entry, `/\@?#`) || strings.Contains(entry, "://") {
		return fmt.Errorf("%q must be a bare hostname, without scheme, path, credentials, query or fragment%s", entry, useHint(entry))
	}
	if strings.ContainsAny(entry, "[]") {
		return fmt.Errorf("%q: write IPv6 addresses without brackets%s", entry, useHint(entry))
	}
	// Bare IP literals (including IPv6, which contains colons) are fine.
	if net.ParseIP(entry) != nil {
		return nil
	}
	if strings.Contains(entry, ":") {
		return fmt.Errorf("%q must not include a port: scope compares hostnames only and ignores the port%s", entry, useHint(entry))
	}
	trimmed := strings.TrimPrefix(entry, ".")
	if trimmed == "" {
		return fmt.Errorf("%q is empty after the leading dot", entry)
	}
	if strings.HasSuffix(trimmed, ".") {
		return fmt.Errorf("%q has a trailing dot; requests for the same host are reported without it, so it would never match%s", entry, useHint(entry))
	}
	labels := strings.Split(trimmed, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%q has an empty label (consecutive dots)", entry)
		}
	}
	for _, r := range trimmed {
		if r > unicode.MaxASCII {
			return fmt.Errorf("%q is not ASCII; browsers send hostnames in punycode (xn--) form, so enter that form", entry)
		}
	}
	// A host whose last label is numeric is parsed as an IPv4 address by
	// browsers (decimal, hex, short forms) and reported in dotted-quad form, so
	// only a real dotted-quad can match.
	if isNumericLabel(labels[len(labels)-1]) {
		return fmt.Errorf("%q looks like a non-standard IPv4 form that browsers normalise; write the dotted-quad address (for example 127.0.0.1)", entry)
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%q contains an invalid character %q", entry, r)
		}
	}
	return nil
}

func isNumericLabel(l string) bool {
	if l == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(l), "0x") {
		l = l[2:]
		for _, r := range l {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
		return true
	}
	for _, r := range l {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ScopeHostSuggestion proposes the entry an operator most likely meant, for the
// shapes that have an obvious canonical form. A returned suggestion is always
// itself valid.
func ScopeHostSuggestion(entry string) (string, bool) {
	e := strings.TrimSpace(entry)
	switch {
	case strings.Contains(e, "://"):
		u, err := url.Parse(e)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		e = u.Hostname()
	case strings.HasPrefix(e, "*."):
		e = "." + strings.TrimPrefix(e, "*.")
	case strings.HasPrefix(e, "["):
		end := strings.Index(e, "]")
		if end < 0 {
			return "", false
		}
		e = e[1:end]
	default:
		if i := strings.IndexAny(e, `/\?#`); i >= 0 {
			e = e[:i]
		}
		if at := strings.LastIndex(e, "@"); at >= 0 {
			e = e[at+1:]
		}
		if net.ParseIP(e) == nil {
			if host, _, err := net.SplitHostPort(e); err == nil {
				e = host
			} else {
				e = strings.TrimSuffix(e, ":")
			}
		}
	}
	e = strings.TrimSuffix(e, ".")
	if e == "" || e == entry || ValidateScopeHost(e) != nil {
		return "", false
	}
	return e, true
}

// ValidateScopePathPrefix reports why prefix cannot be a scope path prefix, or nil.
func ValidateScopePathPrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("path prefix is empty")
	}
	for _, r := range prefix {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%q contains whitespace or a control character", prefix)
		}
	}
	if strings.Contains(prefix, "://") {
		path := "/"
		if u, err := url.Parse(prefix); err == nil && u.Path != "" {
			path = u.Path
		}
		return fmt.Errorf("%q looks like a URL; a path prefix is only the path, for example %q", prefix, path)
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%q must start with %q to match anything; use %q", prefix, "/", "/"+prefix)
	}
	if strings.Contains(prefix, "?") {
		return fmt.Errorf("%q contains a query string; scope compares the path only, so it would never match", prefix)
	}
	if strings.Contains(prefix, "#") {
		return fmt.Errorf("%q contains a fragment; scope compares the path only, so it would never match", prefix)
	}
	for _, seg := range strings.Split(prefix, "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("%q contains a dot-segment; write the canonical path", prefix)
		}
	}
	return nil
}

package scopeproxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file is deliberately pure: it turns the bytes a browser puts on the wire
// into a host/port pair, and refuses every shape where two parsers could
// disagree about what those bytes mean. The lesson from the redirect-Location
// work (docs/browser-scope-boundary.md, "Redirect Location parsing") is that a
// gate which normalizes differently from the browser is a bypass; here the gate
// and the dialler both consume the SAME validated value, so the only job of
// this parser is to refuse ambiguity rather than resolve it.

const (
	// maxAuthorityBytes bounds the authority separately from the HTTP header
	// limit so a very long "host" cannot turn into a very long DNS name.
	maxAuthorityBytes = 1024
	// maxDNSNameBytes is the DNS wire limit for a textual name.
	maxDNSNameBytes = 253
)

var (
	errMalformedAuthority  = errors.New("scopeproxy: malformed authority")
	errUnsupportedTarget   = errors.New("scopeproxy: unsupported request-target")
	errTargetNotAbsolute   = errors.New("scopeproxy: request-target is not absolute-form")
	errFragmentInTarget    = errors.New("scopeproxy: fragment in request-target")
	errHTTPSAbsoluteForm   = errors.New("scopeproxy: https absolute-form is not supported; https is tunnelled with CONNECT")
	errNonCanonicalAddress = errors.New("scopeproxy: non-canonical address literal")
)

// authority is a validated host:port destination. host is lower-case and, for
// IPv6, unbracketed. raw keeps the exact bytes that were accepted, for audit
// events, so a denial can be reported in the form the client actually sent.
type authority struct {
	host string
	port int
	raw  string
}

func (a authority) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(a.port))
}

// isIPLiteral reports whether host is an address rather than a DNS name. A
// literal is never resolved, so it can never be redirected by DNS.
func (a authority) isIPLiteral() bool { return net.ParseIP(a.host) != nil }

// parseAuthority validates an authority-form value ("host:port", "[v6]:port").
// defaultPort is filled in when the string carries no port; passing 0 means a
// port is mandatory (CONNECT, which has no scheme to imply one).
//
// Everything that is not a bare host (or a canonical IP literal) plus one
// decimal port is refused rather than repaired: userinfo, schemes, paths,
// queries, fragments, escapes, backslashes, whitespace, control characters,
// empty labels, trailing dots, non-canonical IP spellings, zero and
// out-of-range ports.
func parseAuthority(raw string, defaultPort int) (authority, error) {
	if raw == "" {
		return authority{}, fmt.Errorf("%w: empty", errMalformedAuthority)
	}
	if len(raw) > maxAuthorityBytes {
		return authority{}, fmt.Errorf("%w: longer than %d bytes", errMalformedAuthority, maxAuthorityBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return authority{}, fmt.Errorf("%w: whitespace or control character", errMalformedAuthority)
		}
	}
	// '@' would be userinfo, '/' a path, '?' a query, '#' a fragment, '%' an
	// escape that a second parser could decode, '\' the WHATWG-vs-RFC
	// separator that the redirect work already had to reject.
	if strings.ContainsAny(raw, `\/@?#%`) {
		return authority{}, fmt.Errorf("%w: forbidden character (userinfo, path, escape or backslash)", errMalformedAuthority)
	}

	hostPart, portPart := raw, ""
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return authority{}, fmt.Errorf("%w: unterminated IPv6 literal", errMalformedAuthority)
		}
		hostPart = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return authority{}, fmt.Errorf("%w: text after IPv6 literal that is not :port", errMalformedAuthority)
			}
			portPart = rest[1:]
		}
		if hostPart == "" || !strings.Contains(hostPart, ":") {
			return authority{}, fmt.Errorf("%w: bracketed host is not an IPv6 literal", errMalformedAuthority)
		}
		ip := net.ParseIP(hostPart)
		if ip == nil {
			return authority{}, fmt.Errorf("%w: bracketed host is not an IPv6 literal", errMalformedAuthority)
		}
		// Go and WHATWG serialize IPv4-mapped addresses differently
		// ([::ffff:7f00:1] vs ::ffff:127.0.0.1), so the two readings can
		// disagree about the same machine. Refuse instead of guessing.
		if ip.To4() != nil {
			return authority{}, fmt.Errorf("%w: IPv4-mapped IPv6 literal", errNonCanonicalAddress)
		}
		if hostPart != ip.String() {
			return authority{}, fmt.Errorf("%w: IPv6 literal is not in canonical form", errNonCanonicalAddress)
		}
	} else {
		if strings.ContainsAny(raw, "[]") {
			return authority{}, fmt.Errorf("%w: unbalanced bracket", errMalformedAuthority)
		}
		switch strings.Count(raw, ":") {
		case 0:
		case 1:
			i := strings.IndexByte(raw, ':')
			hostPart, portPart = raw[:i], raw[i+1:]
			if portPart == "" {
				return authority{}, fmt.Errorf("%w: empty port", errMalformedAuthority)
			}
		default:
			// A bare IPv6 literal is ambiguous with host:port and Chromium
			// always brackets it. Refuse rather than split on a guess.
			return authority{}, fmt.Errorf("%w: bare IPv6 literal or extra colon", errMalformedAuthority)
		}
	}

	if hostPart == "" {
		return authority{}, fmt.Errorf("%w: empty host", errMalformedAuthority)
	}
	host := strings.ToLower(hostPart)
	if ip := net.ParseIP(host); ip != nil {
		// Decimal/hex/octal spellings and zero-padded octets are exactly the
		// aliases the scope matcher refuses; accept only the canonical form.
		if host != ip.String() {
			return authority{}, fmt.Errorf("%w: address literal is not in canonical form", errNonCanonicalAddress)
		}
	} else if looksLikeIPv4Literal(host) {
		// Decimal (2130706433), hex (0x7f.0.0.1) and zero-padded (01.2.3.4)
		// spellings of an IPv4 address are accepted by resolvers and by
		// WHATWG URL parsing but rejected by net.ParseIP here, so without
		// this they would reach the resolver as a "name" and connect
		// somewhere the canonical-form check never saw.
		return authority{}, fmt.Errorf("%w: non-canonical IPv4 spelling", errNonCanonicalAddress)
	} else if !validDNSName(host) {
		return authority{}, fmt.Errorf("%w: host is not a valid DNS name", errMalformedAuthority)
	}

	if portPart == "" {
		if defaultPort <= 0 {
			return authority{}, fmt.Errorf("%w: a port is required", errMalformedAuthority)
		}
		return authority{host: host, port: defaultPort, raw: raw}, nil
	}
	port, err := parsePort(portPart)
	if err != nil {
		return authority{}, err
	}
	return authority{host: host, port: port, raw: raw}, nil
}

// parsePort accepts 1..65535 in decimal digits only. Port 0 is refused: it is
// not an addressable service, so allowing it would only create a shape whose
// meaning differs between platforms.
func parsePort(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, fmt.Errorf("%w: port is empty or too long", errMalformedAuthority)
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: port is not decimal", errMalformedAuthority)
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: port out of range", errMalformedAuthority)
	}
	return n, nil
}

// looksLikeIPv4Literal reports whether h is written as 1-4 dot-separated
// decimal, octal-looking (leading zero) or 0x-prefixed parts — the shapes the
// WHATWG IPv4 parser and libc resolvers both accept and Go's net.ParseIP does
// not. Such a string is never a DNS name an operator scoped.
func looksLikeIPv4Literal(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
			rest := p[2:]
			if rest == "" {
				return false
			}
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					return false
				}
			}
			continue
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// validDNSName accepts lower-case LDH labels plus '_' (common in internal
// names) and refuses a leading dot, a trailing dot, empty labels and punycode-
// absent Unicode. A trailing dot is a different spelling of the same machine
// and the scope matcher denies it, so the proxy does too.
func validDNSName(h string) bool {
	if h == "" || len(h) > maxDNSNameBytes {
		return false
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// splitAbsoluteTarget validates an absolute-form request-target and returns its
// authority plus the exact origin-form suffix that must be forwarded. The
// suffix is cut from the raw bytes, not re-serialized, so path and query
// encoding reach the origin byte-for-byte.
func splitAbsoluteTarget(raw string) (auth, rest string, err error) {
	if raw == "" {
		return "", "", fmt.Errorf("%w: empty", errUnsupportedTarget)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return "", "", fmt.Errorf("%w: whitespace or control character", errUnsupportedTarget)
		}
	}
	if len(raw) >= len("https://") && strings.EqualFold(raw[:len("https://")], "https://") {
		return "", "", errHTTPSAbsoluteForm
	}
	if len(raw) < len("http://") || !strings.EqualFold(raw[:len("http://")], "http://") {
		return "", "", errTargetNotAbsolute
	}
	after := raw[len("http://"):]
	end := strings.IndexAny(after, "/?#")
	switch {
	case end < 0:
		auth, rest = after, "/"
	case after[end] == '#':
		return "", "", errFragmentInTarget
	case after[end] == '?':
		auth, rest = after[:end], "/"+after[end:]
	default:
		auth, rest = after[:end], after[end:]
	}
	if auth == "" {
		return "", "", fmt.Errorf("%w: empty authority", errUnsupportedTarget)
	}
	// A fragment is never sent to an origin. Refuse it rather than forward a
	// request-target whose meaning differs from the URL the browser intended.
	if strings.ContainsRune(rest, '#') {
		return "", "", errFragmentInTarget
	}
	return auth, rest, nil
}

// sameTarget reports whether a dialler-supplied "host:port" is the authority
// that was validated. It is used to refuse any dial the validated value did not
// authorize, including one a transport layer might attempt on its own.
func sameTarget(addr string, a authority) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return strings.EqualFold(host, a.host) && p == a.port
}

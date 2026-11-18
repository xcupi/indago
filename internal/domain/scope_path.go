package domain

// Scope path safety helpers.
//
// These helpers are intentionally independent of Scope.Permits so the path
// rules can be integrated without changing host or scheme semantics. They are
// validators, not normalisers: an ambiguous path is REJECTED, never rewritten
// into a "probably intended" one. Guessing how a server, proxy, or CDN will
// normalise a path is exactly the failure mode this code exists to avoid.
//
// The rules are deliberately conservative. They reject:
//
//   - literal and percent-encoded dot segments (%2e, %2e%2e, .%2e, %2e.),
//   - percent-encoded slashes and backslashes (%2f, %5c),
//   - literal backslashes (Windows/IIS separators),
//   - duplicate slashes (nginx merge_slashes and similar rewrites),
//   - encoded query/fragment delimiters (%3f, %23), which some intermediaries
//     decode before routing,
//   - NUL and other control characters,
//   - a residual %XX escape after one decode, which is the signature of
//     double (or deeper) encoding,
//   - path parameters attached to a dot segment or with no segment name
//     ("/app/..;/x", "/app/;/x"), the forms that can change routing in
//     servlet/container normalisation.
//
// Ordinary matrix parameters on a named segment ("/app;v=1/x") remain valid.
// A scope PREFIX containing any path parameter is rejected: a prefix with a
// parameter is not a stable segment boundary.
//
// Unicode confusables (fullwidth dot/slash) and Windows trailing-dot trimming
// are not interpreted: doing so would mean guessing an origin's normalisation
// policy. They remain documented residual risks for the caller.
//
// False positives are accepted on purpose: a filename that legitimately
// contains the text "%2e", a double slash, or a literal percent followed by
// two hex digits will be denied. Operators must write the decoded, canonical
// path. A false positive only narrows a scan (fail closed); a false negative
// can leave the declared scope.

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SafeScopePath validates the path of an already-parsed URL and returns the
// decoded path a scope decision may use. It never rewrites the path: any error
// means the caller must deny the URL. The caller still owns scheme, host,
// query, and fragment policy.
//
// A nil URL or an opaque URL (for example "http:foo") is an error.
func SafeScopePath(u *url.URL) (string, error) {
	if u == nil {
		return "", fmt.Errorf("scope path: nil URL")
	}
	if u.Opaque != "" {
		return "", fmt.Errorf("scope path: opaque URL has no path to check")
	}

	escaped := u.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if err := validateEscapedScopePath(escaped); err != nil {
		return "", err
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if err := validateDecodedScopePath(path); err != nil {
		return "", err
	}
	return path, nil
}

// SafeScopePathPrefix validates a decoded include/exclude path prefix and
// returns it unchanged. It is stricter than SafeScopePath for prefixes:
//
//   - a percent sign is never accepted, because a stored prefix is supposed to
//     be the decoded path; encoded prefixes tend not to match what the matcher
//     compares and are ambiguous across parsers;
//   - any path parameter (';') is rejected, because a prefix containing one is
//     not a stable segment boundary.
func SafeScopePathPrefix(prefix string) (string, error) {
	if prefix == "" {
		return "", fmt.Errorf("scope path prefix: empty")
	}
	if strings.Contains(prefix, "://") {
		return "", fmt.Errorf("scope path prefix: %q looks like a URL; write only the path", prefix)
	}
	if !strings.HasPrefix(prefix, "/") {
		return "", fmt.Errorf("scope path prefix: %q must start with %q", prefix, "/")
	}
	if strings.ContainsAny(prefix, "?#") {
		return "", fmt.Errorf("scope path prefix: %q must not contain a query or fragment", prefix)
	}
	if strings.Contains(prefix, `\`) {
		return "", fmt.Errorf("scope path prefix: %q contains a backslash", prefix)
	}
	if strings.Contains(prefix, ";") {
		return "", fmt.Errorf("scope path prefix: %q contains a path parameter; a prefix with a parameter is not a stable boundary", prefix)
	}
	if strings.Contains(prefix, "%") {
		return "", fmt.Errorf("scope path prefix: %q contains a percent escape; write the decoded path", prefix)
	}
	if err := validateDecodedScopePath(prefix); err != nil {
		return "", err
	}
	return prefix, nil
}

// ScopePathWithinPrefix reports whether path is the prefix itself or lies
// below it on a segment boundary. Both arguments must be decoded scope paths;
// invalid inputs return false (fail closed).
//
// Examples, with prefix "/app":
//
//	/app          true
//	/app/         true
//	/app/x        true
//	/application  false  (no segment boundary)
//	/app-admin    false
//
// A trailing slash in the prefix keeps its historical meaning: "/app/" does
// not match "/app" itself, but does match "/app/" and "/app/x".
func ScopePathWithinPrefix(path, prefix string) bool {
	if validateDecodedScopePath(path) != nil {
		return false
	}
	checked, err := SafeScopePathPrefix(prefix)
	if err != nil {
		return false
	}
	if checked == "/" {
		return true
	}
	if strings.HasSuffix(checked, "/") {
		return strings.HasPrefix(path, checked)
	}
	return path == checked || strings.HasPrefix(path, checked+"/")
}

// ScopePathWithinLegacyPrefix is the historical plain string-prefix rule:
// "/app" also matches "/application" and "/app-admin". The path and prefix are
// still validated, so ambiguous traversal is denied even in legacy mode; only
// the segment boundary is relaxed.
func ScopePathWithinLegacyPrefix(path, prefix string) bool {
	if validateDecodedScopePath(path) != nil {
		return false
	}
	checked, err := SafeScopePathPrefix(prefix)
	if err != nil {
		return false
	}
	return strings.HasPrefix(path, checked)
}

// ScopePathExcludedByPrefix reports whether path is excluded by prefix. It is
// deliberately broader than ScopePathWithinPrefix: an exclusion that is one
// segment too wide only narrows a scan, while one that is too narrow can let a
// request through. The trailing slash is ignored for matching, so "/admin/"
// also excludes "/admin", and matching is ASCII case-insensitive so "/Admin"
// cannot slip past an exclusion on a case-insensitive origin.
//
// Invalid inputs return true (deny): a malformed exclusion must not silently
// stop excluding everything it was meant to cover.
func ScopePathExcludedByPrefix(path, prefix string) bool {
	if validateDecodedScopePath(path) != nil {
		return true
	}
	checked, err := SafeScopePathPrefix(prefix)
	if err != nil {
		return true
	}
	base := strings.TrimSuffix(checked, "/")
	if base == "" { // prefix "/" excludes every path
		return true
	}
	return asciiHasPrefixFold(path, base)
}

// validateEscapedScopePath checks the raw escaped path, before decoding, for
// forms whose meaning can differ between net/url, WHATWG parsing, an origin
// server, a reverse proxy, or a CDN.
func validateEscapedScopePath(escaped string) error {
	for _, r := range escaped {
		switch {
		case r == '\\':
			return fmt.Errorf("scope path: literal backslash in path")
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("scope path: control character in path")
		case r == ' ':
			return fmt.Errorf("scope path: unescaped space in path")
		}
	}

	for _, bad := range []struct {
		token  string
		reason string
	}{
		{"%2e", "encoded dot in path"},
		{"%2f", "encoded slash in path"},
		{"%5c", "encoded backslash in path"},
		{"%00", "encoded NUL in path"},
		{"%3f", "encoded query delimiter in path"},
		{"%23", "encoded fragment delimiter in path"},
	} {
		if containsFoldASCII(escaped, bad.token) {
			return fmt.Errorf("scope path: %s (%s)", bad.reason, bad.token)
		}
	}
	return nil
}

// validateDecodedScopePath checks a path after exactly one percent-decode.
func validateDecodedScopePath(path string) error {
	if path == "" {
		return fmt.Errorf("scope path: empty path")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("scope path: %q must start with %q", path, "/")
	}
	if !utf8.ValidString(path) {
		return fmt.Errorf("scope path: invalid UTF-8 in path")
	}
	for _, r := range path {
		switch {
		case r == '\\':
			return fmt.Errorf("scope path: literal backslash in path")
		case r == ' ':
			return fmt.Errorf("scope path: unescaped space in path")
		case r < 0x20 || r == 0x7f || unicode.IsControl(r):
			return fmt.Errorf("scope path: control character in path")
		}
	}
	if strings.ContainsAny(path, "?#") {
		return fmt.Errorf("scope path: decoded query or fragment delimiter in path")
	}
	if hasResidualEscape(path) {
		return fmt.Errorf("scope path: residual percent escape in path (double-encoded or IIS-style escape)")
	}
	return validateScopePathSegments(path)
}

// validateScopePathSegments rejects the segment shapes that can change
// routing after container or OS normalisation.
func validateScopePathSegments(path string) error {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			// Allow the empty element before the leading slash and after a
			// trailing slash; any other empty element is a duplicate slash.
			if i == 0 || i == len(segments)-1 {
				continue
			}
			return fmt.Errorf("scope path: duplicate slash in %q", path)
		}
		if segment == "." || segment == ".." {
			return fmt.Errorf("scope path: dot segment %q", segment)
		}
		if semi := strings.IndexByte(segment, ';'); semi >= 0 {
			base := segment[:semi]
			switch base {
			case "":
				return fmt.Errorf("scope path: path parameter %q has no segment name", segment)
			case ".", "..":
				return fmt.Errorf("scope path: path parameter %q follows a dot segment", segment)
			}
		}
	}
	return nil
}

// hasResidualEscape reports a percent escape that survived the first decode:
// %XX (any two hex digits) or IIS's %uXXXX form. It does not try to decide how
// many times a particular server will decode; one residual escape is enough to
// reject the path.
func hasResidualEscape(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		if i+2 < len(path) && isHexByte(path[i+1]) && isHexByte(path[i+2]) {
			return true
		}
		if i+5 < len(path) && (path[i+1] == 'u' || path[i+1] == 'U') &&
			isHexByte(path[i+2]) && isHexByte(path[i+3]) &&
			isHexByte(path[i+4]) && isHexByte(path[i+5]) {
			return true
		}
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

// containsFoldASCII reports whether s contains sub, comparing ASCII letters
// case-insensitively. Percent-escape tokens are ASCII, so this avoids a
// Unicode-aware lower-casing allocation and its length pitfalls.
func containsFoldASCII(s, sub string) bool {
	if sub == "" {
		return true
	}
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		matched := true
		for j := 0; j < len(sub); j++ {
			if asciiLowerByte(s[i+j]) != asciiLowerByte(sub[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// asciiHasPrefixFold is a byte-wise, ASCII-case-insensitive prefix check. It
// preserves the length of the path, so slicing after the check remains valid.
func asciiHasPrefixFold(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if asciiLowerByte(s[i]) != asciiLowerByte(prefix[i]) {
			return false
		}
	}
	return true
}

func asciiLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

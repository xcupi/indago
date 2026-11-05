package domain

import (
	"net"
	"strings"
	"testing"
)

func TestValidateScopeHostRejectsEntriesThatCanNeverMatch(t *testing.T) {
	cases := []struct{ entry, wantHint string }{
		{"https://example.com", `"example.com"`},
		{"http://example.com/app", `"example.com"`},
		{"example.com:8443", `"example.com"`},
		{"example.com/", `"example.com"`},
		{"example.com/app", `"example.com"`},
		{"user@example.com", "bare hostname"},
		{"example.com?x=1", "bare hostname"},
		{"example.com#frag", "bare hostname"},
		{`example.com\app`, "bare hostname"},
		{"*.example.com", `".example.com"`},
		{"*", "wildcard"},
		{"exa*mple.com", "wildcard"},
		{"[::1]", `"::1"`},
		{"[::1]:8080", `"::1"`},
		{"example.com.", "trailing dot"},
		{".", "empty"},
		{"a..example.com", "empty label"},
		{"..example.com", "empty label"},
		{"exa mple.com", "whitespace"},
		{"example.com\t", "whitespace"},
		{"bücher.example", "punycode"},
		{"2130706433", "dotted-quad"},
		{"0x7f.0.0.1", "dotted-quad"},
		{"127.1", "dotted-quad"},
		{"example.com:", "port"},
		{"exa$mple.com", "invalid character"},
	}
	for _, tc := range cases {
		err := ValidateScopeHost(tc.entry)
		if err == nil {
			t.Errorf("%q must be rejected: it can never match a request", tc.entry)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantHint) {
			t.Errorf("%q: message %q should mention %s", tc.entry, err.Error(), tc.wantHint)
		}
	}
}

func TestValidateScopeHostAcceptsRealHostnames(t *testing.T) {
	for _, entry := range []string{
		"example.com", "Example.COM", ".example.com", "localhost", "a-b.example.co.uk",
		"under_score.example.com", "123.example.com", "127.0.0.1", "10.0.0.5", "::1",
		"2001:db8::1", "xn--bcher-kva.example", "internal",
	} {
		if err := ValidateScopeHost(entry); err != nil {
			t.Errorf("%q is a legitimate scope entry but was rejected: %v", entry, err)
		}
	}
}

// The point of validation: an accepted entry must be able to match its own host.
// If this fails, the validator lets through something that silently denies
// everything, which is the bug it exists to remove.
func TestEveryAcceptedHostEntryCanMatchItself(t *testing.T) {
	for _, entry := range []string{
		"example.com", "Example.COM", ".example.com", "localhost", "a-b.example.co.uk",
		"under_score.example.com", "123.example.com", "127.0.0.1", "10.0.0.5", "::1",
		"2001:db8::1", "xn--bcher-kva.example", "internal",
	} {
		if ValidateScopeHost(entry) != nil {
			t.Fatalf("setup: %q should be valid", entry)
		}
		host := strings.TrimPrefix(entry, ".")
		if net.ParseIP(host) != nil && strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		url := "http://" + host + ":8080/x"
		if d := (Scope{IncludeHosts: []string{entry}}).Permits(url); !d.Allowed {
			t.Errorf("accepted entry %q does not permit %s: %s", entry, url, d.Reason)
		}
	}
}

// Conversely, every rejected shape that has a canonical form must be accepted
// once rewritten the way the message suggests.
func TestValidateScopeHostSuggestionsAreThemselvesValid(t *testing.T) {
	for _, entry := range []string{"https://example.com", "example.com:8443", "example.com/app", "*.example.com", "[::1]"} {
		err := ValidateScopeHost(entry)
		if err == nil {
			t.Fatalf("setup: %q should be rejected", entry)
		}
		s, ok := ScopeHostSuggestion(entry)
		if !ok {
			t.Errorf("%q: expected a suggestion", entry)
			continue
		}
		if verr := ValidateScopeHost(s); verr != nil {
			t.Errorf("%q suggests %q, which is itself rejected: %v", entry, s, verr)
		}
	}
}

func TestValidateScopePathPrefix(t *testing.T) {
	for _, entry := range []string{"/", "/app", "/app/", "/a/b/c", "/Admin", "/a%25b"} {
		if err := ValidateScopePathPrefix(entry); err != nil {
			t.Errorf("%q should be accepted: %v", entry, err)
		}
	}
	for _, tc := range []struct{ entry, hint string }{
		{"app", `"/app"`},
		{"admin/", `"/admin/"`},
		{"https://example.com/app", "path"},
		{"/app?x=1", "query"},
		{"/app#top", "fragment"},
		{"/a b", "whitespace"},
		{"/a\tb", "whitespace"},
		{"/app/../x", "dot-segment"},
	} {
		err := ValidateScopePathPrefix(tc.entry)
		if err == nil {
			t.Errorf("%q must be rejected", tc.entry)
		} else if !strings.Contains(err.Error(), tc.hint) {
			t.Errorf("%q: message %q should mention %s", tc.entry, err.Error(), tc.hint)
		}
	}
}

// Path rules that the validator accepts must be able to match, like host entries.
func TestAcceptedPathPrefixCanMatchItself(t *testing.T) {
	for _, p := range []string{"/", "/app", "/app/", "/a/b/c", "/Admin"} {
		s := Scope{IncludeHosts: []string{"example.com"}, IncludePathPrefixes: []string{p}}
		if d := s.Permits("http://example.com" + p); !d.Allowed {
			t.Errorf("prefix %q does not permit its own path: %s", p, d.Reason)
		}
	}
}

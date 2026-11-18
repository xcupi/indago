package domain

import (
	"net/url"
	"strings"
	"testing"
)

func mustParseScopePathURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestSafeScopePathAcceptsConcretePaths(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"root without slash", "http://example.com", "/"},
		{"root", "http://example.com/", "/"},
		{"simple", "http://example.com/app", "/app"},
		{"trailing slash", "http://example.com/app/", "/app/"},
		{"nested", "http://example.com/app/x/y", "/app/x/y"},
		{"dots inside names", "http://example.com/a.b/c-d_e", "/a.b/c-d_e"},
		{"version-like", "http://example.com/v1.0/users", "/v1.0/users"},
		{"three dots", "http://example.com/app/...", "/app/..."},
		{"dotfile segment", "http://example.com/app/.well-known", "/app/.well-known"},
		{"matrix parameter on named segment", "http://example.com/app;v=1/x", "/app;v=1/x"},
		{"matrix parameter later", "http://example.com/app/foo;bar", "/app/foo;bar"},
		{"encoded matrix parameter on named segment", "http://example.com/app/foo%3bbar/x", "/app/foo;bar/x"},
		{"encoded unreserved letter", "http://example.com/app/%41", "/app/A"},
		{"encoded plus", "http://example.com/app/%2B", "/app/+"},
		{"encoded percent alone", "http://example.com/app/%25", "/app/%"},
		{"utf8 path", "http://example.com/app/%E2%9C%93", "/app/✓"},
		{"query ignored", "http://example.com/app?next=/../admin", "/app"},
		{"fragment ignored", "http://example.com/app#/../admin", "/app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafeScopePath(mustParseScopePathURL(t, tc.raw))
			if err != nil {
				t.Fatalf("SafeScopePath(%q) error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("SafeScopePath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestSafeScopePathRejectsAmbiguousRepresentations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		hint string
	}{
		{"literal dot segment", "http://example.com/app/../x", "dot segment"},
		{"literal current segment", "http://example.com/app/./x", "dot segment"},
		{"encoded dot segment", "http://example.com/app/%2e%2e/x", "encoded dot"},
		{"encoded dot uppercase", "http://example.com/app/%2E%2E/x", "encoded dot"},
		{"encoded dot mixed", "http://example.com/app/%2e./x", "encoded dot"},
		{"literal dot encoded dot", "http://example.com/app/.%2e/x", "encoded dot"},
		{"encoded dot in filename", "http://example.com/app/a%2eb", "encoded dot"},
		{"encoded slash", "http://example.com/app/%2f../x", "encoded slash"},
		{"encoded slash inside segment", "http://example.com/app/a%2Fb", "encoded slash"},
		{"encoded slash uppercase", "http://example.com/app/%2F../x", "encoded slash"},
		{"encoded backslash", "http://example.com/app/%5c..%5cx", "encoded backslash"},
		{"encoded backslash uppercase", "http://example.com/app/%5C..%5Cx", "encoded backslash"},
		{"literal backslash", `http://example.com/app\..\x`, "backslash"},
		{"double encoded dot", "http://example.com/app/%252e%252e/x", "double-encoded"},
		{"double encoded slash", "http://example.com/app/%252f../x", "double-encoded"},
		{"triple encoded dot", "http://example.com/app/%25252e/x", "double-encoded"},
		{"double encoded percent", "http://example.com/app/%2525/x", "double-encoded"},
		{"encoded unreserved twice", "http://example.com/app/%2541/x", "double-encoded"},
		{"iis style dot", "http://example.com/app/%25u002e%25u002e/x", "double-encoded"},
		{"encoded NUL", "http://example.com/app/%00/x", "encoded NUL"},
		{"encoded query delimiter", "http://example.com/app/%3f/x", "encoded query"},
		{"encoded fragment delimiter", "http://example.com/app/%23/x", "encoded fragment"},
		{"encoded space", "http://example.com/app/%20/x", "space"},
		{"encoded tab", "http://example.com/app/%09/x", "control"},
		{"encoded DEL", "http://example.com/app/%7f/x", "control"},
		{"invalid utf8", "http://example.com/app/%ff/x", "invalid UTF-8"},
		{"overlong utf8 slash", "http://example.com/app/%c0%af../x", "invalid UTF-8"},
		{"duplicate slash", "http://example.com/app//x", "duplicate slash"},
		{"leading duplicate slash", "http://example.com//app", "duplicate slash"},
		{"triple slash", "http://example.com/app///x", "duplicate slash"},
		{"path parameter on dot segment", "http://example.com/app/..;/x", "path parameter"},
		{"path parameter on current segment", "http://example.com/app/.;/x", "path parameter"},
		{"path parameter without name", "http://example.com/app/;/x", "path parameter"},
		{"encoded path parameter without name", "http://example.com/app/%3bfoo/x", "path parameter"},
		{"encoded path parameter on dot segment", "http://example.com/app/..%3b/x", "path parameter"},
		{"named path parameter on dot segment", "http://example.com/app/..%3bfoo/x", "path parameter"},
		{"encoded dot then slash", "http://example.com/app/%2e%2e%2f/x", "encoded dot"},
		{"encoded slash then dot", "http://example.com/app/%2f%2e%2e/x", "encoded"},
		{"encoded dot then backslash", "http://example.com/app/%2e%2e%5c/x", "encoded dot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SafeScopePath(mustParseScopePathURL(t, tc.raw))
			if err == nil {
				t.Fatalf("SafeScopePath(%q) = nil error, want %q", tc.raw, tc.hint)
			}
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("SafeScopePath(%q) error = %q, want it to mention %q", tc.raw, err, tc.hint)
			}
		})
	}
}

func TestSafeScopePathRejectsNilAndOpaque(t *testing.T) {
	if _, err := SafeScopePath(nil); err == nil || !strings.Contains(err.Error(), "nil URL") {
		t.Fatalf("SafeScopePath(nil) error = %v, want nil URL", err)
	}
	opaque := mustParseScopePathURL(t, "http:foo")
	if _, err := SafeScopePath(opaque); err == nil || !strings.Contains(err.Error(), "opaque") {
		t.Fatalf("SafeScopePath(opaque) error = %v, want opaque", err)
	}
}

func TestSafeScopePathChecksProgrammaticURLs(t *testing.T) {
	cases := []struct {
		name string
		u    *url.URL
		hint string
	}{
		{"dot segment", &url.URL{Path: "/app/../x"}, "dot segment"},
		{"encoded dot text", &url.URL{Path: "/app/%2e%2e/x"}, "double-encoded"},
		{"literal percent hex", &url.URL{Path: "/app/%AB"}, "double-encoded"},
		{"backslash", &url.URL{Path: `/app\..\x`}, "backslash"},
		{"relative path", &url.URL{Path: "app/x"}, "start with"},
		{"control", &url.URL{Path: "/app/\x7f"}, "control"},
		{"decoded query delimiter", &url.URL{Path: "/app/x?y"}, "query"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SafeScopePath(tc.u)
			if err == nil {
				t.Fatalf("SafeScopePath(%+v) = nil error, want %q", tc.u, tc.hint)
			}
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("SafeScopePath(%+v) error = %q, want it to mention %q", tc.u, err, tc.hint)
			}
		})
	}
}

func TestSafeScopePathPrefixAcceptsCanonicalPrefixes(t *testing.T) {
	for _, prefix := range []string{
		"/",
		"/app",
		"/app/",
		"/a/b/c",
		"/Admin",
		"/app.v2",
		"/app/...",
		"/app/.well-known",
		"/app/foo-bar_baz",
		"/app/é",
	} {
		t.Run(prefix, func(t *testing.T) {
			got, err := SafeScopePathPrefix(prefix)
			if err != nil {
				t.Fatalf("SafeScopePathPrefix(%q) error: %v", prefix, err)
			}
			if got != prefix {
				t.Fatalf("SafeScopePathPrefix(%q) = %q, want unchanged", prefix, got)
			}
		})
	}
}

func TestSafeScopePathPrefixRejectsAmbiguousPrefixes(t *testing.T) {
	cases := []struct {
		prefix string
		hint   string
	}{
		{"", "empty"},
		{"app", "must start"},
		{"https://example.com/app", "looks like a URL"},
		{"/app?x=1", "query or fragment"},
		{"/app#x", "query or fragment"},
		{`/app\..\x`, "backslash"},
		{"/app/%2e%2e", "percent escape"},
		{"/app/%2f", "percent escape"},
		{"/app/%5c", "percent escape"},
		{"/app/%252e", "percent escape"},
		{"/app/%20", "percent escape"},
		{"/app/%00", "percent escape"},
		{"/a%25b", "percent escape"},
		{"/a%b", "percent escape"},
		{"/app//x", "duplicate slash"},
		{"/app/../x", "dot segment"},
		{"/app/.", "dot segment"},
		{"/app/..", "dot segment"},
		{"/app/..;/x", "path parameter"},
		{"/app/;/x", "path parameter"},
		{"/app;v=1", "path parameter"},
		{"//app", "duplicate slash"},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			_, err := SafeScopePathPrefix(tc.prefix)
			if err == nil {
				t.Fatalf("SafeScopePathPrefix(%q) = nil error, want %q", tc.prefix, tc.hint)
			}
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("SafeScopePathPrefix(%q) error = %q, want it to mention %q", tc.prefix, err, tc.hint)
			}
		})
	}
}

func TestScopePathWithinPrefix(t *testing.T) {
	cases := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/", "/", true},
		{"/app", "/", true},
		{"/app/x", "/", true},
		{"/app", "/app", true},
		{"/app/", "/app", true},
		{"/app/x", "/app", true},
		{"/app/x/y", "/app", true},
		{"/application", "/app", false},
		{"/app-admin", "/app", false},
		{"/app.evil", "/app", false},
		{"/app", "/app/", false},
		{"/app/", "/app/", true},
		{"/app/x", "/app/", true},
		{"/application", "/app/", false},
		{"/app;v=1", "/app", false},
		{"/app", "/app;v=1", false},
		{"/app", "/APP", false},
		{"/app", "", false},
		{"/app/../x", "/app", false},
		{"/app", "/app/../", false},
		{"/app//x", "/app", false},
		{"", "/", false},
	}
	for _, tc := range cases {
		if got := ScopePathWithinPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("ScopePathWithinPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestScopePathWithinLegacyPrefix(t *testing.T) {
	cases := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/application", "/app", true},
		{"/app-admin", "/app", true},
		{"/app", "/app", true},
		{"/app/", "/app", true},
		{"/app/x", "/app", true},
		{"/app", "/app/", false},
		{"/application", "/app/", false},
		{"/app", "/", true},
		{"/application", "/", true},
		{"/app", "", false},
		{"/app/../x", "/app", false},
		{"/app", "/app/../", false},
		{"/App", "/app", false},
		{"/app", "/APP", false},
		{"/app//x", "/app", false},
	}
	for _, tc := range cases {
		if got := ScopePathWithinLegacyPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("ScopePathWithinLegacyPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

func TestScopePathExcludedByPrefix(t *testing.T) {
	cases := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/admin", "/admin", true},
		{"/admin/", "/admin", true},
		{"/admin/x", "/admin", true},
		{"/administrator", "/admin", true},
		{"/Admin", "/admin", true},
		{"/ADMIN/x", "/admin", true},
		{"/admin", "/admin/", true},
		{"/admin/x", "/admin/", true},
		{"/admin", "/ADMIN/", true},
		{"/app", "/admin", false},
		{"/app/admin", "/admin", false},
		{"/", "/", true},
		{"/anything", "/", true},
		{"/admin/../x", "/admin", true},
		{"/admin", "/admin/../", true},
		{"", "/admin", true},
		{"/admin", "", true},
		{"/admin", "/admin;v=1", true},
		{"/admin//x", "/admin", true},
	}
	for _, tc := range cases {
		if got := ScopePathExcludedByPrefix(tc.path, tc.prefix); got != tc.want {
			t.Errorf("ScopePathExcludedByPrefix(%q, %q) = %v, want %v", tc.path, tc.prefix, got, tc.want)
		}
	}
}

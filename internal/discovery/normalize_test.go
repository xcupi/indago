package discovery_test

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"http://Example.com", "http://example.com/", false},          // host lower, path default
		{"http://example.com:80/a", "http://example.com/a", false},    // default port dropped
		{"https://example.com:443/a", "https://example.com/a", false}, // default port dropped
		{"http://example.com:8080/a", "http://example.com:8080/a", false},
		{"http://example.com/a/../b", "http://example.com/b", false},            // dot-segments
		{"http://example.com/a/./b/", "http://example.com/a/b/", false},         // trailing slash preserved
		{"http://example.com/p#frag", "http://example.com/p", false},            // fragment dropped
		{"http://example.com/s?b=2&a=1", "http://example.com/s?a=1&b=2", false}, // query sorted
		{"ftp://example.com/x", "", true},                                       // non-http
		{"mailto:a@b.com", "", true},                                            // non-http
		{"/relative/only", "", true},                                            // not absolute
		{"http://", "", true},                                                   // no host
	}
	for _, c := range cases {
		got, err := discovery.Normalize(c.in)
		if c.err {
			if err == nil {
				t.Errorf("Normalize(%q) expected error, got %q", c.in, got.Canonical)
			}
			continue
		}
		if err != nil {
			t.Errorf("Normalize(%q) error: %v", c.in, err)
			continue
		}
		if got.Canonical != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got.Canonical, c.want)
		}
	}
}

func TestNormalizeRef(t *testing.T) {
	base := "http://example.com/dir/page"
	cases := []struct {
		ref  string
		want string
		err  bool
	}{
		{"../x", "http://example.com/x", false},
		{"sub", "http://example.com/dir/sub", false},
		{"/abs", "http://example.com/abs", false},
		{"?q=1", "http://example.com/dir/page?q=1", false},
		{"//other.com/p", "http://other.com/p", false}, // scheme-relative
		{"javascript:alert(1)", "", true},
		{"mailto:x@y.com", "", true},
	}
	for _, c := range cases {
		got, err := discovery.NormalizeRef(base, c.ref)
		if c.err {
			if err == nil {
				t.Errorf("NormalizeRef(%q) expected error, got %q", c.ref, got.Canonical)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeRef(%q) error: %v", c.ref, err)
			continue
		}
		if got.Canonical != c.want {
			t.Errorf("NormalizeRef(%q) = %q, want %q", c.ref, got.Canonical, c.want)
		}
	}
}

func TestNormalizeRejectsMarkupPaths(t *testing.T) {
	// React/SPA documents carry inline SVG and JSX as TEXT. A link, action or
	// literal extractor reading that text hands back markup fragments such as
	// "/></g></svg>" as if they were routes; registering one produced a GET
	// endpoint no server can route (http://host/></svg>) and every later stage
	// tested a URL that was never a URL.
	cases := []struct {
		in   string
		bad  string // the offending byte the error must name
		note string
	}{
		{"http://example.com/></svg>", ">", "inline SVG close tag"},
		{"http://example.com/></g></svg>", ">", "nested SVG close tags"},
		{"http://example.com/><path d=", ">", "JSX attribute fragment"},
		{"http://example.com/><circle r=", ">", "JSX self-closing fragment"},
		{"http://example.com/<script>", "<", "script tag"},
		{`http://example.com/"><svg onload=alert(1)>`, `"`, "attribute-quote breakout"},
		{"http://example.com/a'b", "'", "single quote"},
		{`http://example.com/a"b`, `"`, "double quote"},
		{`http://example.com/a\b`, `\`, "javascript escape"},
		{"http://example.com/api/{id}", "{", "spec/template placeholder"},
		{"http://example.com/api/${id}", "{", "ES template literal placeholder"},
		{"http://example.com/a`b", "`", "template literal"},
		{"http://example.com/my page", " ", "unescaped space"},
		{"http://example.com/a%0Ab", "\n", "percent-encoded newline"},
		{"http://example.com/a%00b", "\x00", "percent-encoded NUL"},
		{"http://example.com/a%7Fb", "\x7f", "percent-encoded DEL"},
	}
	for _, c := range cases {
		info, err := discovery.Normalize(c.in)
		if err == nil {
			t.Errorf("Normalize(%q) accepted a markup path as %q (%s)", c.in, info.Canonical, c.note)
			continue
		}
		var urlErr *url.Error
		if !errors.As(err, &urlErr) {
			t.Errorf("Normalize(%q) error is %T, want *url.Error", c.in, err)
		}
		if !strings.Contains(err.Error(), "markup") {
			t.Errorf("Normalize(%q) error %q does not say the path is markup", c.in, err)
		}
		if c.bad != "" && !strings.Contains(err.Error(), strconv.Quote(c.bad)) {
			t.Errorf("Normalize(%q) error %q does not name the offending byte %q", c.in, err, c.bad)
		}
		if info.Canonical != "" {
			t.Errorf("Normalize(%q) returned canonical %q alongside an error", c.in, info.Canonical)
		}
	}
}

// The gate is deliberately narrow: only the PATH is validated. A raw-query
// payload is a legitimate injection value, and a hash route is rendered in the
// browser, never requested over HTTP — neither may be rejected for containing
// the bytes that disqualify a path.
func TestNormalizeKeepsMarkupOutOfThePathOnly(t *testing.T) {
	payload := `"><svg onload=alert(1)>`
	info, err := discovery.Normalize("http://example.com/search?q=" + url.QueryEscape(payload))
	if err != nil {
		t.Fatalf("markup in a query VALUE must still normalize: %v", err)
	}
	if info.Path != "/search" || info.Query.Get("q") != payload {
		t.Fatalf("query normalization changed: path=%q q=%q", info.Path, info.Query.Get("q"))
	}

	route, err := discovery.Normalize("http://example.com/#/search?q=%3Cscript%3E")
	if err != nil {
		t.Fatalf("markup in a fragment route must still normalize: %v", err)
	}
	if route.FragmentRoute != "/search" {
		t.Fatalf("fragment route = %q, want /search", route.FragmentRoute)
	}

	// A path that only carries endpoint-key delimiters is still a path.
	delims, err := discovery.Normalize("http://h/a%23/b%7Cfragment:q")
	if err != nil {
		t.Fatalf("path with encoded '#' and '|' must still normalize: %v", err)
	}
	if delims.Path != "/a#/b|fragment:q" {
		t.Fatalf("path = %q", delims.Path)
	}
}

// Markup reaches normalization through the link extractor, so the gate must
// hold for the refs an inline-SVG page actually produces. This is the crAPI
// shape: an icon wrapped in a link whose attribute quoting is markup-close
// ("<a href=\"/></g></svg>\">"), which ExtractLinks hands back verbatim.
func TestNormalizeRefRejectsMarkupFromInlineSVGPage(t *testing.T) {
	const page = `<html><body><svg><a href="/></g></svg>"><circle r="5"/></a></svg></body></html>`
	base := "http://example.com/app"

	refs := discovery.ExtractLinks(page)
	if len(refs) == 0 {
		t.Log("link extractor already drops the markup ref; normalization stays the backstop")
	}
	for _, ref := range refs {
		info, err := discovery.NormalizeRef(base, ref)
		if err == nil {
			t.Errorf("NormalizeRef(%q) resolved markup to %q", ref, info.Canonical)
		}
	}

	// The same refs, stated explicitly: whatever a source hands over, none of
	// these may become an endpoint, whether absolute or resolved against base.
	for _, ref := range []string{"/></g></svg>", "/><path d=", "/><circle r=", "/<script>", "/svg></path>"} {
		if info, err := discovery.NormalizeRef(base, ref); err == nil {
			t.Errorf("NormalizeRef(%q) accepted %q", ref, info.Canonical)
		}
		if info, err := discovery.Normalize("http://example.com" + ref); err == nil {
			t.Errorf("Normalize(%q) accepted %q", "http://example.com"+ref, info.Canonical)
		}
	}
}

func TestEndpointKeyDedupByParamNames(t *testing.T) {
	a, _ := discovery.Normalize("http://e.com/search?q=apple")
	b, _ := discovery.Normalize("http://e.com/search?q=banana")
	if discovery.EndpointKey(domain.MethodGET, a) != discovery.EndpointKey(domain.MethodGET, b) {
		t.Fatal("same path + same param names (different values) must share an endpoint key")
	}

	c, _ := discovery.Normalize("http://e.com/search?q=x&page=2")
	if discovery.EndpointKey(domain.MethodGET, a) == discovery.EndpointKey(domain.MethodGET, c) {
		t.Fatal("different param sets must have different endpoint keys")
	}

	// Method matters.
	if discovery.EndpointKey(domain.MethodGET, a) == discovery.EndpointKey(domain.MethodPOST, a) {
		t.Fatal("method must be part of the endpoint key")
	}
}

func TestParamKeyDistinct(t *testing.T) {
	info, _ := discovery.Normalize("http://e.com/x?a=1")
	k1 := discovery.ParamKey(domain.MethodGET, info, "a", domain.LocationQuery)
	k2 := discovery.ParamKey(domain.MethodGET, info, "b", domain.LocationQuery)
	k3 := discovery.ParamKey(domain.MethodGET, info, "a", domain.LocationForm)
	if k1 == k2 || k1 == k3 {
		t.Fatalf("param keys should be distinct by name and location: %q %q %q", k1, k2, k3)
	}
}

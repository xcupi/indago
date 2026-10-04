package discovery_test

import (
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

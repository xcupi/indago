package scan

// The request-construction regression for the raw query-string capability:
// with the raw-query pseudo-parameters present in an endpoint's parameter list
// ("always" mode), a NAMED parameter's baseline and mutated request are
// byte-identical to the same build without them. This is the strongest
// available proof short of diffing two binaries, and it pins the one place the
// feature touches request building.

import (
	"net/url"
	"testing"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func rawQueryParamFor(t *testing.T, ep *domain.Endpoint, name string) *domain.Parameter {
	t.Helper()
	if _, ok := discovery.RawQueryPrefix(name); !ok {
		t.Fatalf("%q is not a reserved raw-query shape name", name)
	}
	return &domain.Parameter{
		ID: domain.NewID(), ScanID: ep.ScanID, EndpointID: ep.ID,
		Name: name, Location: domain.LocationRawQuery, Source: domain.SourceUserProvided,
		CreatedAt: time.Now(),
	}
}

func TestRawQueryInjection_NamedParameterRequestByteIdentical(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/search?q=hi", domain.MethodGET)
	q := env.param(ep, "q", domain.LocationQuery, "hi")
	rawBare := rawQueryParamFor(t, ep, discovery.RawQueryBareName)
	rawNamed := rawQueryParamFor(t, ep, discovery.RawQueryNamedName)

	without, err := buildRequest(ep, []*domain.Parameter{q}, &injection{param: q, value: "MARK"})
	if err != nil {
		t.Fatal(err)
	}
	with, err := buildRequest(ep, []*domain.Parameter{q, rawBare, rawNamed}, &injection{param: q, value: "MARK"})
	if err != nil {
		t.Fatal(err)
	}
	if without.URL != with.URL {
		t.Fatalf("named-parameter request changed when raw-query pseudo-parameters are present:\n without: %s\n with:    %s", without.URL, with.URL)
	}

	// And the baseline (no injection at all) is unchanged too.
	baseWithout, _ := buildRequest(ep, []*domain.Parameter{q}, nil)
	baseWith, _ := buildRequest(ep, []*domain.Parameter{q, rawBare, rawNamed}, nil)
	if baseWithout.URL != baseWith.URL {
		t.Fatalf("baseline changed when raw-query pseudo-parameters are present: %q vs %q", baseWithout.URL, baseWith.URL)
	}

	// An injected raw-query parameter replaces the whole query string with the
	// shape's prefix plus the encoded payload — and drops the named params,
	// which is the point of a blob probe.
	injected, err := buildRequest(ep, []*domain.Parameter{q, rawBare, rawNamed}, &injection{param: rawNamed, value: `"><svg onload=M>`})
	if err != nil {
		t.Fatal(err)
	}
	want := "x=" + url.QueryEscape(`"><svg onload=M>`)
	if u, _ := url.Parse(injected.URL); u.RawQuery != want {
		t.Fatalf("raw-query injected URL query = %q, want %q", u.RawQuery, want)
	}

	bare, err := buildRequest(ep, []*domain.Parameter{q, rawBare, rawNamed}, &injection{param: rawBare, value: "MARK"})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(bare.URL); u.RawQuery != "MARK" {
		t.Fatalf("bare raw-query URL query = %q, want %q", u.RawQuery, "MARK")
	}
}

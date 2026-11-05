package discovery_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

func TestNormalizeFragmentRouteKeepsRouteAndParams(t *testing.T) {
	info, err := discovery.Normalize("HTTP://Example.com:80/#/search?q=hello&x=1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Canonical != "http://example.com/#/search?q=&x=" {
		t.Errorf("canonical = %q, want route and blank fragment parameter names retained", info.Canonical)
	}
	if info.FragmentRoute != "/search" {
		t.Errorf("FragmentRoute = %q, want /search", info.FragmentRoute)
	}
	if want := []string{"q", "x"}; !reflect.DeepEqual(info.FragmentParams, want) {
		t.Errorf("FragmentParams = %v, want %v", info.FragmentParams, want)
	}
}

func TestNormalizeFragmentRouteRoundTripsEscapedParameterNames(t *testing.T) {
	cases := []struct {
		fragment, want string
	}{
		{"/r?q%26x=1", "q&x"},
		{"/r?q%3Dx=1", "q=x"},
		{"/r?q%2526x=1", "q%26x"},
		{"/r?q+name=1", "q name"},
		{"/r?q%2Bname=1", "q+name"},
	}
	for _, tc := range cases {
		t.Run(tc.fragment, func(t *testing.T) {
			first, err := discovery.Normalize("http://h/#" + tc.fragment)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(first.FragmentParams, []string{tc.want}) {
				t.Fatalf("fragment params = %q, want %q", first.FragmentParams, tc.want)
			}
			second, err := discovery.Normalize(first.Canonical)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(second.FragmentParams, first.FragmentParams) || second.Canonical != first.Canonical {
				t.Fatalf("canonical round trip changed fragment params: first=%+v second=%+v", first, second)
			}
		})
	}
}

func TestEndpointKeySeparatesEncodedFragmentNameFromMultipleNames(t *testing.T) {
	oneName, err := discovery.Normalize("http://h/#/r?q%26x=1")
	if err != nil {
		t.Fatal(err)
	}
	twoNames, err := discovery.Normalize("http://h/#/r?q=1&x=1")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.EndpointKey(domain.MethodGET, oneName) == discovery.EndpointKey(domain.MethodGET, twoNames) {
		t.Fatal("encoded ampersand in one fragment parameter name collided with two names")
	}
}

func TestEndpointKeySeparatesRouteFromDelimiterContainingPath(t *testing.T) {
	route, err := discovery.Normalize("http://h/a#/b?q=x")
	if err != nil {
		t.Fatal(err)
	}
	path, err := discovery.Normalize("http://h/a%23/b%7Cfragment:q")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.EndpointKey(domain.MethodGET, route) == discovery.EndpointKey(domain.MethodGET, path) {
		t.Fatal("fragment route collided with a path containing endpoint-key delimiters")
	}
}

func TestNormalizeFragmentRouteWithoutQueryIsNotAParameterSource(t *testing.T) {
	info, err := discovery.Normalize("http://h/#/about")
	if err != nil {
		t.Fatal(err)
	}
	if info.FragmentRoute != "" || len(info.FragmentParams) != 0 {
		t.Errorf("route without a query gave route=%q params=%v, want none", info.FragmentRoute, info.FragmentParams)
	}
	if info.Canonical != "http://h/" {
		t.Errorf("canonical = %q, want http://h/ (no route without a query)", info.Canonical)
	}
}

func TestNormalizePlainAnchorIsNotARoute(t *testing.T) {
	info, err := discovery.Normalize("http://h/page#section?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if info.FragmentRoute != "" || len(info.FragmentParams) != 0 {
		t.Errorf("plain anchor was read as route=%q params=%v", info.FragmentRoute, info.FragmentParams)
	}
}

func TestExtractScriptParamNamesCapsCandidates(t *testing.T) {
	var body strings.Builder
	body.WriteString("<script>")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&body, `location.href.indexOf("p%02d=");`, i)
	}
	body.WriteString("</script>")
	got := discovery.ExtractScriptParamNames(body.String())
	if len(got) != 32 {
		t.Fatalf("candidate count = %d, want cap 32", len(got))
	}
	for i, name := range got {
		want := fmt.Sprintf("p%02d", i)
		if name != want {
			t.Fatalf("candidate[%d] = %q, want %q", i, name, want)
		}
	}
}

func TestEndpointKeySeparatesFragmentRoutesAndCollapsesValues(t *testing.T) {
	route, _ := discovery.Normalize("http://h/#/search?q=a")
	routeOtherValue, _ := discovery.Normalize("http://h/#/search?q=zzz")
	routeOtherParam, _ := discovery.Normalize("http://h/#/search?x=a")
	home, _ := discovery.Normalize("http://h/")
	kRoute := discovery.EndpointKey(domain.MethodGET, route)
	if kRoute == discovery.EndpointKey(domain.MethodGET, home) {
		t.Errorf("route endpoint collided with the home endpoint: %q", kRoute)
	}
	if kRoute != discovery.EndpointKey(domain.MethodGET, routeOtherValue) {
		t.Errorf("same route with a different value made a different endpoint: %q vs %q",
			kRoute, discovery.EndpointKey(domain.MethodGET, routeOtherValue))
	}
	if kRoute == discovery.EndpointKey(domain.MethodGET, routeOtherParam) {
		t.Errorf("same route with a different fragment parameter name collided: %q", kRoute)
	}
}

func TestEndpointKeyDoesNotCollideOnEncodedOuterQueryName(t *testing.T) {
	oneName, err := discovery.Normalize("http://h/?q%26x=1")
	if err != nil {
		t.Fatal(err)
	}
	twoNames, err := discovery.Normalize("http://h/?q=1&x=2")
	if err != nil {
		t.Fatal(err)
	}
	if discovery.EndpointKey(domain.MethodGET, oneName) == discovery.EndpointKey(domain.MethodGET, twoNames) {
		t.Fatal("one encoded parameter name collided with two distinct parameter names")
	}
}

func TestExtractScriptParamNames(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "indexOf literal read of the page URL (DVWA xss_d shape)",
			body: `<script>if (document.location.href.indexOf("default=") >= 0) {}</script>`,
			want: []string{"default"},
		},
		{
			name: "URLSearchParams get with a literal name",
			body: `<script>const p = new URLSearchParams(location.search); p.get('lang')</script>`,
			want: []string{"lang"},
		},
		{
			name: "getParameterByName helper with a literal name",
			body: `<script>var id = getParameterByName("id");</script>`,
			want: []string{"id"},
		},
		{
			name: "sorted and de-duplicated across occurrences",
			body: `<script>const p = new URLSearchParams(location.search); p.get("lang"); location.href.indexOf("default="); p.get("lang");</script>`,
			want: []string{"default", "lang"},
		},
		{
			name: "unrelated Map.get is not a URL parameter",
			body: `<script>const cache = new Map(); cache.get("account");</script>`,
			want: nil,
		},
		{
			name: "same text outside a script is not a JavaScript read",
			body: `<p>indexOf("default=")</p>`,
			want: nil,
		},
		{
			name: "names that are not plain identifiers are rejected",
			body: `<script>x.indexOf("a b=")</script>`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discovery.ExtractScriptParamNames(tc.body)
			if !reflect.DeepEqual(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
				t.Errorf("ExtractScriptParamNames = %v, want %v", got, tc.want)
			}
		})
	}
}

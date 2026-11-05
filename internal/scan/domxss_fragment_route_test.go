package scan

import "testing"

// A single-page-app route parameter lives inside the URL fragment. The DOM
// engine must set exactly that parameter, keep the route, and encode the value
// the way a fragment needs it. Whole-fragment replacement would drop the route.
func TestDOMXSSFragmentRouteURL(t *testing.T) {
	cases := []struct {
		name, endpoint, param, value, want string
	}{
		{"route with a plain value", "http://h/#/search", "q", "<img>", "http://h/#/search?q=%3Cimg%3E"},
		{"space is percent-encoded", "http://h/#/search", "q", "x y", "http://h/#/search?q=x%20y"},
		{"reserved characters in parameter name are encoded", "http://h/#/search", "q&x=1", "v", "http://h/#/search?q%26x%3D1=v"},
		{"existing query is kept", "http://h/?a=1#/search", "q", "v", "http://h/?a=1#/search?q=v"},
		{"endpoint without a route fragment", "http://h/", "q", "v", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domXSSFragmentRouteURL(tc.endpoint, tc.param, tc.value); got != tc.want {
				t.Errorf("domXSSFragmentRouteURL(%q,%q,%q) = %q, want %q", tc.endpoint, tc.param, tc.value, got, tc.want)
			}
		})
	}
}

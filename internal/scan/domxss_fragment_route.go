package scan

import (
	"net/url"
	"strings"
)

// domXSSFragmentRouteURL builds the navigation URL that sets param to value
// inside the route fragment of endpointURL, for example "#/search?q=<value>".
// It keeps the route and any non-fragment query, and percent-encodes the value
// the way a fragment is read back (jsEncodeURIComponent). It returns "" when
// endpointURL carries no route fragment. Other route parameters are not carried
// over: the probe sets only the parameter under test.
func domXSSFragmentRouteURL(endpointURL, param, value string) string {
	i := strings.IndexByte(endpointURL, '#')
	if i < 0 {
		return ""
	}
	base, frag := endpointURL[:i], endpointURL[i+1:]
	if !strings.HasPrefix(frag, "/") {
		return ""
	}
	route := frag
	if q := strings.IndexByte(frag, '?'); q >= 0 {
		route = frag[:q]
	}
	return base + "#" + route + "?" + url.QueryEscape(param) + "=" + jsEncodeURIComponent(value)
}

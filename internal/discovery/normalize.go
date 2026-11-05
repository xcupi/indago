package discovery

import (
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// URLInfo is a normalized, canonical view of a URL used for deduplication and
// scope checks. Canonical preserves a recognized SPA route path in the fragment
// (but not its fragment-query values); plain anchors remain omitted.
type URLInfo struct {
	Canonical  string     // canonical URL; recognized SPA route paths are preserved without fragment-query values
	Scheme     string     // lowercased, http or https
	Host       string     // lowercased host without default port
	HostPort   string     // host[:port] with default ports dropped
	Path       string     // cleaned path (dot-segments resolved; leading slash)
	Query      url.Values // parsed query
	ParamNames []string   // sorted, unique query parameter names

	// FragmentRoute is the path of a single-page-app route fragment such as
	// "/search" for "#/search?q=hello". Empty when the fragment is not a
	// route with a query string (a plain anchor is not a route).
	FragmentRoute string
	// FragmentParams are the sorted, unique query parameter names carried
	// inside the route fragment (e.g. "q" for "#/search?q=hello").
	FragmentParams []string
}

// defaultPort reports the default port for a scheme.
func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// Normalize parses and canonicalizes an absolute http(s) URL. Non-absolute or
// non-http(s) URLs are rejected so callers never persist or crawl them.
func Normalize(raw string) (URLInfo, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return URLInfo{}, err
	}
	return normalizeParsed(u)
}

// NormalizeRef resolves ref against base and normalizes the result. It is how
// links/forms discovered on a page are turned into absolute, canonical URLs.
func NormalizeRef(base, ref string) (URLInfo, error) {
	ref = strings.TrimSpace(ref)
	bu, err := url.Parse(base)
	if err != nil {
		return URLInfo{}, err
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return URLInfo{}, err
	}
	return normalizeParsed(bu.ResolveReference(ru))
}

func normalizeParsed(u *url.URL) (URLInfo, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return URLInfo{}, &url.Error{Op: "normalize", URL: u.String(), Err: errNonHTTP}
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return URLInfo{}, &url.Error{Op: "normalize", URL: u.String(), Err: errNoHost}
	}

	// Drop the port when it is the scheme default.
	port := u.Port()
	hostPort := host
	if port != "" && port != defaultPort(scheme) {
		hostPort = host + ":" + port
	}

	// Clean the path, resolving dot-segments while preserving a trailing slash.
	p := u.Path
	if p == "" {
		p = "/"
	}
	trailing := strings.HasSuffix(p, "/")
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if trailing && cleaned != "/" && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}

	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)

	canonical := scheme + "://" + hostPort + cleaned
	if enc := q.Encode(); enc != "" { // url.Values.Encode sorts by key
		canonical += "?" + enc
	}
	fragRoute, fragParams := parseFragmentRoute(u.EscapedFragment())
	if fragRoute != "" {
		canonical += "#" + fragRoute
		if len(fragParams) > 0 {
			encodedNames := make([]string, 0, len(fragParams))
			for _, name := range fragParams {
				encodedNames = append(encodedNames, url.QueryEscape(name)+"=")
			}
			canonical += "?" + strings.Join(encodedNames, "&")
		}
	}

	return URLInfo{
		Canonical:  canonical,
		Scheme:     scheme,
		Host:       host,
		HostPort:   hostPort,
		Path:       cleaned,
		Query:      q,
		ParamNames: names,

		FragmentRoute:  fragRoute,
		FragmentParams: fragParams,
	}, nil
}

// parseFragmentRoute reads a single-page-app route from the URL's escaped
// fragment representation. Keeping reserved escapes intact until ParseQuery is
// important: only literal '?', '&', and '=' delimit route/query syntax; escaped
// delimiters belong to the route or parameter name. Anything else (a plain
// "#section", or "#/about" without a query) is not a route.
func parseFragmentRoute(escapedFragment string) (string, []string) {
	if !strings.HasPrefix(escapedFragment, "/") {
		return "", nil
	}
	i := strings.IndexByte(escapedFragment, '?')
	if i < 0 {
		return "", nil
	}
	q, err := url.ParseQuery(escapedFragment[i+1:])
	if err != nil {
		return "", nil
	}
	names := make([]string, 0, len(q))
	for k := range q {
		if k != "" {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	sort.Strings(names)
	return escapedFragment[:i], names
}

// EndpointKey is the deduplication key for an endpoint. Legacy non-fragment
// endpoint keys retain their existing form; fragment-route keys use a versioned,
// length-prefixed tuple so path, route, and parameter names cannot collide.
func EndpointKey(method domain.HTTPMethod, info URLInfo) string {
	if info.FragmentRoute != "" {
		var b strings.Builder
		b.WriteString("v2:")
		writePart := func(value string) {
			b.WriteString(strconv.Itoa(len(value)))
			b.WriteByte(':')
			b.WriteString(value)
		}
		writePart(string(method))
		writePart(info.Scheme)
		writePart(info.HostPort)
		writePart(info.Path)
		writePart(strconv.Itoa(len(info.ParamNames)))
		for _, name := range info.ParamNames {
			writePart(name)
		}
		writePart(info.FragmentRoute)
		writePart(strconv.Itoa(len(info.FragmentParams)))
		for _, name := range info.FragmentParams {
			writePart(name)
		}
		return b.String()
	}

	var b strings.Builder
	b.WriteString(string(method))
	b.WriteString("|")
	b.WriteString(info.Scheme)
	b.WriteString("://")
	b.WriteString(info.HostPort)
	b.WriteString(info.Path)
	if len(info.ParamNames) > 0 {
		encodedNames := make([]string, 0, len(info.ParamNames))
		for _, name := range info.ParamNames {
			encodedNames = append(encodedNames, url.QueryEscape(name))
		}
		b.WriteString("?")
		b.WriteString(strings.Join(encodedNames, "&"))
	}
	return b.String()
}

// ParamKey is the deduplication key for a parameter on an endpoint.
func ParamKey(method domain.HTTPMethod, info URLInfo, name string, loc domain.ParamLocation) string {
	return EndpointKey(method, info) + "#" + string(loc) + ":" + name
}

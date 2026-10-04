package discovery

import (
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// URLInfo is a normalized, canonical view of a URL used for deduplication and
// scope checks.
type URLInfo struct {
	Canonical  string     // full canonical URL (sorted query, no fragment, default port dropped)
	Scheme     string     // lowercased, http or https
	Host       string     // lowercased host without default port
	HostPort   string     // host[:port] with default ports dropped
	Path       string     // cleaned path (dot-segments resolved; leading slash)
	Query      url.Values // parsed query
	ParamNames []string   // sorted, unique query parameter names
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

	return URLInfo{
		Canonical:  canonical,
		Scheme:     scheme,
		Host:       host,
		HostPort:   hostPort,
		Path:       cleaned,
		Query:      q,
		ParamNames: names,
	}, nil
}

// EndpointKey is the deduplication key for an endpoint: method plus the URL with
// query parameter *names* only (values stripped). This collapses value
// permutations (e.g. ?q=a and ?q=b) into one endpoint while preserving the
// parameter set, preventing crawl explosion.
func EndpointKey(method domain.HTTPMethod, info URLInfo) string {
	var b strings.Builder
	b.WriteString(string(method))
	b.WriteString("|")
	b.WriteString(info.Scheme)
	b.WriteString("://")
	b.WriteString(info.HostPort)
	b.WriteString(info.Path)
	if len(info.ParamNames) > 0 {
		b.WriteString("?")
		b.WriteString(strings.Join(info.ParamNames, "&"))
	}
	return b.String()
}

// ParamKey is the deduplication key for a parameter on an endpoint.
func ParamKey(method domain.HTTPMethod, info URLInfo, name string, loc domain.ParamLocation) string {
	return EndpointKey(method, info) + "#" + string(loc) + ":" + name
}

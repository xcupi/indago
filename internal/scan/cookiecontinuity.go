package scan

// Response-cookie continuity for ONE page-disclosure follow-up.
//
// Some targets bind a server-disclosed path to the anonymous session cookie
// the SAME response minted: the home page hands out a fresh session cookie and
// its own script names the admin path that cookie unlocks, while the path is
// bound to that exact value (Lab 19, "unprotected admin functionality with
// unpredictable URL"). A probe that re-uses the stored jar, or that sends
// nothing at all, sees a 404 and the path is never tested — a false negative
// even though the path was extracted correctly.
//
// continuityCookies derives, from ONE response's Set-Cookie headers, the
// cookies that a browser would send on a follow-up request to a target URL:
//
//   - the response and the target must share an origin (scheme, host, effective
//     port). A cookie is never carried across an origin boundary, even when
//     its Domain attribute would permit it: a disclosed path is only ever
//     resolved on the page's own origin, and continuity stops there.
//   - host-only cookies (no Domain attribute) stay on the exact host; a Domain
//     attribute is a domain cookie with or without the legacy leading dot and
//     must cover the host that set it (RFC 6265 §5.3), or it is not kept.
//   - a missing or relative Path takes the RFC 6265 §5.1.4 default-path of the
//     response URL, so a cookie set by /account/ is not sent to /admin-…
//   - Secure cookies are only kept for https targets, expired / Max-Age<=0
//     cookies are dropped, and `Partitioned` cookies are refused (a raw HTTP
//     request has no top-level-site partition context).
//
// The result is a plain value: it lives for the duration of one job and is never
// written to the store, the scan config, logs or report detail — the probe's
// evidence records each cookie NAME with its value redacted (see persistPair),
// never the value itself. Nothing here reads or writes the scan's authenticated
// session cookies — those keep their own, separate path.
//
// Both ends of the hand-over are isolated from the ambient cookie state. The
// disclosure fetch (and the external-script fetch beside it) runs with
// httpengine.Request.NoJar, so the response that issues these cookies neither
// reads the HTTP client's shared jar nor writes to it; the follow-up probe runs
// Jarless, so the derived value is the only cookie state it sees. The
// continuity therefore exists only as this function's return value for the
// duration of the job.

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxContinuityCookies bounds the replay set. A real anonymous session cookie
// set is a handful of cookies; a response that would make a probe carry
// hundreds is not evidence of anything, and the probe stays bounded.
const maxContinuityCookies = 16

// continuityCookies returns the cookies responseURL's Set-Cookie headers set
// that may be sent to targetURL. header is the response's header block; the
// returned cookies carry the Domain/Path/Expires/Secure scope derived above so
// the engine can re-evaluate them on every redirect hop.
//
// It returns nil when the two URLs are not same-origin, when the response set
// no cookies, or when no cookie's scope reaches targetURL.
func continuityCookies(responseURL string, header http.Header, targetURL string) []*http.Cookie {
	if len(header.Values("Set-Cookie")) == 0 {
		return nil
	}
	respURL, ok := parseHTTPURL(responseURL)
	if !ok {
		return nil
	}
	if _, ok := parseHTTPURL(targetURL); !ok {
		return nil
	}
	if !sameOriginURL(responseURL, targetURL) {
		return nil
	}
	respHost, ok := normalizedCookieHost(respURL.Hostname())
	if !ok {
		return nil
	}
	setCookies := (&http.Response{Header: header}).Cookies()
	if len(setCookies) == 0 {
		return nil
	}

	defaultPath := cookieDefaultPath(respURL.EscapedPath())
	now := time.Now()
	out := make([]*http.Cookie, 0, len(setCookies))
	for _, set := range setCookies {
		if set == nil || set.Partitioned {
			continue
		}
		cookie := *set
		switch {
		case set.Domain == "":
			// No Domain attribute: a host-only cookie for the host that set it.
			cookie.Domain = respHost
		default:
			// A Set-Cookie Domain attribute denotes a DOMAIN cookie whether or
			// not it carries the legacy leading dot (RFC 6265 §5.2.3). The
			// engine's storage-state representation uses the dot to tell the
			// two apart, so normalize only after proving the attribute
			// genuinely covers the host that set it (RFC 6265 §5.3).
			domain := strings.ToLower(strings.TrimPrefix(set.Domain, "."))
			if domain == "" {
				continue
			}
			if strings.EqualFold(respHost, domain) {
				// Naming the setting host itself (including an IP) is
				// host-only in effect for this replay: it can never widen
				// into the parent domain.
				cookie.Domain = respHost
			} else if cookieDomainPermitsHost("."+domain, respHost) {
				cookie.Domain = "." + domain
			} else {
				// A Domain that does not cover the response host was not
				// validly set; never widen it into a scope it never had.
				continue
			}
		}
		if cookie.Path == "" || !strings.HasPrefix(cookie.Path, "/") {
			cookie.Path = defaultPath
		}
		switch {
		case cookie.MaxAge < 0:
			continue // already expired
		case cookie.MaxAge > 0:
			cookie.Expires = now.Add(time.Duration(cookie.MaxAge) * time.Second)
		}
		if !cookiePermitsURL(&cookie, targetURL) {
			continue
		}
		out = append(out, &cookie)
		if len(out) >= maxContinuityCookies {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cookieDefaultPath implements the RFC 6265 §5.1.4 default-path of a request
// URI path: everything up to (but not including) the right-most "/", or "/"
// when the path has no more than one "/".
func cookieDefaultPath(uriPath string) string {
	if uriPath == "" || !strings.HasPrefix(uriPath, "/") {
		return "/"
	}
	right := strings.LastIndexByte(uriPath, '/')
	if right <= 0 {
		return "/"
	}
	return uriPath[:right]
}

// cookieDomainPermitsHost reports whether a cookie's Domain attribute covers
// host. A leading dot denotes a Domain cookie (subdomains included); a domain
// without one is host-only, matching the storage-state representation used by
// cookiePermitsURL.
func cookieDomainPermitsHost(rawDomain, host string) bool {
	cookieDomain, domainCookie, ok := cookieDomainParts(rawDomain)
	if !ok {
		return false
	}
	cookieHost, ok := normalizedCookieHost(host)
	if !ok {
		return false
	}
	if domainCookie {
		return cookieHost == cookieDomain || strings.HasSuffix(cookieHost, "."+cookieDomain)
	}
	return cookieHost == cookieDomain
}

// parseHTTPURL parses one absolute http(s) URL.
func parseHTTPURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, false
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return nil, false
	}
	return u, true
}

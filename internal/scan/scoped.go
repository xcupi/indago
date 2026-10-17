package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/ratelimit"
	"golang.org/x/net/publicsuffix"
)

// maxScopedRedirects bounds the redirect chain followed by scopedEngine.
const maxScopedRedirects = 10

// scopedEngine wraps an httpengine.Engine so that NO request leaves the scan's
// scope — including requests caused by redirects.
//
// The HTTP engine deliberately performs no scope checks (scope enforcement lives
// outside that module). The controller therefore enforces it here, at the
// boundary where discovery obtains its engine:
//
//  1. every request URL is checked against scope (fail closed) before it is sent;
//  2. redirects are followed MANUALLY, re-checking scope on every hop, so an
//     in-scope page cannot bounce the crawler to an out-of-scope host.
//
// For (2) to hold, the wrapped engine MUST be configured with
// FollowRedirects=false; otherwise it would follow redirects itself, bypassing
// the per-hop check. cmd/indago builds its client that way.
type scopedEngine struct {
	inner httpengine.Engine
	scope domain.Scope
	// cookies are the scan's saved session cookies. cookiesForURL applies each
	// cookie's scope separately for the current URL/hop; nil for most scans
	// (anonymous auth, or no browser storage state).
	cookies []*http.Cookie
	// limiter paces every request this engine sends (one permit per request,
	// per redirect hop), after the scope check — see WithRateLimiter.
	limiter *ratelimit.Limiter
}

var _ httpengine.Engine = (*scopedEngine)(nil)

func newScopedEngine(inner httpengine.Engine, scope domain.Scope) *scopedEngine {
	return &scopedEngine{inner: inner, scope: scope}
}

// WithSessionCookies gives scopedEngine the saved browser cookies to evaluate
// independently against each request URL, including every redirect hop. The
// scan's authenticated session (established for browser verification) is ALSO
// carried by plain HTTP-level reflection/candidate testing, but only where the
// cookie's stored domain/host, path, scheme, and expiry permit it. Returns the
// same engine for chaining. Each scopedEngine instance is scan-scoped (built
// fresh per launch), so this never leaks one scan's cookies into another's
// requests even though the underlying transport (c.opts.HTTP) is shared.
func (s *scopedEngine) WithSessionCookies(cookies []*http.Cookie) *scopedEngine {
	s.cookies = cookies
	return s
}

// WithRateLimiter paces every request this engine sends with the scan's shared
// limiter: one permit per request and per redirect hop, taken AFTER the scope
// check (an out-of-scope request never consumes a permit) and BEFORE the request
// leaves. nil leaves the engine unpaced. Returns the same engine for chaining.
func (s *scopedEngine) WithRateLimiter(l *ratelimit.Limiter) *scopedEngine {
	s.limiter = l
	return s
}

// Do implements httpengine.Engine.
func (s *scopedEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", httpengine.ErrInvalidRequest)
	}
	cur := *req // never mutate the caller's request
	requestCookies := append([]*http.Cookie(nil), req.Cookies...)
	var chain []string

	for hop := 0; ; hop++ {
		if d := s.scope.Permits(cur.URL); !d.Allowed {
			return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
		}
		// Pace AFTER the scope check (an out-of-scope request takes no permit)
		// and BEFORE the request is sent — once per hop, so redirects count.
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		// Rebuild the cookie list for this URL on every hop. Session cookies
		// carry storage-state scope metadata; request-specific overrides remain
		// first so a targeted injection wins over a same-named session cookie.
		cur.Cookies = s.cookiesForURL(cur.URL, req.URL, requestCookies, hop == 0)
		resp, err := s.inner.Do(ctx, &cur)
		if err != nil {
			return nil, err
		}
		if !isRedirectStatus(resp.Status) {
			resp.RedirectChain = chain
			resp.FinalURL = cur.URL
			return resp, nil
		}

		loc := resp.Headers.Get("Location")
		if loc == "" {
			resp.RedirectChain = chain
			resp.FinalURL = cur.URL
			return resp, nil // redirect without a target: hand the 3xx back
		}
		next, err := resolveRedirect(cur.URL, loc)
		if err != nil {
			return nil, fmt.Errorf("%w: bad redirect Location %q", httpengine.ErrInvalidRequest, loc)
		}
		if hop >= maxScopedRedirects {
			return nil, httpengine.ErrTooManyRedirects
		}
		chain = append(chain, next)
		cur.URL = next
		// Per RFC 9110, 301/302/303 turn a non-GET/HEAD into GET and drop the body;
		// 307/308 preserve method and body.
		if resp.Status == 301 || resp.Status == 302 || resp.Status == 303 {
			if cur.Method != "" && cur.Method != http.MethodGet && cur.Method != http.MethodHead {
				cur.Method = http.MethodGet
				cur.Body = nil
				cur.ContentType = ""
			}
		}
	}
}

// cookiesForURL combines explicit request cookies with only those saved-session
// cookies whose browser scope permits rawURL. An explicit request cookie wins
// over a same-named session cookie. A cookie override without its own scope can
// follow a redirect only when a same-named stored cookie matched both the
// original request and the redirected URL; otherwise it is one-hop-only.
func (s *scopedEngine) cookiesForURL(rawURL, initialURL string, requestCookies []*http.Cookie, firstHop bool) []*http.Cookie {
	activeRequestCookies := make([]*http.Cookie, 0, len(requestCookies))
	existing := make(map[string]struct{}, len(requestCookies))
	for _, requestCookie := range requestCookies {
		if requestCookie == nil {
			continue
		}
		if requestCookie.Domain != "" && requestCookie.Path != "" {
			if cookiePermitsURL(requestCookie, rawURL) {
				activeRequestCookies = append(activeRequestCookies, requestCookie)
				existing[requestCookie.Name] = struct{}{}
			}
			continue
		}

		matchedStoredScope := false
		storedNameExists := false
		for _, storedCookie := range s.cookies {
			if storedCookie == nil || storedCookie.Name != requestCookie.Name {
				continue
			}
			storedNameExists = true
			if cookiePermitsURL(storedCookie, initialURL) && cookiePermitsURL(storedCookie, rawURL) {
				matchedStoredScope = true
				break
			}
		}
		if matchedStoredScope || (firstHop && !storedNameExists) {
			activeRequestCookies = append(activeRequestCookies, requestCookie)
			existing[requestCookie.Name] = struct{}{}
		}
	}

	out := append([]*http.Cookie(nil), activeRequestCookies...)
	for _, c := range s.cookies {
		if c == nil {
			continue
		}
		if _, overridden := existing[c.Name]; overridden {
			continue
		}
		if cookiePermitsURL(c, rawURL) {
			out = append(out, c)
		}
	}
	return out
}

// cookiePermitsURL implements the storage-state cookie checks needed by a raw
// HTTP request. A leading dot in Domain denotes a Domain cookie (and permits
// subdomains); a domain without a leading dot is host-only, matching the
// Playwright storage-state serialization observed from Chromium.
func cookiePermitsURL(c *http.Cookie, rawURL string) bool {
	if c == nil || c.Valid() != nil || !validCookiePath(c.Path) {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if c.Secure && scheme != "https" {
		return false
	}
	if !c.Expires.IsZero() && !c.Expires.After(time.Now()) {
		return false
	}

	cookieDomain, domainCookie, ok := cookieDomainParts(c.Domain)
	if !ok {
		return false
	}
	host, ok := normalizedCookieHost(u.Hostname())
	if !ok {
		return false
	}
	if domainCookie {
		if host != cookieDomain && !strings.HasSuffix(host, "."+cookieDomain) {
			return false
		}
	} else if host != cookieDomain {
		return false
	}

	requestPath := u.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	return cookiePathMatches(c.Path, requestPath)
}

func cookieDomainParts(raw string) (domain string, domainCookie bool, ok bool) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", false, false
	}
	if strings.HasPrefix(raw, ".") {
		domainCookie = true
		raw = raw[1:]
	}
	if raw == "" || strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") {
		return "", false, false
	}
	domain, ok = normalizedCookieHost(raw)
	if !ok {
		return "", false, false
	}
	if domainCookie {
		if net.ParseIP(domain) != nil {
			return "", false, false
		}
		publicSuffix, _ := publicsuffix.PublicSuffix(domain)
		if publicSuffix == domain {
			return "", false, false
		}
	}
	return domain, domainCookie, true
}

func normalizedCookieHost(host string) (string, bool) {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\\\\/%?#@ 	\r\n") {
		return "", false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.HasSuffix(host, ".") {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}
	if len(host) > 253 || strings.Contains(host, ":") {
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", false
			}
		}
	}
	return host, true
}

func validCookiePath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || r == ';' {
			return false
		}
	}
	return true
}

func cookiePathMatches(cookiePath, requestPath string) bool {
	if cookiePath == requestPath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || requestPath[len(cookiePath)] == '/'
}

func isRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// sessionCookies reads a browser storage-state file and retains every valid
// cookie for per-request scoping by scopedEngine. Missing/unreadable/malformed
// state yields no cookies; a malformed individual cookie is skipped rather
// than being sent with guessed host/path semantics.
func sessionCookies(statePath string) []*http.Cookie {
	if statePath == "" {
		return nil
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var state struct {
		Cookies []struct {
			Name         string   `json:"name"`
			Value        string   `json:"value"`
			Domain       string   `json:"domain"`
			Path         string   `json:"path"`
			Expires      *float64 `json:"expires"`
			HTTPOnly     bool     `json:"httpOnly"`
			Secure       bool     `json:"secure"`
			SameSite     string   `json:"sameSite"`
			PartitionKey *string  `json:"partitionKey"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	var out []*http.Cookie
	for _, stored := range state.Cookies {
		if stored.PartitionKey != nil {
			// Raw HTTP requests have no top-level-site partition context; do
			// not broaden a partitioned browser cookie into an unpartitioned one.
			continue
		}
		if _, _, ok := cookieDomainParts(stored.Domain); !ok || !validCookiePath(stored.Path) {
			continue
		}
		basic := &http.Cookie{Name: stored.Name, Value: stored.Value}
		if basic.Valid() != nil {
			continue
		}
		cookie := &http.Cookie{
			Name:     stored.Name,
			Value:    stored.Value,
			Domain:   stored.Domain,
			Path:     stored.Path,
			HttpOnly: stored.HTTPOnly,
			Secure:   stored.Secure,
		}
		switch stored.SameSite {
		case "":
		case "Strict":
			cookie.SameSite = http.SameSiteStrictMode
		case "Lax":
			cookie.SameSite = http.SameSiteLaxMode
		case "None":
			cookie.SameSite = http.SameSiteNoneMode
		default:
			continue
		}
		if stored.Expires != nil {
			expires := *stored.Expires
			switch {
			case expires == -1:
				// Playwright represents session cookies with expires=-1.
			case expires < 0 || math.IsNaN(expires) || math.IsInf(expires, 0) || expires >= float64(math.MaxInt64):
				continue
			default:
				sec, fraction := math.Modf(expires)
				cookie.Expires = time.Unix(int64(sec), int64(math.Round(fraction*float64(time.Second))))
			}
		}
		out = append(out, cookie)
	}
	return out
}

func resolveRedirect(base, loc string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return bu.ResolveReference(lu).String(), nil
}

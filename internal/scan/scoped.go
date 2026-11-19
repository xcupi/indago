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
	// authHeaders are bearer tokens recovered from the saved browser storage
	// state (SPA localStorage). They are applied only to their exact origin and
	// are dropped again on a redirect to another origin.
	authHeaders []sessionAuthHeader
	// limiter paces every request this engine sends (one permit per request,
	// per redirect hop), after the scope check — see WithRateLimiter.
	limiter *ratelimit.Limiter
}

// sessionAuthHeader is one bearer token recovered from the scan's saved browser
// storage state. Value is already a complete Authorization header value.
//
// An exact-origin token (HostOnly false) is applied only to the origin that
// stored it. A HostOnly token is a host-scoped fallback, recovered from a
// cookie: it is used only for requests to that host for which no exact-origin
// token matched, which is what lets a JWT-in-cookie SPA authenticate raw HTTP
// requests without ever sending the token to another host.
type sessionAuthHeader struct {
	Origin   string
	Value    string
	HostOnly bool
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

// WithSessionAuthHeaders gives scopedEngine bearer credentials recovered from
// the saved browser state. They are never sent outside the origin that stored
// them, and an explicit Authorization header on the request always wins.
func (s *scopedEngine) WithSessionAuthHeaders(headers []sessionAuthHeader) *scopedEngine {
	s.authHeaders = headers
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

// sessionBearerFor returns the Authorization header value this engine would send
// to rawURL: a token stored for rawURL's exact origin always wins, and a
// host-scoped token recovered from a cookie is used only as a fallback for
// requests no exact-origin token covers. Empty when the engine holds no bearer
// credential for the URL.
//
// It is also how the IDOR engine reads the caller identity offline: the token
// that authenticates a request also carries the claims that name the caller.
func (s *scopedEngine) sessionBearerFor(rawURL string) string {
	return sessionBearerFrom(s.authHeaders, rawURL)
}

// sessionBearerFrom is sessionBearerFor's logic as a free function, so a caller
// that has the scan's recovered headers but not the engine (the JWT pass's
// bounded enqueue, which must know which origins even carry a bearer token)
// applies exactly the same origin/host matching.
func sessionBearerFrom(headers []sessionAuthHeader, rawURL string) string {
	for _, h := range headers {
		if !h.HostOnly && h.Origin != "" && sameURLOrigin(rawURL, h.Origin) {
			return h.Value
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	for _, h := range headers {
		if !h.HostOnly || h.Origin == "" {
			continue
		}
		if strings.EqualFold(host, strings.TrimPrefix(strings.ToLower(h.Origin), ".")) {
			return h.Value
		}
	}
	return ""
}

// Do implements httpengine.Engine.
func (s *scopedEngine) Do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", httpengine.ErrInvalidRequest)
	}
	cur := *req // never mutate the caller's request
	if len(s.authHeaders) > 0 && !cur.NoCookies {
		// The header is added/removed per redirect hop; work on a copy so the
		// caller's request map is never mutated.
		cur.Headers = cloneHeaderMap(req.Headers)
	}
	requestCookies := append([]*http.Cookie(nil), req.Cookies...)
	var chain []string

	for hop := 0; ; hop++ {
		if d := s.scope.Permits(cur.URL); !d.Allowed {
			if hop > 0 {
				return nil, fmt.Errorf("%w: %s", ErrOutOfScopeRedirect, d.Reason)
			}
			return nil, fmt.Errorf("%w: %s", ErrOutOfScope, d.Reason)
		}
		// Pace AFTER the scope check (an out-of-scope request takes no permit)
		// and BEFORE the request is sent — once per hop, so redirects count.
		if err := s.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		// Apply the saved SPA bearer token only to the exact origin that stored
		// it, falling back to a host-scoped token recovered from a cookie when
		// no exact-origin token covers this request. A redirect can change
		// origin (or host); never carry a token across it.
		if !cur.NoCookies {
			if _, explicit := req.Headers["Authorization"]; !explicit {
				delete(cur.Headers, "Authorization")
				if value := s.sessionBearerFor(cur.URL); value != "" {
					cur.Headers = ensureHeaderMap(cur.Headers)
					cur.Headers["Authorization"] = value
				}
			}
		}

		// Rebuild the cookie list for this URL on every hop. Session cookies
		// carry storage-state scope metadata; request-specific overrides remain
		// first so a targeted injection wins over a same-named session cookie.
		// A NoCookies request is a deliberate anonymous probe: attach nothing.
		// A Jarless request carries ONLY the cookies the caller supplied, each
		// evaluated against this hop by its own scope metadata — the scan's
		// session cookies and the ambient jar are deliberately out of it.
		// A NoJar request takes the default path below (explicit saved session
		// cookies included): the transport hides the jar in both directions,
		// which is the one thing that separates it from Jarless.
		switch {
		case cur.NoCookies:
			cur.Cookies = nil
		case cur.Jarless:
			cur.Cookies = jarlessCookiesForURL(cur.URL, req.URL, requestCookies, hop == 0)
		default:
			cur.Cookies = s.cookiesForURL(cur.URL, req.URL, requestCookies, hop == 0)
		}
		resp, err := s.inner.Do(ctx, &cur)
		if err != nil {
			return nil, err
		}
		// A NoRedirects request wants the 3xx itself (a redirect body can be
		// the only place an object is disclosed); hand it back before the
		// scope-enforcing loop follows it away.
		if cur.NoRedirects || !isRedirectStatus(resp.Status) {
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
			resp.RedirectChain = chain
			resp.FinalURL = cur.URL
			return resp, nil // unparseable Location cannot be followed; hand the 3xx back
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

// jarlessCookiesForURL filters a jarless request's own cookies against one hop
// URL. A cookie carrying its own browser scope (Domain and Path — this is how
// continuityCookies hands its result over) is re-evaluated on every hop, so it
// follows a same-origin redirect exactly where a browser would send it. A
// cookie without scope metadata is a single-hop override.
//
// RFC 6265 cookie scope ignores ports, but a replay set is stricter on purpose:
// it was issued by ONE origin, so it is dropped as soon as a hop leaves that
// origin (scheme, host and effective port), never merely the host.
func jarlessCookiesForURL(rawURL, initialURL string, requestCookies []*http.Cookie, firstHop bool) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(requestCookies))
	sameOrigin := sameOriginURL(initialURL, rawURL)
	for _, requestCookie := range requestCookies {
		if requestCookie == nil {
			continue
		}
		if requestCookie.Domain == "" || requestCookie.Path == "" {
			if firstHop {
				out = append(out, requestCookie)
			}
			continue
		}
		if !sameOrigin {
			continue
		}
		if cookiePermitsURL(requestCookie, rawURL) {
			out = append(out, requestCookie)
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

	if !cookieDomainPermitsHost(c.Domain, u.Hostname()) {
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

func sameURLOrigin(rawURL, rawOrigin string) bool {
	a, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	b, err := url.Parse(rawOrigin)
	if err != nil {
		return false
	}
	return a.Scheme != "" && strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host)
}

func ensureHeaderMap(headers map[string]string) map[string]string {
	if headers == nil {
		return make(map[string]string, 1)
	}
	return headers
}

func cloneHeaderMap(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = v
	}
	return out
}

// sessionCookieTokenNames are the cookie names an SPA commonly stores its bearer
// JWT under. Only these names, and only a JWT-shaped value, are turned into a
// fallback Authorization header: an arbitrary cookie is never one.
var sessionCookieTokenNames = map[string]bool{
	"token": true, "access_token": true, "access-token": true,
	"id_token": true, "jwt": true, "auth_token": true,
}

// sessionAuthHeaders recovers bearer tokens from Playwright storage state: first
// from localStorage (scoped to the exact origin recorded in the state file),
// then from cookies (scoped to the cookie's host, used only when no
// exact-origin token matched the request). Only a small set of conventional
// token names and JWT-shaped values are considered; arbitrary stored values are
// never turned into headers.
func sessionAuthHeaders(statePath string) []sessionAuthHeader {
	if statePath == "" {
		return nil
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var state struct {
		Origins []struct {
			Origin       string `json:"origin"`
			LocalStorage []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"localStorage"`
		} `json:"origins"`
		Cookies []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
			// partitionKey is an object in newer storage states; a raw pointer
			// keeps a partitioned cookie recognisable without failing the whole
			// state parse on its shape.
			PartitionKey *json.RawMessage `json:"partitionKey"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	var out []sessionAuthHeader
	seen := map[string]bool{}
	for _, origin := range state.Origins {
		u, err := url.Parse(origin.Origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		for _, entry := range origin.LocalStorage {
			name := strings.ToLower(strings.TrimSpace(entry.Name))
			value := strings.TrimSpace(entry.Value)
			if value == "" || len(value) > 8192 {
				continue
			}
			switch name {
			case "token", "access_token", "access-token", "id_token", "jwt", "auth_token", "authorization":
			default:
				continue
			}
			header := value
			if name == "authorization" {
				if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
					continue
				}
			} else if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
				if !looksLikeJWT(value) {
					continue
				}
				header = "Bearer " + value
			}
			key := u.Scheme + "://" + u.Host
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sessionAuthHeader{Origin: key, Value: header})
		}
	}
	// A JWT kept in an httpOnly cookie is invisible to localStorage but is
	// still the scan's own session credential. It becomes a host-scoped
	// fallback: exact-origin tokens above always win, and a request to any
	// other host never sees it. Partitioned cookies are skipped for the same
	// reason sessionCookies skips them: a raw request has no partition context.
	for _, cookie := range state.Cookies {
		if cookie.PartitionKey != nil {
			continue
		}
		if !sessionCookieTokenNames[strings.ToLower(strings.TrimSpace(cookie.Name))] {
			continue
		}
		value := strings.TrimSpace(cookie.Value)
		if value == "" || len(value) > 8192 || !looksLikeJWT(value) {
			continue
		}
		host, _, ok := cookieDomainParts(cookie.Domain)
		if !ok {
			continue
		}
		key := "host:" + host
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sessionAuthHeader{Origin: host, Value: "Bearer " + value, HostOnly: true})
	}
	return out
}

func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	return len(parts) == 3 && len(parts[0]) > 4 && len(parts[1]) > 4
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

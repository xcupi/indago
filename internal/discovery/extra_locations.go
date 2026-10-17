package discovery

import (
	"context"
	"regexp"

	"github.com/indago/indago/internal/domain"
)

// This file registers injection points for the two remaining ParamLocation
// values that are not derived purely from the URL/body: Header and Cookie.
// (Path is purely URL-derived and lives in path_segments.go.)

// defaultHeaderInjectionNames is the small, conservative, DEFAULT set of
// commonly-reflected request headers Indago additionally registers as
// injection points (domain.LocationHeader) for every discovered endpoint.
// Deliberately small: these are headers real applications are commonly
// observed echoing back into a response (User-Agent in a "detected
// browser"/log/debug banner, Referer in a referrer-aware page, X-Forwarded-
// For in an "your IP is ..." display) — not an attempt to enumerate every
// header a target might reflect.
var defaultHeaderInjectionNames = []string{"User-Agent", "Referer", "X-Forwarded-For"}

// sessionCookieNamePattern is a liberal, name-based heuristic for "this
// cookie is almost certainly the scan's own authentication/session cookie
// (or a CSRF-token cookie protecting it)" — mirrors the equally liberal
// dynamicTokenName heuristic in internal/scan/dynamic_params.go: a
// false-positive match only costs one cookie that does not get tested for
// reflection (harmless), while a false negative would let Indago overwrite
// the scan's own login cookie mid-test, which is the one outcome this
// exists to prevent. Matches common session-cookie names (PHPSESSID,
// JSESSIONID, connect.sid, laravel_session, …) and auth/token/jwt/csrf
// cookies alike.
var sessionCookieNamePattern = regexp.MustCompile(`(?i)sess|sid|auth|token|jwt|csrf|xsrf`)

func isSessionCookieName(name string) bool { return sessionCookieNamePattern.MatchString(name) }

// registerHeaderInjectionPoints registers an injection point for each
// default header name (see defaultHeaderInjectionNames) on the endpoint —
// headers are location-agnostic (not derived from the URL), so every
// endpoint gets the same small set. Example is left empty: unlike a query/
// form/JSON parameter there is no "observed" header value from discovery
// alone — the baseline request simply uses whatever header the HTTP engine
// would normally send, and only the mutated/candidate request overrides it
// (see buildRequest in internal/scan/executor.go).
func (c *Collector) registerHeaderInjectionPoints(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, source domain.DiscoverySource) {
	for _, name := range defaultHeaderInjectionNames {
		c.registerParam(ctx, endpointID, method, info, name, domain.LocationHeader, "", source)
	}
}

// registerCookieInjectionPoints registers an injection point for every
// non-authentication cookie present in the scan's saved session context
// (c.cfg.SessionCookies). scopedEngine retains each cookie's scope and applies
// it to the mutated request and any redirect, so a cookie from another host or
// path is not sent just because its name was registered on this endpoint.
// Never fabricates a cookie: an anonymous scan has no points here.
func (c *Collector) registerCookieInjectionPoints(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, source domain.DiscoverySource) {
	for _, ck := range c.cfg.SessionCookies {
		if ck == nil || ck.Name == "" || isSessionCookieName(ck.Name) {
			continue
		}
		c.registerParam(ctx, endpointID, method, info, ck.Name, domain.LocationCookie, ck.Value, source)
	}
}

// registerPathInjectionPoints registers an injection point for every URL
// path segment that looks like a variable value rather than a literal route
// keyword (see QualifyingPathSegments) — e.g. the "42" in /users/42/edit,
// never "users" or "edit". The Parameter's Name encodes the segment's
// position (PathSegmentParamName) so buildRequest can recompute the SAME
// segment split from the endpoint's URL and substitute exactly that one
// segment.
func (c *Collector) registerPathInjectionPoints(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, source domain.DiscoverySource) {
	for _, m := range QualifyingPathSegments(info.Path) {
		c.registerParam(ctx, endpointID, method, info, PathSegmentParamName(m.Index), domain.LocationPath, m.Value, source)
	}
}

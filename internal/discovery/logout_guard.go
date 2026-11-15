package discovery

// Logout / session-destroying link guard for authenticated crawls.
//
// Almost every authenticated application puts a "Logout" link in the
// navigation of every page, and many carry the action in a query parameter
// (?action=logout) or behind a single-page-app route (#/logout). A crawler
// that follows one of them mid-scan ends the session it was explicitly given:
// every later request runs unauthenticated, and whatever sits behind the
// login is silently never tested. Discovery therefore refuses — on an
// authenticated scan only — to register or request a URL that names a
// session-termination action (see Collector.AllowFetch; an operator-provided
// seed is explicit intent and is exempt).
//
// The guard is a name heuristic, not a security control. It recognizes three
// shapes, all word-bounded, so "/blog/out", "/catalog/outlet" and "/login" are
// untouched:
//
//   - a path or parameter name that is itself the action: /logout,
//     /logout.php, /auth/sign-out, /user_logout, ?logout=1, ?signout;
//   - a session object paired with a verb that ends it, in either order:
//     /session/destroy, /api/v1/auth/token/revoke, session_destroy,
//     destroy-session;
//   - an action-valued query parameter: ?action=logout, ?op=sign-out,
//     ?do=logoff, ?action=session.destroy. A value that merely mentions the
//     word (?q=logout, ?next=/logout) is not an action and stays discoverable.
//
// SPA route fragments are checked as well: #/logout is never requested as its
// own URL, but rendering it under the seed page still performs the logout.
//
// It cannot see a link that looks harmless but redirects to a logout endpoint,
// and it does not split CamelCase ("LogoutServlet" is one word and does not
// match). A false positive costs one skipped URL; a false negative can end the
// session mid-scan and invalidate everything after it, so the guard
// deliberately errs toward skipping.

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// logoutToken matches one whole word that names a session-termination
	// action: logout, log-out, log_out, "log out", logoff, signout, sign-out.
	// Word boundaries are any non-alphanumeric character, so "/logout.php",
	// "/user_logout" and "/do/sign-out" match while "/blog/out",
	// "/catalog/outlet" and "LogoutServlet" do not.
	logoutToken = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(?:log[-_ ]?off|log[-_ ]?out|sign[-_ ]?out)(?:[^a-z0-9]|$)`)

	// wordSplit splits a path segment, parameter name or action value into
	// lowercased words: "/session/destroy.php" yields session, destroy, php.
	wordSplit = regexp.MustCompile(`[^a-z0-9]+`)
)

// sessionSubjects and sessionEndingVerbs are the two halves of the object+verb
// shape. Neither word alone is enough, which keeps "/session/start",
// "/session/refresh", "/auth/login" and "/oauth/authorize" out of the guard
// while "/session/end", "/auth/token/revoke" and "/session_destroy" match.
var (
	sessionSubjects = map[string]struct{}{
		"session": {}, "sessions": {},
		"auth": {}, "oauth": {},
		"token": {}, "tokens": {},
	}
	sessionEndingVerbs = map[string]struct{}{
		"destroy": {}, "terminate": {}, "end": {}, "kill": {},
		"invalidate": {}, "revoke": {}, "expire": {}, "close": {},
		"drop": {}, "unset": {}, "abort": {},
		"logout": {}, "logoff": {}, "signout": {},
	}
)

// queryActionParams are parameter names that carry an action verb instead of
// data. "?action=logout" is a logout trigger; "?q=logout" is a search for the
// word and stays discoverable.
var queryActionParams = map[string]struct{}{
	"action": {}, "actions": {}, "act": {}, "op": {}, "operation": {},
	"do": {}, "cmd": {}, "command": {}, "task": {}, "event": {},
	"func": {}, "function": {}, "method": {}, "mode": {}, "route": {},
}

// looksSessionTerminating reports whether rawURL names a logout / sign-out /
// session-destroy action — one that, if requested on an authenticated scan,
// would likely end the session. Only the URL's own path, query and route
// fragment are inspected: a malformed URL reports false, because failing
// closed on malformed/unparseable URLs is the scope check's job, not this
// heuristic's.
func looksSessionTerminating(rawURL string) bool {
	return sessionTerminationReason(rawURL) != ""
}

// sessionTerminationReason classifies why rawURL is guarded ("path", "query",
// "route") so a skip can be logged with its cause. It returns "" when the URL
// is not a session-termination URL.
func sessionTerminationReason(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if looksSessionTerminatingPath(u.Path) {
		return "path"
	}
	if looksSessionTerminatingQuery(u.Query()) {
		return "query"
	}
	if looksSessionTerminatingRoute(u.Fragment) {
		return "route"
	}
	return ""
}

// looksSessionTerminatingPath reports whether a URL path names a
// session-termination endpoint.
func looksSessionTerminatingPath(p string) bool {
	if p == "" {
		return false
	}
	if logoutToken.MatchString(p) {
		return true
	}
	return hasSessionEndingPair(splitWords(p))
}

// looksSessionTerminatingQuery reports whether the query string carries a
// session-termination action, either as the parameter name itself
// ("?logout=1") or as the value of an action parameter ("?action=logout").
// A parameter that merely holds the word as data ("?q=logout",
// "?next=/logout") is not an action and is left alone.
func looksSessionTerminatingQuery(q url.Values) bool {
	for name, values := range q {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		words := splitWords(name)
		if logoutToken.MatchString(name) || hasSessionEndingPair(words) {
			return true
		}
		if !hasActionWord(words) {
			continue
		}
		for _, v := range values {
			if looksSessionTerminatingAction(v) {
				return true
			}
		}
	}
	return false
}

// hasActionWord reports whether any word of a parameter name is an
// action-carrying name (see queryActionParams).
func hasActionWord(words []string) bool {
	for _, w := range words {
		if _, ok := queryActionParams[w]; ok {
			return true
		}
	}
	return false
}

// looksSessionTerminatingAction reports whether the value of an action
// parameter names a session-termination action. A leading path slash is
// tolerated (?action=/logout).
func looksSessionTerminatingAction(raw string) bool {
	v := strings.Trim(strings.TrimSpace(raw), "/")
	if v == "" {
		return false
	}
	if logoutToken.MatchString(v) {
		return true
	}
	return hasSessionEndingPair(splitWords(v))
}

// looksSessionTerminatingRoute applies the path and query rules to a
// single-page-app route fragment. "#/logout" and "#/session/destroy" are never
// sent as URLs of their own — the browser renders them under the seed page —
// but rendering one still performs the logout. Plain anchors ("#section") and
// fragments without a path separator are not routes and are ignored, matching
// extractSPARoutes/spaHashRoute.
func looksSessionTerminatingRoute(fragment string) bool {
	route := fragmentRouteReference(fragment)
	if route == "" {
		return false
	}
	u, err := url.Parse(route)
	if err != nil {
		return false
	}
	return looksSessionTerminatingPath(u.Path) || looksSessionTerminatingQuery(u.Query())
}

// fragmentRouteReference turns a route-like fragment into a parsable
// path+query reference, or returns "" when the fragment is not a route.
func fragmentRouteReference(fragment string) string {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" || len(fragment) > 512 {
		return ""
	}
	if strings.HasPrefix(fragment, "/") {
		return fragment
	}
	if !strings.Contains(fragment, "/") {
		return ""
	}
	return "/" + fragment
}

// hasSessionEndingPair reports whether two adjacent words form a session
// object plus a verb that ends it, in either order.
func hasSessionEndingPair(words []string) bool {
	for i := 0; i+1 < len(words); i++ {
		a, b := words[i], words[i+1]
		if isSessionSubject(a) && isSessionEndingVerb(b) {
			return true
		}
		if isSessionEndingVerb(a) && isSessionSubject(b) {
			return true
		}
	}
	return false
}

func isSessionSubject(word string) bool {
	_, ok := sessionSubjects[word]
	return ok
}

func isSessionEndingVerb(word string) bool {
	_, ok := sessionEndingVerbs[word]
	return ok
}

// splitWords lowercases s and splits it on every run of non-alphanumeric
// characters. Empty words (leading/trailing separators) are dropped.
func splitWords(s string) []string {
	parts := wordSplit.Split(strings.ToLower(s), -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

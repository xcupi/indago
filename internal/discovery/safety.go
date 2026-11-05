package discovery

import (
	"net/url"
	"regexp"
)

// sessionTerminatingPath matches URL path segments that look like a
// logout/sign-out endpoint. Bounded by anything that is not a letter or digit,
// so it catches "logout.php", "/auth/sign-out", "/user/log_off", "user_logout"
// and "logout_user" (an underscore is a separator here, unlike in regexp's \b)
// without flagging an unrelated word that merely contains one of these as a
// substring ("blog/outstanding", "catalog_outlet"). CamelCase names such as
// "LogoutServlet" are not recognized.
var sessionTerminatingPath = regexp.MustCompile(`(?i)(^|[^a-z0-9])(log[-_]?off|log[-_]?out|sign[-_]?out)([^a-z0-9]|$)`)

// looksSessionTerminating reports whether a URL's path looks like a
// logout/sign-out endpoint — one that, if requested, would likely end an
// authenticated session. Only the path is checked (not the query string or
// host), and a malformed URL conservatively reports false (the normal scope
// check downstream is what fails closed on malformed/unparseable URLs, not
// this heuristic).
func looksSessionTerminating(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return sessionTerminatingPath.MatchString(u.Path)
}

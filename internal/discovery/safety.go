package discovery

import (
	"net/url"
	"regexp"
)

// sessionTerminatingPath matches URL path segments that look like a
// logout/sign-out endpoint. Word-bounded so it catches "logout.php",
// "/auth/sign-out", "/user/log_off" etc. without flagging an unrelated word
// that merely contains one of these as a substring.
var sessionTerminatingPath = regexp.MustCompile(`(?i)\b(log[-_]?off|log[-_]?out|sign[-_]?out)\b`)

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

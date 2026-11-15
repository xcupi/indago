package discovery

import "testing"

// TestLooksSessionTerminating pins the guard's contract: it must recognize
// clear logout / sign-out / session-destroy shapes in the path, the query
// string and an SPA route fragment, and must not flag unrelated paths that
// merely contain the same letters ("/blog/out", "/catalog/outlet") or query
// values that mention the word without naming an action ("?q=logout").
func TestLooksSessionTerminating(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		// --- path: a segment that is itself the action -------------------
		{"logout path", "http://example.com/logout", true},
		{"logout path with extension", "http://example.com/logout.php", true},
		{"logout path uppercase", "http://example.com/LOGOUT.PHP", true},
		{"logout path trailing slash", "http://example.com/logout/", true},
		{"logout hyphenated", "http://example.com/log-out", true},
		{"logout underscored", "http://example.com/log_out", true},
		{"signout", "http://example.com/signout", true},
		{"signout hyphenated", "http://example.com/auth/sign-out", true},
		{"signout underscored", "http://example.com/auth/sign_out", true},
		{"auth logout", "http://example.com/auth/logout", true},
		{"prefixed segment", "http://example.com/user_logout", true},
		{"suffixed segment", "http://example.com/logout_user.php", true},
		{"embedded between separators", "http://example.com/do_sign_out/now", true},

		// --- path: a session object plus a verb that ends it -------------
		{"session destroy", "http://example.com/session/destroy", true},
		{"session destroy with extension", "http://example.com/session/destroy.php", true},
		{"sessions destroy trailing slash", "http://example.com/sessions/destroy/", true},
		{"php session_destroy", "http://example.com/session_destroy", true},
		{"reverse order", "http://example.com/destroy-session", true},
		{"session end", "http://example.com/session/end", true},
		{"api session terminate", "http://example.com/api/v1/session/terminate", true},
		{"auth token revoke", "http://example.com/api/v1/auth/token/revoke", true},
		{"sessions invalidate", "http://example.com/sessions/invalidate", true},
		{"tokens expire", "http://example.com/api/tokens/expire", true},

		// --- query: the parameter name is the action ---------------------
		{"logout flag", "http://example.com/account?logout=1", true},
		{"logout bare", "http://example.com/account?logout", true},
		{"signout flag", "http://example.com/account?signout=true", true},
		{"session_destroy param", "http://example.com/account?session_destroy=1", true},

		// --- query: an action parameter carries the action ---------------
		{"action logout", "http://example.com/account?action=logout", true},
		{"action signout", "http://example.com/account?action=signout", true},
		{"action sign-out", "http://example.com/account?action=sign-out", true},
		{"action logoff", "http://example.com/account?action=logoff", true},
		{"action log out", "http://example.com/account?action=log+out", true},
		{"action value uppercase", "http://example.com/account?Action=LogOut", true},
		{"action with slash value", "http://example.com/account?action=%2Flogout", true},
		{"action session destroy", "http://example.com/account?action=session.destroy", true},
		{"action session slash destroy", "http://example.com/account?action=session%2Fdestroy", true},
		{"op logout", "http://example.com/account?op=logout", true},
		{"do signout", "http://example.com/account?do=signout", true},
		{"task log-off", "http://example.com/account?task=log-off", true},
		{"clashing next parameter", "http://example.com/account?next=%2Fhome&action=logout", true},
		{"bracketed action name", "http://example.com/settings?params%5Baction%5D=logout", true},

		// --- SPA route fragment ------------------------------------------
		{"spa logout route", "https://example.com/#/logout", true},
		{"spa signout route", "https://example.com/app#/auth/signout", true},
		{"spa session destroy route", "https://example.com/#/session/destroy", true},
		{"spa logout route with query", "https://example.com/#/logout?tab=1", true},
		{"hashbang logout", "https://example.com/#!/logout", true},

		// --- negative controls -------------------------------------------
		{"blog out", "http://example.com/blog/out", false},
		{"catalog outlet", "http://example.com/catalog/outlet", false},
		{"blog outstanding", "http://example.com/blog_outstanding", false},
		{"catalog outside", "http://example.com/catalog/outside", false},
		{"login", "http://example.com/login", false},
		{"login php", "http://example.com/login.php", false},
		{"auth login", "http://example.com/auth/login", false},
		{"bare session", "http://example.com/session", false},
		{"bare auth", "http://example.com/auth", false},
		{"session start", "http://example.com/session/start", false},
		{"session refresh", "http://example.com/session/refresh", false},
		{"sessions new", "http://example.com/sessions/new", false},
		{"session endpoints", "http://example.com/session/endpoints", false},
		{"account", "http://example.com/account", false},
		{"profile", "http://example.com/profile", false},
		{"camelcase servlet", "http://example.com/LogoutServlet", false},
		{"search word", "http://example.com/search?q=logout", false},
		{"search signout", "http://example.com/search?search=signout", false},
		{"next redirect", "http://example.com/login?next=%2Flogout", false},
		{"return url redirect", "http://example.com/login?returnUrl=%2Flogout", false},
		{"action login", "http://example.com/account?action=login", false},
		{"action view", "http://example.com/account?action=view", false},
		{"action session-start", "http://example.com/account?action=session-start", false},
		{"token data", "http://example.com/account?token=abc", false},
		{"session id data", "http://example.com/account?session_id=123", false},
		{"auth token data", "http://example.com/account?auth_token=xyz", false},
		{"root", "http://example.com/", false},
		{"root with port", "http://example.com:8080", false},
		{"plain anchor", "http://example.com/page#section", false},
		{"spa login route", "https://example.com/#/login", false},
		{"spa basket out", "https://example.com/#/basket/out", false},
		{"spa report route", "https://example.com/#report/2024", false},
		{"malformed url", "://bad", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksSessionTerminating(tc.url); got != tc.want {
				t.Errorf("looksSessionTerminating(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

// TestSessionTerminationReason documents the category a skip is logged with:
// an operator reading a debug log can tell a path match from a query action.
func TestSessionTerminationReason(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"http://example.com/logout", "path"},
		{"http://example.com/session/destroy", "path"},
		{"http://example.com/account?action=logout", "query"},
		{"http://example.com/account?logout=1", "query"},
		{"https://example.com/#/logout", "route"},
		{"http://example.com/blog/out", ""},
		{"http://example.com/account?q=logout", ""},
		{"http://example.com/login?next=%2Flogout", ""},
		{"://bad", ""},
	}
	for _, tc := range cases {
		if got := sessionTerminationReason(tc.url); got != tc.want {
			t.Errorf("sessionTerminationReason(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// TestLooksSessionTerminatingIgnoresNonActionQueryValues guards the "not overly
// broad" requirement directly: a page that accepts a redirect target or a
// search term is still a legitimate test surface on an authenticated scan.
func TestLooksSessionTerminatingIgnoresNonActionQueryValues(t *testing.T) {
	for _, u := range []string{
		"http://example.com/search?q=how+to+log+out",
		"http://example.com/login?next=https%3A%2F%2Fexample.com%2Flogout",
		"http://example.com/help?article=signing-out",
		"http://example.com/account?tab=security",
	} {
		if looksSessionTerminating(u) {
			t.Errorf("looksSessionTerminating(%q) = true, want false (data, not an action)", u)
		}
	}
}

// TestLooksSessionTerminatingIsCaseInsensitive makes sure a target cannot slip
// a logout action past the guard by capitalizing it.
func TestLooksSessionTerminatingIsCaseInsensitive(t *testing.T) {
	for _, u := range []string{
		"http://example.com/LOGOUT",
		"http://example.com/Auth/Sign-Out",
		"http://example.com/Session/Destroy",
		"http://example.com/account?ACTION=LOGOUT",
		"http://example.com/account?LOGOUT=1",
		"https://example.com/#/LOGOUT",
	} {
		if !looksSessionTerminating(u) {
			t.Errorf("looksSessionTerminating(%q) = false, want true", u)
		}
	}
}

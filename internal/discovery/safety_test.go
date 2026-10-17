package discovery

import "testing"

func TestLooksSessionTerminating(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://example.com/logout.php", true},
		{"http://example.com/logout", true},
		{"http://example.com/LOGOUT.PHP", true},
		{"http://example.com/auth/sign-out", true},
		{"http://example.com/auth/sign_out", true},
		{"http://example.com/user/log-off", true},
		{"http://example.com/user/log_off", true},
		{"http://example.com/api/logoff", true},
		// Should NOT false-positive on unrelated words/paths.
		{"http://example.com/vulnerabilities/xss_r/", false},
		{"http://example.com/blog/outstanding-bug", false},
		{"http://example.com/catalog/outlet", false},
		{"http://example.com/login.php", false},
		{"http://example.com/", false},
		// Query string content must not trigger it (path-only check).
		{"http://example.com/search?q=logout", false},
	}
	for _, c := range cases {
		if got := looksSessionTerminating(c.url); got != c.want {
			t.Errorf("looksSessionTerminating(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

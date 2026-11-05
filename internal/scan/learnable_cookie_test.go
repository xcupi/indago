package scan

// Which target-issued cookies may be flipped as authorization flags.
//
// The session heuristic exists so the engine never flips its own login cookie.
// It must not swallow an explicit authorization name, though: `auth_level`
// matches "auth" yet is precisely the kind of flag this engine tests.

import "testing"

func TestLearnableFlagCookie(t *testing.T) {
	yes := []string{
		"Admin", "is_staff", "access_level", "auth_level", "role", "user_role",
		"privileged", "moderator", "staff_flag", "god_mode",
	}
	for _, name := range yes {
		if !learnableFlagCookie(name) {
			t.Errorf("learnableFlagCookie(%q) = false, want true", name)
		}
	}
	no := []string{
		"", "   ", "session", "PHPSESSID", "connect.sid", "csrf_token",
		"XSRF-TOKEN", "jwt", "__Host-auth",
	}
	for _, name := range no {
		if learnableFlagCookie(name) {
			t.Errorf("learnableFlagCookie(%q) = true, want false", name)
		}
	}
	// A non-session name that is not an authorization name is eligible here and
	// is filtered later by DeriveFlags' RoleName check, not by this helper.
	for _, name := range []string{"themes", "lang"} {
		if !learnableFlagCookie(name) {
			t.Errorf("learnableFlagCookie(%q) = false: eligibility is decided by RoleName later", name)
		}
	}
}

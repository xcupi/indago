package accesscontrol

// Real-target generalization of the role-flag derivation.
//
// The lab that motivated this slice uses a cookie literally named "Admin"
// whose value is "false". The engine confirmed it because the fallback
// vocabulary already carried {Admin, cookie, true}. A real target is not that
// generous: the flag can be named is_staff, moderator, access_level, and its
// negative literal can be 0, no, off, guest, disabled or false. Two bounded
// generalizations are pinned here:
//
//  1. the probe value follows the OBSERVED literal (false -> true, 0 -> 1,
//     guest -> admin, disabled -> enabled, …), so the engine does not depend on
//     a name-based value guess;
//  2. the name vocabulary covers the authorization names bounty programs
//     actually expose, still closed and bounded (never a wordlist).
//
// Every negative that mattered before must stay negative: an ordinary
// parameter, a session cookie or a non-authorization name must derive nothing.

import (
	"strings"
	"testing"
)

func TestDeriveFlagsFollowsObservedNegativeLiteral(t *testing.T) {
	cases := []struct {
		name   string
		obs    Observed
		want   []string
		absent []string
	}{
		{
			name: "boolean false becomes true",
			obs:  Observed{Name: "Admin", Location: LocationCookie, Value: "false"},
			want: []string{"true"},
		},
		{
			name: "capitalized False becomes True as well",
			obs:  Observed{Name: "Admin", Location: LocationCookie, Value: "False"},
			want: []string{"True", "true"},
		},
		{
			name: "numeric zero becomes one",
			obs:  Observed{Name: "access_level", Location: LocationQuery, Value: "0"},
			want: []string{"1"},
		},
		{
			name: "no becomes yes",
			obs:  Observed{Name: "is_staff", Location: LocationCookie, Value: "no"},
			want: []string{"yes"},
		},
		{
			name: "off becomes on",
			obs:  Observed{Name: "admin_mode", Location: LocationQuery, Value: "off"},
			want: []string{"on"},
		},
		{
			name: "disabled becomes enabled",
			obs:  Observed{Name: "privileged", Location: LocationCookie, Value: "disabled"},
			want: []string{"enabled"},
		},
		{
			name: "low role becomes admin",
			obs:  Observed{Name: "role", Location: LocationCookie, Value: "guest"},
			want: []string{"admin"},
		},
		{
			name: "already-privileged literal adds nothing new",
			obs:  Observed{Name: "Admin", Location: LocationCookie, Value: "true"},
			want: nil,
		},
		{
			name: "unrecognized literal adds nothing",
			obs:  Observed{Name: "Admin", Location: LocationCookie, Value: "1a2b3c"},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveFlags([]Observed{tc.obs})
			values := flagValuesFor(got, tc.obs.Name, tc.obs.Location)
			for _, w := range tc.want {
				if !values[w] {
					t.Errorf("%s=%q: derived values %v, want %q present", tc.obs.Name, tc.obs.Value, keysOf(values), w)
				}
			}
			if tc.want == nil && len(values) > 0 {
				// Nothing should be derived FROM THE OBSERVED VALUE; the
				// bounded vocabulary may still contribute its own flags, so
				// only the observed literal's own counterparts are checked.
				for _, v := range keysOf(values) {
					if v != "true" && v != "1" && v != "admin" && v != "administrator" {
						t.Errorf("%s=%q: unexpected value %q derived from the observed literal", tc.obs.Name, tc.obs.Value, v)
					}
				}
			}
		})
	}
}

func TestRoleNameCoversRealAuthorizationNames(t *testing.T) {
	yes := []string{
		"moderator", "is_moderator", "manager", "is_manager", "owner", "is_owner",
		"support", "agent", "editor", "operator", "supervisor", "approver",
		"reviewer", "internal", "developer", "is_developer", "elevated",
		"god_mode", "impersonate",
	}
	for _, n := range yes {
		if !RoleName(n) {
			t.Errorf("RoleName(%q) = false, want true", n)
		}
	}
	no := []string{
		"session", "csrf", "q", "page", "id", "view", "theme", "lang", "plan",
		"price", "cart", "search", "email", "password",
	}
	for _, n := range no {
		if RoleName(n) {
			t.Errorf("RoleName(%q) = true, want false", n)
		}
	}
}

func TestRoleNameSuffixRulesStayBounded(t *testing.T) {
	yes := []string{"access_flag", "admin_mode", "staff_level", "user_role", "account_role_id"}
	for _, n := range yes {
		if !RoleName(n) {
			t.Errorf("RoleName(%q) = false, want true", n)
		}
	}
	// A suffix must not swallow arbitrary long names that merely end with it.
	if RoleName("this_is_a_very_long_parameter_name_that_ends_in_level") {
		t.Error("a 48-character name must stay outside the vocabulary bound")
	}
}

func TestDeriveFlagsNeverExceedsBudget(t *testing.T) {
	obs := []Observed{
		{Name: "role", Location: LocationQuery, Value: "guest"},
		{Name: "admin", Location: LocationQuery, Value: "false"},
		{Name: "is_admin", Location: LocationQuery, Value: "0"},
		{Name: "isAdmin", Location: LocationCookie, Value: "no"},
		{Name: "Admin", Location: LocationCookie, Value: "false"},
		{Name: "access_level", Location: LocationQuery, Value: "0"},
		{Name: "privileged", Location: LocationCookie, Value: "disabled"},
	}
	got := DeriveFlags(obs)
	if len(got) > MaxFlags {
		t.Fatalf("derived %d flags, budget is %d", len(got), MaxFlags)
	}
	for _, f := range got {
		if strings.TrimSpace(f.Name) == "" || strings.TrimSpace(f.Value) == "" {
			t.Fatalf("derived an incomplete flag: %+v", f)
		}
	}
}

// flagValuesFor returns the set of values derived for one observed name and
// location, so a test can assert the derivation without depending on the order
// the vocabulary happens to add its own flags.
func flagValuesFor(flags []Flag, name string, loc Location) map[string]bool {
	out := map[string]bool{}
	want := strings.ToLower(strings.TrimSpace(name))
	for _, f := range flags {
		if f.Location == loc && strings.ToLower(strings.TrimSpace(f.Name)) == want && f.Source == "discovered" {
			out[f.Value] = true
		}
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

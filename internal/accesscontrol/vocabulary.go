package accesscontrol

// The engine's bounded vocabulary for client-controlled authorization values.
//
// One vocabulary, three uses:
//
//   - case 19 recognises a role/privilege CONTROL on an anonymously fetched
//     page (a <select name="role"> offering "admin" is an administrative
//     capability, not a word);
//   - case 20 proposes the flags to try on a privileged endpoint (query
//     parameter or cookie names);
//   - case 21 proposes the field names to add to a profile update.
//
// It is a fixed list plus a small set of suffixes, NEVER a wordlist: the goal
// is a handful of plausible authorization names, not coverage of every
// parameter an application might have.

import "strings"

// NormalizeName lowercases a name and drops the separators applications use
// interchangeably, so is_admin, isAdmin, is-admin and is.admin all normalize to
// isadmin.
func NormalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch r {
		case '_', '-', '.', ' ', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// roleNames is the closed vocabulary of names that plausibly carry an
// authorization decision in a request parameter, a cookie or a body field.
// Generic names (type, id, view) are deliberately excluded: their false
// positives would spend requests without ever plausibly granting a role.
var roleNames = map[string]bool{
	"admin": true, "isadmin": true, "adminflag": true, "adminmode": true,
	"administrator": true, "isadministrator": true,
	"superuser": true, "issuperuser": true, "root": true, "isroot": true,
	"privileged": true, "isprivileged": true, "elevated": true, "iselevated": true,
	"staff": true, "isstaff": true,
	"role": true, "roleid": true, "roles": true, "userrole": true, "accountrole": true,
	"usertype": true, "accounttype": true,
	"accesslevel": true, "authlevel": true, "access": true,
	"privilege": true, "privileges": true, "permission": true, "permissions": true,
	// Names real applications (and bounty programs) actually expose. All are
	// authorization decisions; none are billing-only (plan, tier, price) or
	// generic identifiers, which would spend probes without plausibly granting
	// a role.
	"moderator": true, "ismoderator": true, "mod": true, "ismod": true,
	"manager": true, "ismanager": true, "owner": true, "isowner": true,
	"support": true, "issupport": true, "agent": true, "isagent": true,
	"editor": true, "iseditor": true, "operator": true, "isoperator": true,
	"supervisor": true, "issupervisor": true, "approver": true, "isapprover": true,
	"reviewer": true, "isreviewer": true, "developer": true, "isdeveloper": true,
	"internal": true, "isinternal": true, "godmode": true, "impersonate": true,
}

// roleSuffixes catch the common qualified spellings (user_role, memberRole,
// account_role_id, access_flag, staff_level, …) without opening the vocabulary
// to arbitrary names. The 28-character bound in RoleName keeps a long ordinary
// parameter that merely ends with one of these from matching.
var roleSuffixes = []string{"role", "roleid", "flag", "mode", "level"}

// RoleName reports whether a parameter, cookie or field name plausibly carries
// a client-controlled authorization decision.
func RoleName(name string) bool {
	n := NormalizeName(name)
	if n == "" || len(n) > 28 {
		return false
	}
	if roleNames[n] {
		return true
	}
	for _, suffix := range roleSuffixes {
		if strings.HasSuffix(n, suffix) && len(n) > len(suffix) {
			return true
		}
	}
	return false
}

// AdminLikeValue reports whether a value names an administrative role or an
// affirmative flag.
func AdminLikeValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "admin", "administrator", "true", "1", "yes", "on", "superuser", "root":
		return true
	default:
		return false
	}
}

// RoleValues returns the bounded, ordered admin-like values to try for a name:
// a role-shaped flag gets admin/administrator, an identifier-shaped one gets
// the conventional elevated id, and a boolean-shaped one gets true/1. At most
// two values are ever returned.
func RoleValues(name string) []string {
	n := NormalizeName(name)
	switch {
	case strings.HasSuffix(n, "roleid") || n == "roleid":
		return []string{"2"}
	case n == "role" || n == "roles" || n == "userrole" || n == "accountrole" ||
		n == "usertype" || n == "accounttype" || n == "accesslevel" || n == "authlevel" ||
		n == "access" || n == "privilege" || n == "privileges" ||
		n == "permission" || n == "permissions" || strings.HasSuffix(n, "role"):
		return []string{"admin", "administrator"}
	default:
		return []string{"true", "1"}
	}
}

// elevatedValue chooses the single value to send for a role FIELD (case 21).
// A role NAME is set to "admin"; an identifier field (roleid/role_id) gets the
// conventional elevated id 2; a boolean flag gets true. Deterministic, one
// value, no guessing loop.
func elevatedValue(name string) (string, ValueKind) {
	n := NormalizeName(name)
	switch {
	case strings.Contains(n, "roleid"):
		return "2", ValueNumber
	case n == "admin" || strings.HasPrefix(n, "is"):
		return "true", ValueBool
	default:
		return "admin", ValueText
	}
}

// IdentityParameter reports whether a body parameter names an identity or
// credential attribute a profile-update request would carry. It is the signal
// that an endpoint is a profile update rather than an arbitrary form.
func IdentityParameter(name string) bool {
	switch NormalizeName(name) {
	case "email", "emailaddress", "mail", "username", "user", "login",
		"password", "passwd", "newpassword", "oldpassword", "currentpassword",
		"passwordconfirmation", "passwordconfirm", "displayname", "fullname",
		"firstname", "lastname":
		return true
	}
	return false
}

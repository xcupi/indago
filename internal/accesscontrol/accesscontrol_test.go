package accesscontrol

// Tests for the pure access-control analysis and decision layer. They are the
// honesty controls for the engine's central claim: an anonymous 2xx response
// is Confirmed ONLY when it actually exposes a privileged admin action, never
// because the path merely answered 200 or looks admin-like.

import (
	"strings"
	"testing"
)

const adminPanelHTML = `<!doctype html><html><head><title>Admin panel</title></head><body>
<h1>Admin panel</h1>
<h2>User list</h2>
<table>
<tr><th>Username</th><th>Actions</th></tr>
<tr><td>wiener</td><td><a href="/admin/delete?username=wiener">Delete</a></td></tr>
<tr><td>carlos</td><td><a href="/admin/delete?username=carlos">Delete</a></td></tr>
</table>
</body></html>`

func TestAnalyzeDetectsDeleteUserAndUserList(t *testing.T) {
	obs := Analyze(Snapshot{Status: 200, Body: []byte(adminPanelHTML)})
	if obs.LoginPage {
		t.Fatal("admin panel must not be classified as a login page")
	}
	var deleteUser, userList bool
	for _, a := range obs.Actions {
		switch a.Kind {
		case ActionDeleteUser:
			deleteUser = true
			if a.Target == "" {
				t.Fatalf("delete-user action must carry its target: %+v", a)
			}
		case ActionUserList:
			userList = true
		}
	}
	if !deleteUser {
		t.Fatalf("delete-user action not detected; actions=%+v", obs.Actions)
	}
	if !userList {
		t.Fatalf("user-list action not detected; actions=%+v", obs.Actions)
	}
	if !obs.Privileged() {
		t.Fatal("a page with delete-user and user-list actions is privileged")
	}
}

func TestAnalyzeDetectsFormDeleteUser(t *testing.T) {
	body := `<h1>Users</h1>
<form action="/admin/users/delete" method="post">
  <input type="hidden" name="username" value="carlos">
  <button type="submit">Delete user</button>
</form>`
	obs := Analyze(Snapshot{Status: 200, Body: []byte(body)})
	if !obs.Has(ActionDeleteUser) {
		t.Fatalf("form-based delete-user action not detected; actions=%+v", obs.Actions)
	}
}

func TestAnalyzeDetectsAdminUsersCollectionLink(t *testing.T) {
	body := `<h1>Admin panel</h1><nav><a href="/admin/users">Manage users</a></nav>`
	obs := Analyze(Snapshot{Status: 200, Body: []byte(body)})
	if !obs.Has(ActionUserList) {
		t.Fatalf("admin users-collection link not detected; actions=%+v", obs.Actions)
	}
}

func TestAnalyzeOrdinaryPageHasNoPrivilegedAction(t *testing.T) {
	// A public shop page: a nav "Users" link, a product delete link and a
	// user table without any admin action must all stay non-privileged.
	body := `<html><body>
<nav><a href="/users">Users</a> <a href="/products">Products</a> <a href="/login">Login</a></nav>
<h2>Users</h2>
<table>
<tr><td>alice</td><td>Member since 2020</td></tr>
<tr><td>bob</td><td>Member since 2021</td></tr>
</table>
<table>
<tr><td>Widget</td><td><a href="/products/delete?id=3">Delete</a></td></tr>
</table>
</body></html>`
	obs := Analyze(Snapshot{Status: 200, Body: []byte(body)})
	if obs.Privileged() {
		t.Fatalf("ordinary page must not be privileged; actions=%+v", obs.Actions)
	}
}

func TestAnalyzeLoginPage(t *testing.T) {
	body := `<html><body><h1>Sign in</h1>
<form action="/login" method="post"><input name="username"><input type="password" name="password"><button>Log in</button></form>
</body></html>`
	obs := Analyze(Snapshot{Status: 200, Body: []byte(body)})
	if !obs.LoginPage {
		t.Fatal("password form must be recognised as a login page")
	}
	if obs.Privileged() {
		t.Fatalf("a login page exposes no privileged action; actions=%+v", obs.Actions)
	}
}

func TestAnalyzeDeterministic(t *testing.T) {
	a := Analyze(Snapshot{Status: 200, Body: []byte(adminPanelHTML)})
	b := Analyze(Snapshot{Status: 200, Body: []byte(adminPanelHTML)})
	if len(a.Actions) != len(b.Actions) {
		t.Fatalf("action count is not deterministic: %d vs %d", len(a.Actions), len(b.Actions))
	}
	for i := range a.Actions {
		if a.Actions[i] != b.Actions[i] {
			t.Fatalf("action %d is not deterministic: %+v vs %+v", i, a.Actions[i], b.Actions[i])
		}
	}
}

func TestAdminLikePath(t *testing.T) {
	yes := []string{
		"http://h/admin", "http://h/administrator", "http://h/admin/", "http://h/wp-admin/",
		"http://h/admin.php", "http://h/manage/users", "http://h/dashboard", "http://h/backoffice",
	}
	for _, u := range yes {
		if !AdminLikePath(u) {
			t.Errorf("AdminLikePath(%q) = false, want true", u)
		}
	}
	no := []string{"http://h/", "http://h/products", "http://h/users", "http://h/login", "http://h/search?q=admin"}
	for _, u := range no {
		if AdminLikePath(u) {
			t.Errorf("AdminLikePath(%q) = true, want false", u)
		}
	}
}

func TestDecideConfirmsAnonymousPrivilegedExposure(t *testing.T) {
	d := Decide(Snapshot{Status: 200, Body: []byte(adminPanelHTML)}, nil)
	if d.Outcome != OutcomeConfirmed {
		t.Fatalf("outcome = %q (%s), want confirmed", d.Outcome, d.Reason)
	}
	if len(d.Privileged) == 0 {
		t.Fatal("confirmed decision must carry the actions it proved")
	}
	if !strings.Contains(d.Reason, "delete_user") && !strings.Contains(d.Reason, "user_list") {
		t.Fatalf("reason must name the actions it found: %q", d.Reason)
	}
}

func TestDecideRejects200WithoutPrivilegedAction(t *testing.T) {
	body := `<html><body><h1>Admin panel</h1><p>Nothing to see here.</p></body></html>`
	d := Decide(Snapshot{Status: 200, Body: []byte(body)}, nil)
	if d.Outcome != OutcomeRejected {
		t.Fatalf("outcome = %q (%s), want rejected", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "no privileged admin action") {
		t.Fatalf("reason should say the page exposes no privileged action: %q", d.Reason)
	}
}

func TestDecideRejectsAuthRequired(t *testing.T) {
	for _, tc := range []struct {
		name string
		anon Snapshot
	}{
		{"401", Snapshot{Status: 401, Body: []byte("unauthorized")}},
		{"403", Snapshot{Status: 403, Body: []byte("forbidden")}},
		{"302 to login", Snapshot{Status: 200, FinalURL: "http://h/login", Body: []byte(`<form><input type="password"></form>`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.anon, nil)
			if d.Outcome != OutcomeRejected {
				t.Fatalf("outcome = %q (%s), want rejected", d.Outcome, d.Reason)
			}
		})
	}
}

func TestDecideComparesAuthenticatedNonAdmin(t *testing.T) {
	anon := Snapshot{Status: 200, Body: []byte(adminPanelHTML)}
	denied := Snapshot{Status: 403, Body: []byte("forbidden")}
	d := Decide(anon, &denied)
	if d.Outcome != OutcomeConfirmed {
		t.Fatalf("anon privileged + non-admin denied: outcome = %q (%s), want confirmed", d.Outcome, d.Reason)
	}
	if !d.Compared {
		t.Fatal("decision must record that the non-admin comparison happened")
	}
	if !strings.Contains(d.Reason, "denied") {
		t.Fatalf("reason should record the non-admin denial: %q", d.Reason)
	}

	// A non-admin session that reaches the same path but does not see the
	// actions is also a confirmed differential.
	noActions := Snapshot{Status: 200, Body: []byte(`<html><body><h1>Admin panel</h1><p>No actions for you.</p></body></html>`)}
	d = Decide(anon, &noActions)
	if d.Outcome != OutcomeConfirmed {
		t.Fatalf("anon privileged + non-admin without actions: outcome = %q (%s), want confirmed", d.Outcome, d.Reason)
	}

	// When the non-admin sees the exact same privileged actions, the surface
	// applies no role check at all. Anonymous access is still unauthorized,
	// so the finding is Confirmed, but the reason must say what was observed
	// instead of claiming a role boundary that does not exist.
	same := Snapshot{Status: 200, Body: []byte(adminPanelHTML)}
	d = Decide(anon, &same)
	if d.Outcome != OutcomeConfirmed {
		t.Fatalf("anon and non-admin both privileged: outcome = %q (%s), want confirmed", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "no role check") {
		t.Fatalf("reason should state that the non-admin sees the same actions: %q", d.Reason)
	}
}

func TestDecideNonAdminDenialNeverMakesAnonymousSafe(t *testing.T) {
	// The negative control that matters: the anonymous response itself must
	// be privileged. A strongly privileged non-admin response cannot turn an
	// anonymous page with no actions into a finding.
	anon := Snapshot{Status: 200, Body: []byte(`<html><body><h1>Welcome</h1></body></html>`)}
	admin := Snapshot{Status: 200, Body: []byte(adminPanelHTML)}
	d := Decide(anon, &admin)
	if d.Outcome != OutcomeRejected {
		t.Fatalf("outcome = %q (%s), want rejected", d.Outcome, d.Reason)
	}
}

func TestDecideTruncatedBodyIsInconclusive(t *testing.T) {
	body := `<html><body><h1>Admin panel</h1>` // truncated before any action
	d := Decide(Snapshot{Status: 200, Truncated: true, Body: []byte(body)}, nil)
	if d.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive", d.Outcome, d.Reason)
	}
}

func TestDecideNoResponseIsInconclusive(t *testing.T) {
	d := Decide(Snapshot{}, nil)
	if d.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome = %q (%s), want inconclusive", d.Outcome, d.Reason)
	}
}

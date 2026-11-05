// Package accesscontrol is Indago's PURE decision layer for function- and
// role-level access control (the "unprotected admin functionality" class).
//
// It answers one question with no network, browser or LLM involvement: given
// the response an ANONYMOUS request received, does that page actually expose a
// privileged administrative action? A 2xx status alone is never enough — the
// body must contain a recognisable privileged action (a user list or a
// delete-user control). The optional non-admin snapshot is the comparison an
// authenticated low-privileged session produced for the same path; it is
// recorded as evidence, and it can never turn an anonymous page with no
// privileged action into a finding.
//
// Everything here is deterministic: the same bytes always produce the same
// actions, in the same order.
package accesscontrol

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// Outcome is the decision for one candidate path.
type Outcome string

const (
	// OutcomeConfirmed means the anonymous response exposes a privileged
	// admin action. It does NOT mean any later request verified it: the
	// engine only ever sends GET requests.
	OutcomeConfirmed Outcome = "confirmed"
	// OutcomeRejected means the path is not anonymously reachable, requires
	// authentication, or answered without any privileged action.
	OutcomeRejected Outcome = "rejected"
	// OutcomeInconclusive means the response could not be assessed (no
	// response, truncated body).
	OutcomeInconclusive Outcome = "inconclusive"
)

// ActionKind classifies a privileged administrative action found on a page.
//
// The four kinds are the ONE vocabulary every case of this engine uses:
// case 19 reports them from an anonymous page, cases 20 and 21 require at
// least one of them from the privileged surface that became reachable. A page
// whose text merely says "admin" produces none of them.
type ActionKind string

const (
	// ActionDeleteUser is a control that deletes/removes/deactivates a user
	// or account.
	ActionDeleteUser ActionKind = "delete_user"
	// ActionUserList is a listing of user accounts (or a link to one) that a
	// non-administrator is not meant to see.
	ActionUserList ActionKind = "user_list"
	// ActionPrivilegedAction is a link/form that targets a DEEPER operation
	// under a privileged path than the page itself (…/admin/delete,
	// …/admin/users/42/role). A link back to the privileged landing path is
	// navigation, not a capability.
	ActionPrivilegedAction ActionKind = "privileged_action"
	// ActionRoleControl is a form control that lets the caller set a role or
	// privilege to an admin-like value, or a role selector offering one.
	ActionRoleControl ActionKind = "role_control"
)

// Action is one privileged action found in a response body.
type Action struct {
	Kind ActionKind `json:"kind"`
	// Evidence is a short, normalised description of the element that
	// carried the action (text and/or target), capped for storage.
	Evidence string `json:"evidence"`
	// Target is the href/action the element points at, when it has one.
	Target string `json:"target,omitempty"`
}

// Snapshot is one response to analyse.
type Snapshot struct {
	Status    int
	FinalURL  string
	Truncated bool
	Body      []byte
}

// Observation is what one response body was found to contain.
type Observation struct {
	LoginPage bool
	Actions   []Action
}

// Privileged reports whether any privileged action was observed.
func (o Observation) Privileged() bool { return len(o.Actions) > 0 }

// Has reports whether an action of kind k was observed.
func (o Observation) Has(k ActionKind) bool {
	for _, a := range o.Actions {
		if a.Kind == k {
			return true
		}
	}
	return false
}

// Decision is the engine's verdict for one candidate path.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason"`
	// Privileged are the actions found in the anonymous response.
	Privileged []Action `json:"privileged_actions,omitempty"`
	// Compared is true when a non-admin snapshot was supplied.
	Compared bool `json:"compared,omitempty"`
	// NonAdminStatus / NonAdminActions record what the comparison saw.
	NonAdminStatus  int      `json:"non_admin_status,omitempty"`
	NonAdminActions []Action `json:"non_admin_actions,omitempty"`
}

// Analyze parses one HTML response and reports the privileged actions it
// exposes. A password form marks the response as a login page: reaching a
// login page is not access to the page that was requested.
func Analyze(s Snapshot) Observation {
	doc, err := html.Parse(bytes.NewReader(s.Body))
	if err != nil {
		return Observation{}
	}

	var (
		obs             Observation
		actions         []Action
		headings        []string
		rows            []string // first identity-looking cell of each table row
		rowsWithDelete  int
		adminUsersLinks int
	)

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			switch tag {
			case "input":
				if strings.EqualFold(attr(n, "type"), "password") {
					obs.LoginPage = true
				}
			case "h1", "h2", "h3", "h4", "h5", "h6":
				if t := nodeText(n, 200); t != "" {
					headings = append(headings, t)
				}
			case "tr":
				if cell := identityCell(n); cell != "" {
					rows = append(rows, cell)
				}
				if hasDeleteAction(n) {
					rowsWithDelete++
				}
			case "li":
				if hasDeleteAction(n) {
					rowsWithDelete++
				}
			}
			if isActionElement(tag) {
				if a, ok := classify(n, tag); ok {
					actions = append(actions, a)
					if a.Kind == ActionUserList {
						adminUsersLinks++
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	if adminUsersLinks > 0 || rowsWithDelete >= 2 {
		actions = append(actions, Action{Kind: ActionUserList,
			Evidence: fmt.Sprintf("page lists user accounts with %d row action(s)", maxInt(rowsWithDelete, adminUsersLinks))})
	} else if hasExplicitListHeading(headings) && len(distinct(rows)) >= 2 {
		actions = append(actions, Action{Kind: ActionUserList,
			Evidence: fmt.Sprintf("user listing with %d accounts", len(distinct(rows)))})
	}

	obs.Actions = dedupeAndSort(actions)
	return obs
}

// Decide applies the verdict rules. nonAdmin is nil when the scan has no
// authenticated session to compare with.
//
// A page that merely answered 200 with no privileged action is Rejected. A
// path that required authentication (401/403, or a login form) is Rejected.
// Only an anonymous response that actually exposes a privileged admin action
// can be Confirmed.
func Decide(anon Snapshot, nonAdmin *Snapshot) Decision {
	if anon.Status == 0 {
		return Decision{Outcome: OutcomeInconclusive, Reason: "no anonymous response was received"}
	}
	obs := Analyze(anon)
	d := Decision{Privileged: obs.Actions}

	if anon.Status < 200 || anon.Status >= 300 {
		d.Outcome = OutcomeRejected
		d.Reason = fmt.Sprintf("anonymous request returned HTTP %d; the path is not anonymously reachable", anon.Status)
		return d
	}
	if obs.LoginPage {
		d.Outcome = OutcomeRejected
		d.Reason = fmt.Sprintf("anonymous request returned HTTP %d but rendered a login form; the path requires authentication", anon.Status)
		return d
	}
	if len(obs.Actions) == 0 {
		if anon.Truncated {
			d.Outcome = OutcomeInconclusive
			d.Reason = fmt.Sprintf("anonymous request returned HTTP %d but its body was truncated before the privileged-action scan could complete", anon.Status)
			return d
		}
		d.Outcome = OutcomeRejected
		d.Reason = fmt.Sprintf("anonymous request returned HTTP %d but the page exposes no privileged admin action", anon.Status)
		return d
	}

	d.Outcome = OutcomeConfirmed
	base := fmt.Sprintf("anonymous request returned HTTP %d and exposes privileged admin action(s): %s",
		anon.Status, actionNames(obs.Actions))

	if nonAdmin == nil {
		d.Reason = base + "; no authenticated non-admin session was configured for a comparison"
		return d
	}
	d.Compared = true
	d.NonAdminStatus = nonAdmin.Status
	nonObs := Analyze(*nonAdmin)
	d.NonAdminActions = nonObs.Actions

	switch {
	case nonAdmin.Status == 0:
		d.Reason = base + "; the authenticated non-admin comparison request failed, so only the anonymous exposure was established"
	case nonAdmin.Status == 401 || nonAdmin.Status == 403:
		d.Reason = base + fmt.Sprintf("; the authenticated non-admin request was denied (HTTP %d)", nonAdmin.Status)
	case nonObs.LoginPage:
		d.Reason = base + "; the authenticated non-admin request reached a login page"
	case len(nonObs.Actions) == 0:
		d.Reason = base + "; the authenticated non-admin response does not expose them"
	default:
		d.Reason = base + "; the authenticated non-admin response exposes the same actions, so the surface applies no role check at all"
	}
	return d
}

// ---------------------------------------------------------------------------
// path classification
// ---------------------------------------------------------------------------

// adminKeywords identify a path segment that is administrative. Matching is a
// substring test on the lower-cased segment, so /administrator, /wp-admin,
// /admin.php and /admin-8f3a2b all qualify. The list is deliberately tiny:
// there is no wordlist and no guessing, only a fixed vocabulary.
var adminKeywords = []string{"admin", "manage", "dashboard", "console", "backoffice", "backend", "cpanel", "panel"}

// AdminLikePath reports whether a URL's path looks administrative. It is used
// to bound which discovered paths the pass is willing to probe; the verdict
// itself still depends on the response content.
func AdminLikePath(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Path == "" {
		return false
	}
	return adminPathLike(u.Path)
}

// adminPathLike is the path-only form of AdminLikePath, shared with the
// disclosure layer (a script literal is a path, not a URL).
func adminPathLike(path string) bool {
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		for _, kw := range adminKeywords {
			if strings.Contains(seg, kw) {
				return true
			}
		}
	}
	return false
}

// isActionElement reports whether an element can carry a user-visible action.
func isActionElement(tag string) bool {
	switch tag {
	case "a", "area", "button", "input", "form", "select":
		return true
	}
	return false
}

// classify inspects one action element and returns a privileged action when
// its text/target describes one.
func classify(n *html.Node, tag string) (Action, bool) {
	target := attr(n, "href")
	if target == "" {
		target = attr(n, "action")
	}
	label := strings.ToLower(elementLabel(n, tag))
	hasDelete := hasDeleteVerb(label)
	hasUserNoun := hasUserNoun(label)
	pathDelete := hasDeleteSegment(target)
	pathUsers := pathHasUserCollection(target)
	userParam := hasUserQueryParam(target)

	if tag == "a" || tag == "area" {
		if adminUsersCollection(target) {
			return Action{Kind: ActionUserList, Evidence: clip("link to "+target, 160), Target: target}, true
		}
	}
	if hasDelete && (hasUserNoun || pathUsers || userParam) {
		return Action{Kind: ActionDeleteUser, Evidence: clip(elementText(n, tag, target), 160), Target: target}, true
	}
	if pathDelete && userParam && (AdminLikePath(target) || hasUserNoun) {
		return Action{Kind: ActionDeleteUser, Evidence: clip(elementText(n, tag, target), 160), Target: target}, true
	}
	if pathDelete && pathUsers && AdminLikePath(target) {
		return Action{Kind: ActionDeleteUser, Evidence: clip(elementText(n, tag, target), 160), Target: target}, true
	}
	// A role/privilege control the caller can set is itself an administrative
	// capability: a page offering <select name="role"><option>admin</option>
	// is handing out the role, not merely mentioning it. A control offering
	// only "user" is a sign-up field, not a capability.
	if c, ok := roleControl(n, tag); ok {
		return c, true
	}
	// Any other link/form into a DEEPER operation under a privileged path is
	// an actionable administrative surface. The privileged landing path itself
	// is navigation, not a capability.
	if ok := deeperPrivilegedTarget(target); ok {
		return Action{Kind: ActionPrivilegedAction, Evidence: clip(elementText(n, tag, target), 160), Target: target}, true
	}
	return Action{}, false
}

// roleControl recognises a form control that lets the caller set a role or
// privilege to an admin-like value. It is shared by all cases: case 19 needs
// it to see such a control on an anonymous page, and cases 20/21 need it to
// recognise the privileged surface's role-change affordance.
func roleControl(n *html.Node, tag string) (Action, bool) {
	switch tag {
	case "input", "button", "select", "textarea":
	default:
		return Action{}, false
	}
	name := attr(n, "name")
	if !RoleName(name) {
		return Action{}, false
	}
	switch tag {
	case "select":
		var offered []string
		var walk func(*html.Node)
		walk = func(x *html.Node) {
			if x.Type == html.ElementNode && strings.EqualFold(x.Data, "option") {
				v := strings.TrimSpace(attr(x, "value"))
				if v == "" {
					v = strings.TrimSpace(nodeText(x, 40))
				}
				if AdminLikeValue(v) {
					offered = append(offered, v)
				}
			}
			for c := x.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(n)
		if len(offered) == 0 {
			return Action{}, false
		}
		return Action{Kind: ActionRoleControl,
			Evidence: clip(fmt.Sprintf("role select %q offers %q", name, offered[0]), 160), Target: name}, true
	case "input":
		switch strings.ToLower(attr(n, "type")) {
		case "checkbox", "radio":
			return Action{Kind: ActionRoleControl,
				Evidence: clip(fmt.Sprintf("%s control %q", tag, name), 160), Target: name}, true
		}
		fallthrough
	default:
		if v := attr(n, "value"); AdminLikeValue(v) {
			return Action{Kind: ActionRoleControl,
				Evidence: clip(fmt.Sprintf("%s %q=%q", tag, name, v), 160), Target: name}, true
		}
	}
	return Action{}, false
}

// nonCapabilityOps are route words that are navigation or session
// management, never an administrative operation. A link to /admin/logout is
// not evidence that /admin hands out administrative capability.
var nonCapabilityOps = map[string]bool{
	"logout": true, "log-out": true, "signout": true, "sign-out": true,
	"login": true, "log-in": true, "signin": true, "sign-in": true,
	"index": true, "home": true, "static": true, "assets": true,
}

// deeperPrivilegedTarget reports whether raw points at an operation DEEPER
// than a privileged area's landing path (…/admin/delete, …/users/42/role).
// The landing path itself is where the caller already is, so it is not a
// capability.
func deeperPrivilegedTarget(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segs {
		if !adminPathLike(seg) {
			continue
		}
		if i == len(segs)-1 {
			continue // the privileged landing path itself
		}
		op := strings.ToLower(segs[i+1])
		if nonCapabilityOps[op] || assetPath(u.Path) {
			return false
		}
		return true
	}
	return false
}

// elementLabel is the lower-cased text and attributes that describe an
// element's action. For a form it includes its descendant input names/values
// so a delete form whose only user noun lives in <input name="username"> is
// still recognised.
func elementLabel(n *html.Node, tag string) string {
	var b strings.Builder
	b.WriteString(nodeText(n, 300))
	for _, key := range []string{"href", "action", "name", "value", "id", "title", "aria-label", "alt"} {
		if v := attr(n, key); v != "" {
			b.WriteByte(' ')
			b.WriteString(v)
		}
	}
	if tag == "form" {
		var walk func(*html.Node)
		walk = func(x *html.Node) {
			if x.Type == html.ElementNode && strings.EqualFold(x.Data, "input") {
				for _, key := range []string{"name", "value"} {
					if v := attr(x, key); v != "" {
						b.WriteByte(' ')
						b.WriteString(v)
					}
				}
			}
			for c := x.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(n)
	}
	return b.String()
}

// elementText is a human-readable identifier for the action, preferring the
// element's own text and falling back to its target.
func elementText(n *html.Node, tag, target string) string {
	if tag == "form" {
		if target != "" {
			return "form " + target
		}
		return "form"
	}
	if t := nodeText(n, 160); t != "" {
		if target != "" {
			return t + " -> " + target
		}
		return t
	}
	if v := attr(n, "value"); v != "" {
		if target != "" {
			return v + " -> " + target
		}
		return v
	}
	if target != "" {
		return target
	}
	return tag
}

// hasDeleteVerb reports whether s contains a deletion verb.
func hasDeleteVerb(s string) bool {
	for _, v := range []string{"delete", "remove", "deactivate", "disable", "ban", "revoke", "terminate", "purge"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

// hasUserNoun reports whether s contains a word that makes the action's
// object a user/account rather than an ordinary resource.
func hasUserNoun(s string) bool {
	for _, w := range []string{"user", "account", "member", "customer", "staff", "employee", "subscriber"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// hasDeleteSegment reports whether a URL path has a deletion verb segment
// (e.g. /admin/delete, /admin/deleteUser, /users/42/remove).
func hasDeleteSegment(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(u.Path), "/") {
		for _, v := range []string{"delete", "remove", "deactivate", "disable", "ban", "revoke", "terminate", "purge"} {
			if seg == v || strings.HasPrefix(seg, v) || strings.HasSuffix(seg, v) {
				return true
			}
		}
	}
	return false
}

// pathHasUserCollection reports whether a URL path addresses a users/accounts
// collection (e.g. /admin/users, /admin/members).
func pathHasUserCollection(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(strings.ToLower(u.Path), "/") {
		switch seg {
		case "users", "user", "members", "member", "accounts", "account", "staff", "employees", "customers", "subscribers":
			return true
		}
	}
	return false
}

// hasUserQueryParam reports whether a URL carries a parameter that selects a
// user/account. A bare "id" is only accepted on an administrative path, so an
// ordinary /products/delete?id=... is never mistaken for a user deletion.
func hasUserQueryParam(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, key := range queryKeys(u.RawQuery) {
		switch strings.ToLower(key) {
		case "username", "user", "userid", "user_id", "account", "accountid", "account_id",
			"member", "memberid", "member_id", "customer", "customerid", "customer_id",
			"staff", "employee", "email":
			return true
		case "id":
			if AdminLikePath(raw) {
				return true
			}
		}
	}
	return false
}

// adminUsersCollection reports whether a URL is an administrative users/
// accounts collection (the canonical "manage users" link).
func adminUsersCollection(raw string) bool {
	return AdminLikePath(raw) && pathHasUserCollection(raw)
}

// queryKeys parses a raw query string without decoding errors aborting the
// whole analysis.
func queryKeys(rawQuery string) []string {
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Fall back to a split so one malformed pair does not hide the rest.
		var out []string
		for _, pair := range strings.Split(rawQuery, "&") {
			if i := strings.IndexByte(pair, '='); i > 0 {
				out = append(out, pair[:i])
			}
		}
		return out
	}
	out := make([]string, 0, len(vals))
	for k := range vals {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hasExplicitListHeading reports whether a heading names a user listing. A
// bare "Users" heading is deliberately not enough: navigation on an ordinary
// page uses that word too, and only an explicit listing phrase (or an actual
// table of actions) justifies the user_list action.
func hasExplicitListHeading(headings []string) bool {
	for _, h := range headings {
		h = strings.ToLower(h)
		for _, p := range []string{"user list", "users list", "user management", "manage users",
			"all users", "registered users", "member list", "members list", "account list",
			"user accounts", "user administration", "manage members", "manage accounts"} {
			if strings.Contains(h, p) {
				return true
			}
		}
	}
	return false
}

// hasDeleteAction reports whether n's subtree contains a delete-user action.
func hasDeleteAction(n *html.Node) bool {
	if n.Type == html.ElementNode {
		tag := strings.ToLower(n.Data)
		if isActionElement(tag) {
			if a, ok := classify(n, tag); ok && a.Kind == ActionDeleteUser {
				return true
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if hasDeleteAction(c) {
			return true
		}
	}
	return false
}

// identityCell returns the first identity-looking cell of a table row.
func identityCell(tr *html.Node) string {
	for c := tr.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || !strings.EqualFold(c.Data, "td") {
			continue
		}
		txt := strings.TrimSpace(nodeText(c, 80))
		if isIdentityToken(txt) {
			return strings.ToLower(txt)
		}
	}
	return ""
}

// isIdentityToken reports whether a cell looks like a username/account name.
func isIdentityToken(s string) bool {
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	if strings.Trim(s, "0123456789") == "" {
		return false // a pure number is an id, not a username
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@':
		default:
			return false
		}
	}
	switch strings.ToLower(s) {
	case "id", "name", "username", "email", "role", "actions", "edit", "delete", "user", "users", "member", "account":
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// nodeText returns the normalised text of a subtree, skipping script/style
// content, capped at limit bytes.
func nodeText(n *html.Node, limit int) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if b.Len() >= limit {
			return
		}
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
			b.WriteByte(' ')
			return
		}
		if x.Type == html.ElementNode {
			switch strings.ToLower(x.Data) {
			case "script", "style", "noscript", "template":
				return
			}
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return clip(strings.Join(strings.Fields(b.String()), " "), limit)
}

func clip(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	return strings.TrimSpace(s[:limit])
}

func distinct(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func dedupeAndSort(in []Action) []Action {
	seen := make(map[string]struct{}, len(in))
	var out []Action
	for _, a := range in {
		if a.Kind == "" {
			continue
		}
		key := string(a.Kind) + "\x00" + a.Target + "\x00" + a.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Evidence != out[j].Evidence {
			return out[i].Evidence < out[j].Evidence
		}
		return out[i].Target < out[j].Target
	})
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func actionNames(actions []Action) string {
	seen := make(map[ActionKind]struct{}, len(actions))
	var out []string
	for _, a := range actions {
		if _, ok := seen[a.Kind]; ok {
			continue
		}
		seen[a.Kind] = struct{}{}
		out = append(out, string(a.Kind))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

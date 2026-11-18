package discovery

// Conservative guard against following GET links that change data.
//
// A GET is not a promise of read-only behaviour. Plenty of applications
// expose state changes as ordinary links — /delete?id=1, /users/7/update,
// ?action=delete — and the crawler follows every in-scope link it finds. The
// executor's write-like guard (isWriteLikeEndpoint) only decides what to TEST
// after discovery has already registered the endpoint, and
// SkipWriteEndpoints is off by default, so a crawl could otherwise send a
// destructive GET before any test-level protection applies.
//
// Discovery therefore refuses, by default and on every scan, to fetch — or to
// register as a read target — a URL whose own path, query or SPA route names a
// clearly destructive/write action. This is separate from the
// session-termination guard (logout_guard.go), which stays scoped to
// authenticated scans because only those have a session to protect.
//
// What this is NOT:
//   - It is not a claim that every GET is safe. An endpoint with a neutral
//     name that mutates on GET (/api/items/42), a link that redirects to a
//     destructive action, and a spelling of a verb this list does not know stay
//     invisible to it. It is a name heuristic, not a security control.
//   - It only guards methods discovery fetches without a body
//     (GET/HEAD/OPTIONS). A POST form target is still registered: discovery
//     never submits it, and the executor's explicit state-changing opt-ins
//     remain the gate for sending it.
//   - An operator-supplied seed is explicit intent and is never skipped.
//
// False positives are accepted, not hidden: /orders/42/update is often a
// read-only form page, and ?delete=0 may only toggle a UI flag in a status
// filter. Such URLs are skipped, which can cost coverage of one page; one
// skipped read is cheaper than one destructive request. To keep the list from
// swallowing ordinary pages, ambiguous nouns are deliberately excluded from
// the PATH vocabulary — /store (a shop), /register, /create and /users/1/edit
// are form pages, not actions, and only match when they are the VALUE of an
// explicit action parameter (?action=store), where the URL itself says it is
// an action.

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/indago/indago/internal/domain"
)

// mutatingPathVerbs name a destructive/write action when they appear as a
// whole path word or query-parameter word. Word-bounded ("/deleted-items" and
// "/updates" do not match), with a CamelCase allowance for suffixes such as
// "deleteUser" or "updateProfile".
var mutatingPathVerbs = map[string]struct{}{
	"delete": {}, "remove": {}, "destroy": {}, "drop": {},
	"purge": {}, "erase": {}, "truncate": {}, "wipe": {},
	"update": {}, "modify": {},
	"revoke": {}, "unsubscribe": {}, "deactivate": {},
}

// mutatingActionVerbs are the values that mark a write when carried by an
// action parameter (?action=…, ?op=…, ?do=…). Wider than the path list because
// the parameter already says "this URL is an action", so nouns that would be
// ambiguous in a path are unambiguous here — "store" is the Laravel create
// action, "create"/"register" are writes.
var mutatingActionVerbs = map[string]struct{}{
	"delete": {}, "remove": {}, "destroy": {}, "drop": {},
	"purge": {}, "erase": {}, "truncate": {}, "wipe": {},
	"update": {}, "modify": {}, "edit": {},
	"create": {}, "insert": {}, "store": {}, "save": {}, "add": {},
	"submit": {}, "upload": {}, "write": {},
	"approve": {}, "reject": {}, "publish": {}, "archive": {}, "restore": {},
	"reset": {}, "revoke": {}, "cancel": {}, "unsubscribe": {},
	"deactivate": {}, "activate": {}, "toggle": {}, "switch": {},
	"enable": {}, "disable": {}, "enforce": {},
	"transfer": {}, "checkout": {},
	"purchase": {}, "register": {}, "signup": {},
}

// looksDataMutating reports whether rawURL names a destructive or write
// action in its own path, query or SPA route fragment.
func looksDataMutating(rawURL string) bool {
	return dataMutationReason(rawURL) != ""
}

// dataMutationReason classifies why rawURL is guarded ("path", "query",
// "route") so a skip can be logged with its cause, and returns "" when the URL
// is not a data-mutating URL. A malformed URL reports "", because failing
// closed on unparseable input is the scope check's job, not this heuristic's.
func dataMutationReason(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if pathNamesMutation(u.Path) {
		return "path"
	}
	if queryNamesMutation(u.Query()) {
		return "query"
	}
	if routeNamesMutation(u.Fragment) {
		return "route"
	}
	return ""
}

// pathNamesMutation reports whether a URL path contains a mutating action
// word: /delete, /users/42/delete, /delete.php, /api/deleteUser.
func pathNamesMutation(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			continue
		}
		if anyWordIn(splitWords(seg), mutatingPathVerbs) {
			return true
		}
		if startsWithCamelVerb(seg, mutatingPathVerbs) {
			return true
		}
	}
	return false
}

// queryNamesMutation reports whether the query string carries a mutating
// action, either as a parameter name itself ("?delete=1", "?delete_id=7") or
// as the value of an action parameter ("?action=delete", "?op=update").
// A value that merely holds the word as data ("?q=delete", "?next=/delete")
// is not an action and is left alone.
func queryNamesMutation(q url.Values) bool {
	for name, values := range q {
		rawName := strings.TrimSpace(name)
		if rawName == "" {
			continue
		}
		words := splitWords(rawName)
		if anyWordIn(words, mutatingPathVerbs) || startsWithCamelVerb(rawName, mutatingPathVerbs) {
			return true
		}
		if !hasActionWord(words) {
			continue
		}
		for _, v := range values {
			if actionValueMutates(v) {
				return true
			}
		}
	}
	return false
}

// actionValueMutates reports whether the value of an action parameter names a
// write. A leading path slash is tolerated (?action=/delete); CamelCase values
// such as "deleteUser" are recognised through their prefix.
func actionValueMutates(raw string) bool {
	v := strings.Trim(strings.TrimSpace(raw), "/")
	if v == "" {
		return false
	}
	if anyWordIn(splitWords(v), mutatingActionVerbs) {
		return true
	}
	return startsWithCamelVerb(v, mutatingActionVerbs)
}

// routeNamesMutation applies the path and query rules to a single-page-app
// route fragment. "#/items/delete?id=1" is never requested as its own URL, but
// rendering it under the seed page can still fire the destructive request.
func routeNamesMutation(fragment string) bool {
	route := fragmentRouteReference(fragment)
	if route == "" {
		return false
	}
	u, err := url.Parse(route)
	if err != nil {
		return false
	}
	return pathNamesMutation(u.Path) || queryNamesMutation(u.Query())
}

// isReadMethod reports whether discovery can fetch a URL with this method and
// no request body. Only those fetches are subject to the data-mutation guard:
// registering a form's POST target is passive, and the executor's state
// changing opt-ins decide whether it is ever sent.
func isReadMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodGET, domain.MethodHEAD, domain.MethodOPTIONS, "":
		return true
	default:
		return false
	}
}

// anyWordIn reports whether any word of words is in set.
func anyWordIn(words []string, set map[string]struct{}) bool {
	for _, w := range words {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}

// startsWithCamelVerb reports whether s begins with one of verbs followed by
// an uppercase letter — "deleteUser", "updateProfile" — the CamelCase shape
// splitWords cannot see. A lowercase continuation ("deleted", "editor") does
// not match, which keeps plurals and ordinary nouns out.
func startsWithCamelVerb(s string, verbs map[string]struct{}) bool {
	for verb := range verbs {
		if len(s) <= len(verb) || !strings.EqualFold(s[:len(verb)], verb) {
			continue
		}
		r, _ := utf8.DecodeRuneInString(s[len(verb):])
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

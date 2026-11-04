package accesscontrol

// Case 21: a profile update that accepts a role field the client should not
// control (mass assignment of a privilege on the caller's OWN profile).
//
// The slice tests ONE thing: adding a role/privilege field to the caller's own
// profile update. It never targets another principal's profile and never
// enumerates users. Whether the write actually elevated the caller is decided
// by the SHARED rule in elevation.go — a privileged surface that was denied
// before the update must be reachable after it. The caller's own profile role
// value is corroborating evidence, never the verdict gate.
//
// No I/O happens here: the scan side sends the update and re-probes the
// surface.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// ValueKind is how the elevated value must be encoded in a JSON body. Form
// bodies always use the plain string form; JSON needs the real type, because
// {"isAdmin":"true"} is a string a typed model will usually reject or ignore
// while {"isAdmin":true} is the boolean it accepts.
type ValueKind string

const (
	ValueText   ValueKind = "text"
	ValueBool   ValueKind = "bool"
	ValueNumber ValueKind = "number"
)

// Field is one role-bearing field to add to (or override in) the profile
// update request.
type Field struct {
	Name   string    `json:"name"`
	Value  string    `json:"value"`
	Kind   ValueKind `json:"kind"`
	Source string    `json:"source"` // "endpoint" | "profile" | "default"
}

// ProfileChange is what the caller's own profile said about the role field
// after the update. It only refines the reason for a non-confirmation; it is
// never the verdict.
type ProfileChange string

const (
	ProfileUnknown   ProfileChange = "unknown"
	ProfileUnchanged ProfileChange = "unchanged"
	ProfileChanged   ProfileChange = "changed"
)

// RawValue renders a field for a JSON body with its intended type.
func (f Field) RawValue() (json.RawMessage, error) {
	switch f.Kind {
	case ValueBool:
		if strings.EqualFold(f.Value, "true") {
			return json.RawMessage("true"), nil
		}
		if strings.EqualFold(f.Value, "false") {
			return json.RawMessage("false"), nil
		}
		return nil, fmt.Errorf("boolean field %q has non-boolean value %q", f.Name, f.Value)
	case ValueNumber:
		return json.RawMessage(f.Value), nil
	default:
		b, err := json.Marshal(f.Value)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(b), nil
	}
}

// CandidateFields builds the bounded, ordered field list to try for one
// endpoint: role fields ALREADY observed on the update endpoint first, then
// role fields the caller's own profile page exposes, then the fixed default
// names. Deduplicated case-insensitively and capped at MaxFieldsPerEndpoint.
func CandidateFields(endpointObserved, profileObserved []string) []Field {
	var out []Field
	seen := map[string]bool{}
	add := func(name, source string) {
		if len(out) >= MaxFieldsPerEndpoint {
			return
		}
		// Deduplicate on the WIRE spelling, not the normalized one: is_admin
		// and isAdmin (or role_id and roleId) are different JSON/form keys and
		// a target may accept only one of them.
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" || !RoleName(name) || seen[n] {
			return
		}
		seen[n] = true
		value, kind := elevatedValue(name)
		out = append(out, Field{Name: strings.TrimSpace(name), Value: value, Kind: kind, Source: source})
	}
	for _, name := range endpointObserved {
		add(name, "endpoint")
	}
	for _, name := range profileObserved {
		add(name, "profile")
	}
	for _, name := range DefaultFieldNames() {
		add(name, "default")
	}
	return out
}

// DefaultFieldNames are the fixed names tried when the target exposes none.
// "isAdmin" and "is_admin" are deliberately separate wire spellings.
func DefaultFieldNames() []string {
	return []string{"role", "roleid", "is_admin", "isAdmin", "admin"}
}

var (
	inputTagRE  = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	inputAttrRE = regexp.MustCompile(`(?is)\b(name|value)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// RoleFieldNames returns the role-bearing field names a page exposes: JSON
// object keys (sorted, deterministic) and HTML input names (document order),
// deduplicated case-insensitively. It never invents a name.
func RoleFieldNames(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" || !RoleName(name) || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, strings.TrimSpace(name))
	}
	for _, name := range jsonRoleKeys(body) {
		add(name)
	}
	for _, name := range htmlRoleInputNames(body) {
		add(name)
	}
	return out
}

func jsonRoleKeys(body []byte) []string {
	root, ok := decodeObject(body)
	if !ok {
		return nil
	}
	var out []string
	var walk func(m map[string]any, depth int)
	walk = func(m map[string]any, depth int) {
		if depth > 3 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch v := m[k].(type) {
			case map[string]any:
				walk(v, depth+1)
			case []any:
				// A list of users is a listing, not this page's own role field.
				_ = v
			default:
				if RoleName(k) {
					out = append(out, k)
				}
			}
		}
	}
	walk(root, 0)
	return out
}

func decodeObject(body []byte) (map[string]any, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

func htmlRoleInputNames(body []byte) []string {
	var out []string
	for _, loc := range inputTagRE.FindAllIndex(body, -1) {
		attrs := htmlInputAttrs(body[loc[0]:loc[1]])
		if RoleName(attrs["name"]) {
			out = append(out, attrs["name"])
		}
	}
	return out
}

func htmlInputAttrs(tag []byte) map[string]string {
	attrs := map[string]string{}
	for _, m := range inputAttrRE.FindAllSubmatch(tag, -1) {
		name := strings.ToLower(string(m[1]))
		val := string(m[2])
		if val == "" {
			val = string(m[3])
		}
		attrs[name] = val
	}
	return attrs
}

// RoleValue returns the value a page shows for a role field, when it shows
// one. It is evidence that the update was stored, never the verdict gate.
func RoleValue(body []byte, name string) (string, bool) {
	want := NormalizeName(name)
	if m, ok := decodeObject(body); ok {
		var found string
		var seen bool
		var walk func(map[string]any, int)
		walk = func(m map[string]any, depth int) {
			if depth > 3 || seen {
				return
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				switch v := m[k].(type) {
				case map[string]any:
					walk(v, depth+1)
				default:
					if NormalizeName(k) != want {
						continue
					}
					if s, ok := scalarString(v); ok {
						found, seen = s, true
						return
					}
				}
			}
		}
		walk(m, 0)
		if seen {
			return found, true
		}
	}
	for _, loc := range inputTagRE.FindAllIndex(body, -1) {
		attrs := htmlInputAttrs(body[loc[0]:loc[1]])
		if NormalizeName(attrs["name"]) == want && strings.TrimSpace(attrs["value"]) != "" {
			return strings.TrimSpace(attrs["value"]), true
		}
	}
	return "", false
}

func scalarString(v any) (string, bool) {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val), strings.TrimSpace(val) != ""
	case json.Number:
		return val.String(), true
	case bool:
		if val {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// target selection
// ---------------------------------------------------------------------------

// authPathHints mark endpoints that are about establishing a session, not
// updating the caller's profile. A login form carries username/password and
// would otherwise look exactly like a profile update.
var authPathHints = []string{"login", "log-in", "signin", "sign-in", "signup", "sign-up", "register", "logout", "log-out", "reset", "forgot"}

func pathHasAny(rawURL string, hints []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for _, h := range hints {
		if strings.Contains(p, h) {
			return true
		}
	}
	return false
}

// ProfilePath reports whether a URL path looks like a profile/account surface
// on the endpoint's own application: profile, account, user, member, or a
// "me" segment. Auth paths (login, register, reset, …) are explicitly not.
func ProfilePath(rawURL string) bool {
	if pathHasAny(rawURL, authPathHints) {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	if strings.Contains(p, "profile") || strings.Contains(p, "account") ||
		strings.Contains(p, "user") || strings.Contains(p, "member") {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "me" {
			return true
		}
	}
	return false
}

// ProfileUpdateEndpoint reports whether an endpoint is a plausible
// profile-update target for this slice: a state-changing method carrying a
// form/JSON body with an identity or role field, on a profile-ish path.
func ProfileUpdateEndpoint(method domain.HTTPMethod, rawURL string, params []*domain.Parameter) bool {
	switch method {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH:
	default:
		return false
	}
	if !ProfilePath(rawURL) {
		return false
	}
	bodyParam, identity, role := false, false, false
	for _, p := range params {
		if p == nil {
			continue
		}
		if p.Location != domain.LocationForm && p.Location != domain.LocationJSON {
			continue
		}
		bodyParam = true
		if IdentityParameter(p.Name) {
			identity = true
		}
		if RoleName(p.Name) {
			role = true
		}
	}
	return bodyParam && (identity || role)
}

// routeWords are path segments that describe the route itself, never a
// principal. Anything else that looks like an identifier is treated as a
// named principal — and refused unless it is the caller's own identity.
var routeWords = map[string]bool{
	"profile": true, "profiles": true, "account": true, "accounts": true,
	"user": true, "users": true, "member": true, "members": true,
	"me": true, "my": true, "my-account": true, "myaccount": true,
	"settings": true, "setting": true, "preferences": true, "details": true,
	"edit": true, "update": true, "change": true, "change-email": true,
	"changeemail": true, "email": true, "password": true, "role": true,
	"roles": true, "api": true, "rest": true, "v1": true, "v2": true, "v3": true,
	"admin": true, "dashboard": true, "home": true, "index": true, "app": true,
	"edit-profile": true, "profile-edit": true, "account-settings": true,
}

var principalShapeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$`)

// OwnProfilePath reports whether an update URL can only address the caller's
// own profile. A segment that names a principal must equal one of the caller's
// own identity values; a segment naming somebody else is refused before any
// request is sent, so this slice can never modify another account.
func OwnProfilePath(rawURL string, caller []string) (bool, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, "the endpoint URL cannot be parsed"
	}
	own := map[string]bool{}
	for _, v := range caller {
		if n := strings.ToLower(strings.TrimSpace(v)); n != "" {
			own[n] = true
		}
	}
	for _, raw := range strings.Split(u.Path, "/") {
		seg, err := url.PathUnescape(raw)
		if err != nil {
			seg = raw
		}
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "" || routeWords[seg] {
			continue
		}
		if own[seg] {
			continue // the path names the caller: explicitly their own profile
		}
		if principalShapeRE.MatchString(seg) {
			return false, fmt.Sprintf("the endpoint path names %q, which is not the caller's own identity; refusing to change another principal's profile", seg)
		}
	}
	return true, ""
}

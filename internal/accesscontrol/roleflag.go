package accesscontrol

// Case 20: authorization decided by a client-controlled value.
//
// The pure half decides WHICH flags to try and whether a flag differential
// proves elevation. A flag is a query parameter or a cookie the request
// carries; setting it to an admin-like value must make a privileged endpoint
// reachable that is otherwise denied. A value that merely changes page TEXT is
// never a finding — the shared rule in elevation.go requires an actionable
// administrative surface.
//
// No network, browser or LLM call is made from this package; the scan-side
// handler feeds it already-fetched responses.

import (
	"fmt"
	"net/url"
	"strings"
)

// Location says where a client-controlled authorization flag is carried.
type Location string

const (
	LocationQuery  Location = "query"
	LocationCookie Location = "cookie"
)

// MaxFlags bounds how many flag probes one privileged endpoint may receive
// (one baseline request is added on top). Small and deterministic on purpose:
// this engine is a bounded differential, never a flag fuzzer.
const MaxFlags = 6

// Flag is one client-controlled authorization flag with the admin-like value
// to try.
type Flag struct {
	Name     string   `json:"name"`
	Location Location `json:"location"`
	Value    string   `json:"value"`
	// Source is "discovered" when the scan observed the flag in a request it
	// already made, or "vocabulary" when the bounded fallback proposed it.
	Source string `json:"source,omitempty"`
}

// Describe renders the flag the way a report should read it.
func (f Flag) Describe() string {
	kind := "query parameter"
	if f.Location == LocationCookie {
		kind = "cookie"
	}
	return fmt.Sprintf("%s %q=%q", kind, f.Name, f.Value)
}

// Kind names the flag location for a report title.
func (f Flag) Kind() string {
	if f.Location == LocationCookie {
		return "cookie"
	}
	return "request parameter"
}

// Key is the case-insensitive identity used to deduplicate probes.
func (f Flag) Key() string {
	return string(f.Location) + "\x00" + strings.ToLower(strings.TrimSpace(f.Name)) + "\x00" + f.Value
}

// Observed is a client-controlled value the scan already saw in a request: a
// discovered query parameter on the privileged endpoint, or a non-session
// cookie the scan's own session carries.
type Observed struct {
	Name     string
	Location Location
	Value    string
}

// vocabularyFlags is the bounded fallback probe set, used when discovery found
// no role-shaped flag to work from. It is a fixed list, never a wordlist, and
// it is capped by MaxFlags together with any discovered flags.
func vocabularyFlags() []Flag {
	return []Flag{
		{Name: "admin", Location: LocationQuery, Value: "true", Source: "vocabulary"},
		{Name: "role", Location: LocationQuery, Value: "admin", Source: "vocabulary"},
		{Name: "is_admin", Location: LocationQuery, Value: "true", Source: "vocabulary"},
		{Name: "isAdmin", Location: LocationQuery, Value: "true", Source: "vocabulary"},
		{Name: "Admin", Location: LocationCookie, Value: "true", Source: "vocabulary"},
		{Name: "role", Location: LocationCookie, Value: "admin", Source: "vocabulary"},
	}
}

// DeriveFlags merges the flags the scan actually observed with the bounded
// vocabulary fallback. Discovered flags come first (they are grounded in a
// request the target itself accepted), duplicates are dropped
// case-insensitively, and the result is capped at MaxFlags.
func DeriveFlags(observed []Observed) []Flag {
	out := make([]Flag, 0, MaxFlags)
	seen := map[string]bool{}
	add := func(f Flag) bool {
		if len(out) >= MaxFlags {
			return false
		}
		k := f.Key()
		if seen[k] {
			return true
		}
		seen[k] = true
		out = append(out, f)
		return true
	}
	for _, o := range observed {
		if !RoleName(o.Name) {
			continue
		}
		for _, v := range RoleValues(o.Name) {
			add(Flag{Name: o.Name, Location: o.Location, Value: v, Source: "discovered"})
		}
	}
	for _, f := range vocabularyFlags() {
		if !add(f) {
			break
		}
	}
	return out
}

// PrivilegedSegment reports whether a path segment names a privileged area.
// Matched case-insensitively at any position, so an application mounted under
// /app/admin/... is recognised too.
func PrivilegedSegment(seg string) bool {
	switch strings.ToLower(strings.TrimSpace(seg)) {
	case "admin", "administrator", "administration", "manage", "management",
		"console", "backoffice", "staff", "superuser", "sysadmin":
		return true
	default:
		return false
	}
}

// PrivilegedPath reports whether a URL path names a privileged area at all
// (used to prefer endpoints discovery already found over the conventional
// fallback path).
func PrivilegedPath(p string) bool {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if PrivilegedSegment(seg) {
			return true
		}
	}
	return false
}

// FlagRequestURL applies a query flag to a privileged endpoint's own URL. It
// is the pure half of request building; the caller still refuses to send it if
// the origin changed.
func FlagRequestURL(privilegedURL string, f Flag) (string, error) {
	u, err := url.Parse(strings.TrimSpace(privilegedURL))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("privileged URL %q is not absolute", privilegedURL)
	}
	if f.Location != LocationQuery {
		return u.String(), nil
	}
	q := u.Query()
	q.Set(f.Name, f.Value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

package discovery

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file supports Path-location injection points: treating a URL path
// SEGMENT (not just query/form/JSON parameters) as a candidate for the
// Reflected XSS pipeline. It is conservative and heuristic-gated only (see
// isQualifyingPathSegment) — a literal route keyword ("api", "v1", "admin",
// "login") is never mutated, only a segment that looks like a variable value
// (numeric ID, UUID, or an opaque alphanumeric slug).

// PathSegments splits a URL path into its slash-delimited, non-empty
// segments (a leading/trailing/double slash contributes no empty elements).
// Shared by discovery (QualifyingPathSegments, deciding which segments to
// register as Path injection points) and the scan executor's buildRequest
// (internal/scan/executor.go, rebuilding the IDENTICAL segment list to
// substitute a candidate value into the chosen segment) — both must agree on
// what "segment index N" means for the same URL, so this is the one place
// that splits a path.
func PathSegments(path string) []string {
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// JoinPathSegments rebuilds an absolute path (always a leading "/") from
// segments produced by PathSegments.
func JoinPathSegments(segs []string) string {
	return "/" + strings.Join(segs, "/")
}

// PathSegmentMatch is one path segment judged to look like a variable value
// (see QualifyingPathSegments), at its position in PathSegments' output.
type PathSegmentMatch struct {
	Index int
	Value string
}

// QualifyingPathSegments returns every segment of path that looks like a
// variable value — purely numeric, UUID-shaped, or an opaque alphanumeric
// slug — rather than a literal route keyword, e.g. the "42" in
// "/users/42/edit", never "users" or "edit". An endpoint whose path has no
// qualifying segment correctly returns nothing (nil).
func QualifyingPathSegments(path string) []PathSegmentMatch {
	var out []PathSegmentMatch
	for i, seg := range PathSegments(path) {
		if isQualifyingPathSegment(seg) {
			out = append(out, PathSegmentMatch{Index: i, Value: seg})
		}
	}
	return out
}

// pathSegmentParamNameRe parses a Path-location domain.Parameter's Name
// (see PathSegmentParamName) back into its segment index.
var pathSegmentParamNameRe = regexp.MustCompile(`^path\[(\d+)\]$`)

// PathSegmentParamName encodes a qualifying segment's position as a
// Parameter.Name, so a later buildRequest can recompute PathSegments on the
// SAME endpoint URL and know exactly which segment this injection point
// targets, without a separate index field on the domain model.
func PathSegmentParamName(index int) string {
	return fmt.Sprintf("path[%d]", index)
}

// ParsePathSegmentParamName is PathSegmentParamName's inverse.
func ParsePathSegmentParamName(name string) (int, bool) {
	m := pathSegmentParamNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	idx, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return idx, true
}

// routeKeywordSegments are common literal route-path words that must NEVER
// be treated as a mutable value, even though a few (containing a digit —
// "v1", "oauth2") would otherwise pass the opaque-slug heuristic below.
// Deliberately small and conservative: a false negative here (a literal
// word not in this list) just means one segment is not tested — safe. A
// false positive (excluding something that happened to be a real value)
// is also safe. Neither risks mutating a real route keyword.
var routeKeywordSegments = map[string]bool{
	"api": true, "v1": true, "v2": true, "v3": true, "v4": true,
	"admin": true, "login": true, "logout": true, "signin": true, "signup": true,
	"signout": true, "register": true, "user": true, "users": true,
	"account": true, "accounts": true, "profile": true, "settings": true,
	"dashboard": true, "home": true, "index": true, "static": true,
	"assets": true, "public": true, "auth": true, "oauth": true, "oauth2": true,
	"callback": true, "webhook": true, "docs": true, "help": true, "about": true,
	"contact": true, "search": true, "edit": true, "new": true, "create": true,
	"update": true, "delete": true, "view": true, "show": true, "list": true,
	"item": true, "items": true, "product": true, "products": true,
	"order": true, "orders": true, "cart": true, "checkout": true,
	"page": true, "pages": true, "category": true, "categories": true,
	"tag": true, "tags": true, "blog": true, "post": true, "posts": true,
	"article": true, "articles": true, "file": true, "files": true,
	"download": true, "upload": true, "image": true, "images": true,
	"img": true, "css": true, "js": true, "fonts": true, "api-docs": true,
}

var (
	numericSegmentRe = regexp.MustCompile(`^[0-9]+$`)
	uuidSegmentRe    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	opaqueSlugRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// isQualifyingPathSegment reports whether seg looks like a variable value
// (purely numeric, a UUID, or an opaque alphanumeric slug — one containing
// at least one digit, so a plain dictionary word is never mistaken for a
// value) rather than a literal route keyword. "api", "v1", "admin", "login"
// (routeKeywordSegments) are never mutated even if they happen to contain a
// digit; a purely alphabetic word NOT in the keyword list ("dashboard",
// "settings") is also never treated as a value — only a segment with a
// digit, or an exact UUID shape, qualifies, so an incomplete keyword list
// never turns into a wrongly-mutated literal segment.
func isQualifyingPathSegment(seg string) bool {
	if seg == "" {
		return false
	}
	if routeKeywordSegments[strings.ToLower(seg)] {
		return false
	}
	if numericSegmentRe.MatchString(seg) {
		return true
	}
	if uuidSegmentRe.MatchString(seg) {
		return true
	}
	return isOpaqueSlug(seg)
}

// isOpaqueSlug is the catch-all case: a non-numeric, non-UUID segment is
// only treated as a value when it is reasonably long, alphanumeric
// (optionally with - or _), has no dot (avoids mutating a filename's
// extension, e.g. "style.css"), and contains at least one digit — the
// digit requirement is what keeps an ordinary English route word
// ("warehouse", "editor") from being misclassified; a real opaque slug/ID
// (base36/base62 object id, short-URL code, SKU) almost always has one.
func isOpaqueSlug(seg string) bool {
	if len(seg) < 6 || strings.Contains(seg, ".") {
		return false
	}
	if !opaqueSlugRe.MatchString(seg) {
		return false
	}
	return strings.ContainsAny(seg, "0123456789")
}

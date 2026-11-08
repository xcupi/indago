package accesscontrol

// Access-control bypass rules (cases 28 and 29).
//
// Both cases are DIFFERENTIAL and server-side: nothing is executed in a browser,
// and nothing state-changing is ever sent. What is proven is that the same
// privileged surface answers DIFFERENTLY to a request the front-end should have
// gated:
//
//   - header path override (case 28): the gateway denies /admin, but the origin
//     server honours X-Original-URL / X-Rewrite-URL, so the same resource is
//     reachable at "/" with the header.
//   - method bypass (case 29): the gateway gates the POST to an admin action,
//     but the handler is reachable with GET — the response is the application's
//     own validation error, which only the handler produces.
//
// The rules are deliberately narrow: a denial must be a real denial (401/403),
// and the variant must show a POSITIVE signal of the privileged surface. A mere
// status change is never enough.

import (
	"regexp"
	"strings"
)

// BypassKind names which bypass a probe proved.
type BypassKind string

const (
	BypassNone      BypassKind = ""
	BypassHeaderURL BypassKind = "header_url_override" // X-Original-URL / X-Rewrite-URL
	BypassMethod    BypassKind = "method_bypass"       // GET reaches a POST-gated action
)

// IsDenialStatus reports whether a status is an authorization denial. Only these
// make a bypass meaningful: a 404 means the surface does not exist, not that it
// is gated.
func IsDenialStatus(status int) bool { return status == 401 || status == 403 }

// AdminSurfaceMarkers are the phrases a granted administrative surface shows.
// They are the positive half of the header-override rule: the response must look
// like the admin UI, not merely be a 200.
var AdminSurfaceMarkers = []string{
	"admin panel",
	"admin interface",
	"administration",
	"delete user",
	"upgrade user",
	"downgrade user",
	"manage users",
	"user management",
	"role",
}

// DenialMarkers are the phrases a denial page uses even when it answers 200.
var DenialMarkers = []string{
	"access denied",
	"not authorized",
	"unauthorized",
	"forbidden",
	"permission denied",
	"you do not have permission",
	"insufficient privileges",
	"admin interface only available",
	"only available to admin",
	"administrators only",
	"admin users only",
	"not allowed to access",
}

// handlerValidationRE matches the application's own parameter-validation error,
// which is produced by the HANDLER rather than by the gateway. That distinction
// is the whole method-bypass proof: the request was parsed as the privileged
// action's own input.
var handlerValidationRE = regexp.MustCompile(`(?i)(missing|required|invalid|unrecognized)\s+(parameter|param|field|argument)|missing parameter`)

// HeaderOverrideReached reports whether an X-Original-URL / X-Rewrite-URL probe
// proved the gateway can be stepped over: the plain request was denied, the
// header variant was not, and its body looks like the administrative surface.
func HeaderOverrideReached(baselineStatus, variantStatus int, variantBody string) bool {
	if !IsDenialStatus(baselineStatus) {
		return false
	}
	if variantStatus < 200 || variantStatus >= 300 {
		return false
	}
	body := strings.ToLower(variantBody)
	if HasDenialMarker(body) {
		return false
	}
	return HasAdminMarker(body)
}

// MethodBypassReached reports whether the same privileged action answered the
// caller with the application's own validation error through a different method
// than the one the gateway gates.
func MethodBypassReached(baselineStatus, variantStatus int, variantBody string) bool {
	if !IsDenialStatus(baselineStatus) {
		return false
	}
	if variantStatus < 400 || variantStatus >= 500 || IsDenialStatus(variantStatus) {
		return false
	}
	body := strings.ToLower(variantBody)
	if HasDenialMarker(body) {
		return false
	}
	return handlerValidationRE.MatchString(body)
}

// HasAdminMarker reports whether the body shows administrative surface content.
func HasAdminMarker(body string) bool {
	body = strings.ToLower(body)
	for _, m := range AdminSurfaceMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// HasDenialMarker reports whether the body is a denial page.
func HasDenialMarker(body string) bool {
	body = strings.ToLower(body)
	for _, m := range DenialMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// BypassPaths are the bounded privileged surfaces the bypass probes cover: the
// administrative panel and its role-management action — the two shapes the two
// bypass classes are measured on. No wordlist, and no path is invented at run
// time.
var BypassPaths = []string{"/admin", "/admin-roles", "/administration"}

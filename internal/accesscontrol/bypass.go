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
	// BypassHeaderClientIP is the authentication-bypass-via-information-
	// disclosure case: a TRACE echo names the client-IP header the edge trusts,
	// and the same denied surface answers a request carrying that header set to
	// the loopback address.
	BypassHeaderClientIP BypassKind = "header_client_ip_spoof"
)

// disclosedIPHeaderRE reads a header NAME from a TRACE echo. It is deliberately
// narrow: only names that look like a client-IP / forwarding header are read, so
// ordinary echoed headers (Host, User-Agent, Accept, Cookie) never become probe
// candidates. The name must be followed by a colon, exactly as an echoed request
// line prints it.
var disclosedIPHeaderRE = regexp.MustCompile(`(?i)\b(x-[a-z0-9-]*(?:ip|forwarded|client)[a-z0-9-]*|forwarded|true-client-ip|cf-connecting-ip)\s*:`)

// MaxDisclosedIPHeaders bounds how many header names one TRACE echo may
// contribute.
const MaxDisclosedIPHeaders = 3

// DisclosedIPHeaders returns the client-IP-shaped header names a TRACE echo
// actually printed, lower-cased, de-duplicated, in first-seen order and capped.
// The list is read from the response — never a wordlist — because the lab's
// header name is application-specific ("X-Custom-IP-Authorization").
func DisclosedIPHeaders(trace string) []string {
	out := make([]string, 0, MaxDisclosedIPHeaders)
	seen := map[string]struct{}{}
	for _, m := range disclosedIPHeaderRE.FindAllStringSubmatch(trace, -1) {
		name := strings.ToLower(strings.TrimSpace(m[1]))
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
		if len(out) >= MaxDisclosedIPHeaders {
			break
		}
	}
	return out
}

// LoopbackSpoofValue is the value every disclosed client-IP header is set to:
// the address an edge treats as "this machine". It is a fixed literal, never a
// guess.
const LoopbackSpoofValue = "127.0.0.1"

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

// HandlerRan reports whether a mutation probe reached the application handler
// on a request the baseline step denied. It is the shared signal for cases 35
// and 36: the same session is refused when it takes the ordinary path, and
// reaches the handler when it adds only the confirmation flag (35) or the
// administrative Referer (36).
//
// The variant must NOT be a denial, must not carry a denial marker, and must
// say something the application wrote: a bare "Bad Request"/"Unauthorized"
// gateway phrase proves nothing, and neither does a body identical to the
// denial's.
func HandlerRan(baselineStatus, variantStatus int, baselineBody, variantBody string) bool {
	if !IsDenialStatus(baselineStatus) {
		return false
	}
	if variantStatus < 200 || variantStatus >= 500 || IsDenialStatus(variantStatus) {
		return false
	}
	body := strings.TrimSpace(variantBody)
	if body == "" || HasDenialMarker(body) {
		return false
	}
	if isBareStatusText(body) {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(baselineBody), body)
}

// isBareStatusText rejects bodies that are just an HTTP reason phrase: those are
// produced by gateways and proxies, not by an application handler.
func isBareStatusText(body string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(body), `"'.`)) {
	case "bad request", "unauthorized", "forbidden", "not found", "error",
		"method not allowed", "internal server error", "not acceptable":
		return true
	}
	return false
}

// BypassPaths are the bounded privileged surfaces the bypass probes cover: the
// administrative panel and its role-management action — the two shapes the two
// bypass classes are measured on. No wordlist, and no path is invented at run
// time.
var BypassPaths = []string{"/admin", "/admin-roles", "/administration"}

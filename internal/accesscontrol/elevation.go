package accesscontrol

// The shared elevation rule for the two "state changed, then look again"
// cases (20 and 21).
//
// Case 19 asks a single question of one response: does an anonymous page expose
// a privileged action? Cases 20 and 21 ask a DIFFERENTIAL question: did a
// privileged surface that was NOT reachable become reachable after a change the
// caller controls (a flag, or a profile field)? Both are the same rule, so they
// share one implementation here:
//
//	before: the privileged endpoint as the caller can reach it today
//	        (flag absent / before the profile update)
//	after:  the SAME endpoint after the client-controlled change
//
// Confirmation requires ALL of:
//
//  1. the surface was not already granted before the change — otherwise the
//     change proved nothing;
//  2. the surface IS granted after the change (not a 401/403, not a login
//     page, not a denial page);
//  3. the after response exposes at least one actionable administrative
//     capability (see accesscontrol.go) — a page whose TEXT merely says
//     "admin" is never a finding;
//  4. the response came from the same host that was requested.
//
// Everything else is Rejected or Inconclusive with a recorded reason. No
// network, browser or LLM call happens here.

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Bounds shared by the two differential slices. They are constants (not
// configuration) so the passes can never grow into enumeration or a write
// storm: at most three profile endpoints per scan, five field names per
// endpoint, and six state-changing requests per scan.
const (
	MaxTargetsPerScan    = 3
	MaxFieldsPerEndpoint = 5
	MaxWritesPerScan     = 6
)

// Reach is the classified state of a privileged surface for the current
// caller.
type Reach string

const (
	ReachUnknown Reach = "unknown"
	ReachDenied  Reach = "denied"
	ReachGranted Reach = "granted"
)

// PrivilegedPaths are the bounded, common privileged surfaces probed when
// discovery found none on the endpoint's origin. No wordlist: two well-known
// paths. A scan that needs a different surface cannot invent one here.
var PrivilegedPaths = []string{"/admin", "/administration"}

var passwordInputRE = regexp.MustCompile(`(?i)<input\b[^>]*type\s*=\s*["']?password`)

// denialMarkers are the phrases an authorization-denial page uses. They are
// what makes a 200 response a denial rather than a granted surface.
var denialMarkers = []string{
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

// ClassifySurface labels a privileged-surface response. Only an explicit
// denial or a real, non-login content page is classified: everything else
// (404, empty 2xx, 5xx, odd redirects) stays Unknown so a scan can never
// confirm on a path that simply does not exist.
//
// A 3xx is classified from its Location: a redirect to a login route is a
// denial; any other redirect is Unknown because the engine follows redirects
// itself and a chain that ends elsewhere has not been observed.
func ClassifySurface(status int, location string, body []byte) Reach {
	switch {
	case status == 0:
		return ReachUnknown
	case status == 401 || status == 403:
		return ReachDenied
	case status >= 300 && status < 400:
		if pathHasAny(location, []string{"login", "signin", "sign-in", "log-in"}) {
			return ReachDenied
		}
		return ReachUnknown
	case status >= 200 && status < 300:
		if len(bytes.TrimSpace(body)) == 0 {
			return ReachUnknown
		}
		if passwordInputRE.Match(body) {
			return ReachDenied // bounced to a login page
		}
		lower := strings.ToLower(string(body))
		for _, marker := range denialMarkers {
			if strings.Contains(lower, marker) {
				return ReachDenied
			}
		}
		return ReachGranted
	default:
		return ReachUnknown
	}
}

// Elevation is the verdict for one before/after pair plus the evidence trail
// that justifies it.
type Elevation struct {
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason"`
	Before  Reach   `json:"before"`
	After   Reach   `json:"after"`
	// BeforeStatus / AfterStatus are the two HTTP statuses observed.
	BeforeStatus int `json:"before_status,omitempty"`
	AfterStatus  int `json:"after_status,omitempty"`
	// Capabilities are the actionable administrative surfaces the after
	// response exposed. Empty unless confirmed.
	Capabilities []Action `json:"capabilities,omitempty"`
}

// DecideElevation applies the shared rule. requestedURL is the URL that was
// asked for (used for the same-host check); before and after are the two
// responses; change is a human-readable description of the client-controlled
// change ("setting cookie \"Admin\"=\"true\"", "the profile update carrying
// \"role\"=\"admin\"").
func DecideElevation(requestedURL string, before, after Snapshot, change string) Elevation {
	beforeReach := ClassifySurface(before.Status, before.FinalURL, before.Body)
	afterReach := ClassifySurface(after.Status, after.FinalURL, after.Body)
	e := Elevation{Before: beforeReach, After: afterReach,
		BeforeStatus: before.Status, AfterStatus: after.Status}

	switch {
	case before.Status == 0:
		e.Outcome = OutcomeInconclusive
		e.Reason = "the baseline request (without the client-controlled change) was not answered"
		return e
	case after.Status == 0:
		e.Outcome = OutcomeInconclusive
		e.Reason = fmt.Sprintf("%s was not answered", change)
		return e
	case after.Truncated:
		e.Outcome = OutcomeInconclusive
		e.Reason = fmt.Sprintf("%s returned HTTP %d but its body was truncated before the administrative-capability scan could complete", change, after.Status)
		return e
	case foreignHost(requestedURL, after.FinalURL):
		e.Outcome = OutcomeInconclusive
		e.Reason = fmt.Sprintf("%s produced a response from a different host (%s); it was not evaluated", change, hostLabel(after.FinalURL))
		return e
	case beforeReach == ReachGranted:
		e.Outcome = OutcomeRejected
		e.Reason = fmt.Sprintf("the privileged surface was already reachable (HTTP %d) before %s, so the change proved nothing", before.Status, change)
		return e
	case afterReach != ReachGranted:
		e.Outcome = OutcomeRejected
		e.Reason = fmt.Sprintf("%s did not make the privileged surface reachable (baseline HTTP %d → HTTP %d, %s)",
			change, before.Status, after.Status, afterReach)
		return e
	}

	caps := Analyze(after).Actions
	e.Capabilities = caps
	if len(caps) == 0 {
		e.Outcome = OutcomeRejected
		e.Reason = fmt.Sprintf("%s produced HTTP %d, but the response exposed no administrative action surface; a change in page text alone is not an authorization change",
			change, after.Status)
		return e
	}
	e.Outcome = OutcomeConfirmed
	e.Reason = fmt.Sprintf("%s made the privileged surface reachable (baseline HTTP %d → HTTP %d) and exposed %s",
		change, before.Status, after.Status, actionKinds(caps))
	return e
}

// foreignHost reports whether a response's final URL left the requested host.
func foreignHost(requestedURL, finalURL string) bool {
	req, err := url.Parse(strings.TrimSpace(requestedURL))
	if err != nil || req.Host == "" {
		return false
	}
	final, err := url.Parse(strings.TrimSpace(finalURL))
	if err != nil || final.Host == "" {
		return false
	}
	if !strings.EqualFold(req.Hostname(), final.Hostname()) {
		return true
	}
	return effectivePort(req) != effectivePort(final)
}

func hostLabel(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// actionKinds renders the distinct kinds of an action list for a reason
// string, in a stable order.
func actionKinds(actions []Action) string {
	seen := make(map[ActionKind]struct{}, len(actions))
	var out []string
	for _, a := range actions {
		if _, ok := seen[a.Kind]; ok {
			continue
		}
		seen[a.Kind] = struct{}{}
		out = append(out, string(a.Kind))
	}
	return strings.Join(out, ", ")
}

package discovery

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// This file models the opt-in RAW QUERY-STRING injection point. Some pages
// echo their ENTIRE query string into the response — a canonical
// <link rel="canonical" href="...">, some 404/search/error pages — so the
// vulnerable input is an unnamed blob ("/?<payload>", "/?x=<payload>") rather
// than a "name=value" parameter. Indago is parameter-driven, so without this
// model such an endpoint has nothing to test at all.
//
// The blob is modelled as a PSEUDO-PARAMETER: an ordinary domain.Parameter
// whose Location is domain.LocationRawQuery and whose Name is one of the
// reserved shape names below (never a real parameter name). Everything
// downstream — injection points, test jobs, reflection analysis, context
// classification, candidate planning, candidate execution and browser
// verification — then runs UNCHANGED, because it is all location-agnostic
// except for the one place that builds a request (scan.buildRequest). No
// second detector exists.
//
// Boundaries: this only ever adds GET probe requests, only when the operator
// opted in, to endpoints that are already in scope. Scope, rate limiting,
// session cookies and fail-closed redirects are exactly the same code paths a
// named parameter uses.

// RawQueryMode selects the opt-in raw query-string probing behaviour. The zero
// value is the empty string, which behaves exactly like RawQueryOff: an
// existing scan (or an old persisted row with no raw_query_injection field)
// never gains these requests.
type RawQueryMode string

const (
	RawQueryOff    RawQueryMode = "off"
	RawQueryAuto   RawQueryMode = "auto"   // only GET endpoints with no named query parameters
	RawQueryAlways RawQueryMode = "always" // every GET endpoint, in addition to its named parameters
)

// ParseRawQueryMode parses the scan option. "false" is the boolean-flag spelling of off. Empty means off (backwards
// compatibility for rows created before the field existed).
func ParseRawQueryMode(s string) (RawQueryMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(RawQueryOff), "false":
		return RawQueryOff, nil
	case string(RawQueryAuto), "true", "on":
		return RawQueryAuto, nil
	case string(RawQueryAlways):
		return RawQueryAlways, nil
	default:
		return RawQueryOff, fmt.Errorf("unknown raw query injection mode %q (want off|auto|always)", s)
	}
}

// Enabled reports whether the mode adds any raw-query probe.
func (m RawQueryMode) Enabled() bool { return m == RawQueryAuto || m == RawQueryAlways }

// Hard bounds. They are constants, not configuration: the whole point of this
// capability is to be small, and an operator cannot raise it by accident.
const (
	// MaxRawQueryShapesPerEndpoint is the fixed number of probe shapes sent at
	// one endpoint — one reflection request per shape, never more:
	//   bare:  /?<payload>
	//   named: /?x=<payload>
	// The shapes are deliberately the two smallest forms that cover both
	// "no parameter syntax at all" and "one parameter whose value is unserialized
	// blob" echo styles.
	MaxRawQueryShapesPerEndpoint = 2

	// MaxRawQueryProbesPerScan caps how many raw-query injection points one
	// scan may register. At 2 shapes per endpoint this covers at most 20
	// endpoints and costs at most 40 raw-query reflection requests per scan
	// (each shape is one mutated reflection request). Baselines are shared with
	// the endpoint's existing jobs and candidate follow-ups are governed by the
	// scan's unchanged candidate profile — neither is extra raw-query work.
	MaxRawQueryProbesPerScan = 40
)

// Reserved pseudo-parameter names. They are deliberately not valid URL
// parameter names and read as "this is the raw query string, not a parameter"
// on every surface (TestCase notes, findings, reports). The value in
// parentheses names the request SHAPE, which is what distinguishes the two
// injection points of one endpoint.
const (
	RawQueryBareName  = "(raw query)"
	RawQueryNamedName = "x=(raw query)"
)

// rawQueryShape is one fixed probe shape.
type rawQueryShape struct {
	name   string
	prefix string // literal query prefix before the encoded payload
	why    string
}

var rawQueryShapes = []rawQueryShape{
	{name: RawQueryBareName, prefix: "", why: "/?<payload>: the payload replaces the whole query string"},
	{name: RawQueryNamedName, prefix: "x=", why: "/?x=<payload>: one parameter-looking name whose value is the payload"},
}

// RawQueryShapeNames returns the reserved pseudo-parameter names, in the fixed
// order the shapes are registered. Callers must not mutate the result.
func RawQueryShapeNames() []string {
	out := make([]string, len(rawQueryShapes))
	for i, s := range rawQueryShapes {
		out[i] = s.name
	}
	return out
}

// RawQueryPrefix reports whether name is a reserved raw-query pseudo-parameter
// name and, if so, the literal query prefix its shape uses ("" for the bare
// blob, "x=" for the named blob).
func RawQueryPrefix(name string) (prefix string, ok bool) {
	for _, s := range rawQueryShapes {
		if s.name == name {
			return s.prefix, true
		}
	}
	return "", false
}

// RawQueryQueryString builds the request query string for one raw-query
// injection: the shape's literal prefix followed by the URL-encoded payload.
// Encoding is exactly what a named parameter value gets (url.QueryEscape), so
// the payload reaches the server the same way and a server that decodes its
// query string sees the same bytes it would see for "?name=<payload>".
//
// A name that is not reserved is reported as not a raw-query parameter.
func RawQueryQueryString(name, payload string) (string, bool) {
	prefix, ok := RawQueryPrefix(name)
	if !ok {
		return "", false
	}
	return prefix + url.QueryEscape(payload), true
}

// isRawQueryLocation reports whether loc is the raw query-string injection
// point. Kept tiny so the collector reads clearly.
func isRawQueryLocation(loc domain.ParamLocation) bool { return loc == domain.LocationRawQuery }

// registerRawQueryInjectionPoints registers this endpoint's bounded set of
// raw-query pseudo-parameters, when the scan opted in and the endpoint is a GET
// endpoint the mode covers.
//
// Mode:
//   - off:    nothing (the default; no request, no persisted row).
//   - auto:   only when the endpoint has NO named query parameters — the
//     canonical-link/404/error-page class, where the parameter-driven
//     pipeline otherwise has nothing at all to focus on.
//   - always: in addition to any named parameters (their pipeline is untouched;
//     the raw-query injection point is separate).
//
// Bounds: exactly MaxRawQueryShapesPerEndpoint (2) shapes per endpoint and at
// most MaxRawQueryProbesPerScan (40) per scan, enforced here. The slot is
// reserved under the mutex BEFORE registerParam so concurrent endpoints can
// never overshoot the scan cap, and released again when the registration turned
// out to be a duplicate (e.g. a resumed discovery run re-seeing a hydrated
// endpoint), so a restart neither double-charges nor overshoots.
func (c *Collector) registerRawQueryInjectionPoints(ctx context.Context, endpointID domain.ID, method domain.HTTPMethod, info URLInfo, source domain.DiscoverySource) {
	if !c.cfg.RawQueryInjection.Enabled() || method != domain.MethodGET {
		return
	}
	if c.cfg.RawQueryInjection == RawQueryAuto && len(info.ParamNames) > 0 {
		return
	}
	for _, shape := range rawQueryShapes {
		c.mu.Lock()
		if c.rawQueryProbes >= MaxRawQueryProbesPerScan {
			c.mu.Unlock()
			c.log.Debug("discovery: raw-query probe cap reached for this scan",
				"endpoint", info.Canonical, "cap", MaxRawQueryProbesPerScan)
			return
		}
		c.rawQueryProbes++
		c.mu.Unlock()

		if c.registerParam(ctx, endpointID, method, info, shape.name, domain.LocationRawQuery, "", source) {
			c.log.Debug("discovery: raw-query injection point recorded",
				"endpoint", info.Canonical, "shape", shape.name, "request", "/?"+shape.prefix+"<payload>")
			continue
		}
		// Duplicate: nothing new was sent or persisted, so give the slot back.
		c.mu.Lock()
		c.rawQueryProbes--
		c.mu.Unlock()
	}
}

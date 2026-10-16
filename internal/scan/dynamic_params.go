package scan

// A single-use anti-CSRF token is a common, legitimate defense: the server
// embeds a per-page(or per-session) token in a hidden form field and rejects
// the next state-affecting request unless it carries the CURRENT token,
// usually rotating it again on every accepted request. Discovery captures a
// form field's value exactly ONCE, at crawl time. Replaying that same stale
// value in every later test request means the application's own CSRF check
// rejects the request before it ever reaches the code that would reflect an
// injected parameter — which, from the outside, looks identical to "safely
// sanitized" (nothing comes back) even though the real defense under test
// (output encoding, filtering, whatever) was never actually exercised. This
// file closes that gap: refresh such a field's value, from a live fetch of
// the endpoint's own page, immediately before each real request that needs
// it.
//
// Known limitation: the refresh fetches ep.URL itself (query stripped). For
// a POST form whose action differs from the page that embeds it, this does
// not help — there is no page-provenance tracking from discovery to know
// which URL actually rendered the token. The common cases (DVWA-style
// self-submitting GET forms, and POST forms that render their own token on
// the same URL they post to) are covered.
//
// Also not solved: true concurrency against a single shared, single-use,
// session-bound token. Each call here does its own independent priming
// fetch immediately before its own real request, which is correct for
// sequential testing of one injection point, but two requests racing in
// parallel against the SAME session can still both prime, then both try to
// spend what is — server-side — a single current token slot, and one loses.
// Lowering http/browser concurrency for a target known to use this pattern
// remains the operator's mitigation; this is not attempted here.

import (
	"context"
	"net/url"
	"regexp"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// dynamicTokenName matches a parameter name that commonly carries a rotating
// anti-CSRF/anti-forgery value: "token" alone (user_token, csrf_token,
// _token, authenticity_token, access_token, …), "csrf", "xsrf", or "nonce".
// Deliberately liberal: a false-positive match only costs one extra,
// harmless priming fetch (a parameter that isn't actually dynamic has the
// same value on the re-fetch, so the "refreshed" value is a no-op), while a
// false negative silently reproduces the exact bug this file exists to fix.
var dynamicTokenName = regexp.MustCompile(`(?i)token|csrf|xsrf|nonce`)

func isDynamicTokenName(name string) bool { return dynamicTokenName.MatchString(name) }

// refreshDynamicParams returns params with any dynamic-looking parameter's
// Example updated to what the server is currently issuing — a fresh GET of
// the endpoint's own page (query stripped), re-parsed for its current form
// field values. focus (the parameter actually under test this request) is
// never touched, even if its own name happens to match the heuristic. If no
// parameter looks dynamic, or eng is nil (unit tests, or a scan with no HTTP
// engine wired up), or the priming fetch fails for any reason, params is
// returned completely unchanged — this is a best-effort improvement, never
// a precondition for testing to proceed.
func refreshDynamicParams(ctx context.Context, eng httpengine.Engine, timeout time.Duration, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	hasDynamic := false
	for _, p := range params {
		if p != focus && isDynamicTokenName(p.Name) {
			hasDynamic = true
			break
		}
	}
	if !hasDynamic || eng == nil {
		return params
	}

	u, err := url.Parse(ep.URL)
	if err != nil {
		return params
	}
	u.RawQuery = ""

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := eng.Do(rctx, &httpengine.Request{Method: "GET", URL: u.String()})
	if err != nil || resp == nil || len(resp.Body) == 0 {
		return params
	}

	fresh := currentFormValues(string(resp.Body))
	if len(fresh) == 0 {
		return params
	}

	out := append([]*domain.Parameter(nil), params...)
	for i, p := range out {
		if p == focus || !isDynamicTokenName(p.Name) {
			continue
		}
		if v, ok := fresh[p.Name]; ok {
			cp := *p
			cp.Example = v
			out[i] = &cp
		}
	}
	return out
}

// currentFormValues flattens every form field on a page into name→value,
// last form wins on a name collision (good enough for picking out a single
// named token field; not a general form model).
func currentFormValues(body string) map[string]string {
	out := map[string]string{}
	for _, f := range discovery.ExtractForms(body) {
		for _, in := range f.Inputs {
			out[in.Name] = in.Value
		}
	}
	return out
}

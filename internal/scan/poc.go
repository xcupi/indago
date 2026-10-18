package scan

// This file generates a standalone Proof-of-Concept (PoC) artifact for a
// CONFIRMED reflected-XSS Finding. It is presentation over data the scan
// already produced, reusing the SAME request-building logic (buildRequest)
// and POST-navigation technique as browser verification. It performs no
// network I/O; when authentication or dynamic tokens are needed, it emits a
// redacted request template rather than claiming an exact replay.
//
// Evidence integrity (AGENTS.md §2.6): a PoC may be generated ONLY for a
// Finding whose STORED Verdict is Confirmed — generating one for a Pending/
// Rejected/Inconclusive finding would fabricate evidence of a vulnerability
// that was never actually confirmed. See GeneratePoC's guard, enforced
// before anything else runs.
//
// Faithfulness over polish: a Query/Path override can be a plain link, and a
// POST+form-encoded override can be an auto-submitting <form>, ONLY when the
// scan had no non-anonymous auth session and there are no non-focus dynamic
// token parameters. If either dependency exists, the artifact is inert,
// replaces other captured token values with placeholders, and requires the
// operator to supply their own authorized session/fresh token manually. A
// Header or Cookie override is not carryable by a static cross-origin link or
// form, and a JSON body is not carryable by an HTML form. Those cases remain
// inert and provide request details plus curl rather than claiming a false
// one-click reproduction. See GeneratePoC and the per-location constraints.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
)

// ErrPoCNotConfirmed is returned when GeneratePoC is asked to generate a PoC
// for a Finding whose Verdict is not Confirmed.
var ErrPoCNotConfirmed = errors.New("poc: a proof-of-concept may only be generated for a Confirmed finding")

// ErrPoCNoVerifiedCandidate is returned for a Confirmed finding whose
// Detail does not actually carry a confirming attempt or the full candidate
// record it replayed. Should not happen for a real Finding
// (correlateVerification always records the confirming attempt, and its
// candidate always lands in Detail.Candidates) — checked explicitly rather
// than assumed, so a bug elsewhere surfaces as a clear error instead of a
// fabricated or blank PoC.
var ErrPoCNoVerifiedCandidate = errors.New("poc: confirmed finding has no recorded verified candidate")

// PoC is a generated standalone PoC artifact plus the metadata a CLI/API
// caller needs to present it.
type PoC struct {
	FindingID  domain.ID
	Method     domain.HTTPMethod
	URL        string
	Parameter  string
	Location   domain.ParamLocation
	Combined   bool
	ParameterB string
	LocationB  domain.ParamLocation
	// AuthenticatedSession is true when this scan had a non-anonymous
	// session. Its cookie/state material is never loaded into the artifact;
	// the operator must supply their own authorized session at replay time.
	AuthenticatedSession bool
	// DynamicTokenNames contains non-focus request parameter names matching
	// isDynamicTokenName. Their captured values are replaced with placeholders.
	DynamicTokenNames []string
	// RequestTemplate is true when auth or dynamic-token refresh is required,
	// so the displayed request is not an exact runnable reproduction.
	RequestTemplate bool
	// OneClick is true when the generated HTML, opened directly in a
	// browser with no further action, fully reproduces the confirmed
	// request (every override is Query/Path/Form and there is no auth or
	// dynamic-token refresh dependency). False when a Header, Cookie, JSON,
	// auth, or dynamic-token dependency is involved.
	OneClick bool
	HTML     []byte
}

// Filename is a safe, descriptive default filename for the generated PoC.
func (p *PoC) Filename() string {
	return fmt.Sprintf("indago-poc-%s.html", p.FindingID)
}

// GeneratePoC builds a standalone PoC HTML artifact reproducing findingID's
// verified candidate. It refuses (ErrPoCNotConfirmed) for any Finding whose
// stored Verdict is not Confirmed — see the file doc comment on evidence
// integrity — and only ever replays data the scan already produced; it
// performs no network I/O itself.
func GeneratePoC(ctx context.Context, st store.Store, findingID domain.ID) (*PoC, error) {
	f, err := st.Findings().Get(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("load finding: %w", err)
	}
	if f.VulnClass != domain.VulnReflectedXSS {
		return nil, fmt.Errorf("poc: unsupported vuln class %q (only reflected XSS PoC generation is implemented)", f.VulnClass)
	}
	if f.Verdict != domain.VerdictConfirmed {
		return nil, fmt.Errorf("%w (this finding's verdict is %q)", ErrPoCNotConfirmed, f.Verdict)
	}

	d := decodeFindingDetail(f.Detail)
	att := d.verifiedAttempt()
	if att == nil {
		return nil, ErrPoCNoVerifiedCandidate
	}
	cand := findCandidateForAttempt(d.Candidates, att)
	if cand == nil {
		return nil, ErrPoCNoVerifiedCandidate
	}

	ep, err := st.Endpoints().Get(ctx, f.EndpointID)
	if err != nil {
		return nil, fmt.Errorf("load endpoint: %w", err)
	}
	params, err := st.Parameters().ListByEndpoint(ctx, f.EndpointID)
	if err != nil {
		return nil, fmt.Errorf("list parameters: %w", err)
	}

	focusA := findParamByNameLocation(params, cand.Parameter, cand.Location)
	if focusA == nil {
		return nil, fmt.Errorf("poc: parameter %q (%s) is no longer present on this endpoint", cand.Parameter, cand.Location)
	}
	var focusB *domain.Parameter
	if cand.Combined {
		focusB = findParamByNameLocation(params, cand.ParameterB, cand.LocationB)
		if focusB == nil {
			return nil, fmt.Errorf("poc: second (combined) parameter %q (%s) is no longer present on this endpoint", cand.ParameterB, cand.LocationB)
		}
	}

	authenticated, err := scanHasNonAnonymousSession(ctx, st, f.ScanID)
	if err != nil {
		return nil, err
	}
	dynamicParams := nonFocusDynamicParams(params, focusA, focusB)

	inj := &injection{param: focusA, value: cand.Value}
	if focusB != nil {
		inj.paramB, inj.valueB = focusB, cand.ValueB
	}
	// Reuse the same request-building logic as candidate execution and
	// verification. Then remove captured non-focus CSRF-like values without
	// contacting the target; a current token must be fetched by the operator.
	req, err := buildRequest(ep, params, inj)
	if err != nil {
		return nil, fmt.Errorf("poc: rebuild request template: %w", err)
	}
	if err := redactDynamicTokenValues(req, dynamicParams); err != nil {
		return nil, fmt.Errorf("poc: redact dynamic token values: %w", err)
	}

	p := &PoC{
		FindingID: f.ID, Method: ep.Method, URL: req.URL,
		Parameter: focusA.Name, Location: focusA.Location,
		AuthenticatedSession: authenticated,
		DynamicTokenNames:    dynamicTokenNames(dynamicParams),
		RequestTemplate:      authenticated || len(dynamicParams) > 0,
	}
	locs := []domain.ParamLocation{focusA.Location}
	if cand.Combined {
		p.Combined = true
		p.ParameterB, p.LocationB = cand.ParameterB, cand.LocationB
		locs = append(locs, focusB.Location)
	}
	p.OneClick = allLinkable(locs, ep.Method) && !p.RequestTemplate
	p.HTML = renderPoCHTML(p, req)
	return p, nil
}

func scanHasNonAnonymousSession(ctx context.Context, st store.Store, scanID domain.ID) (bool, error) {
	sc, err := st.Scans().Get(ctx, scanID)
	if err != nil {
		return false, fmt.Errorf("load scan auth metadata: %w", err)
	}
	if sc.SessionID.Empty() {
		return false, nil
	}
	sess, err := st.Sessions().Get(ctx, sc.SessionID)
	if errors.Is(err, store.ErrNotFound) {
		// The scan records a session dependency but its metadata is gone; do
		// not silently turn an unknown session into a public one-click PoC.
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("load scan session metadata: %w", err)
	}
	if sess == nil || sess.ScanID != scanID {
		return true, nil
	}
	return sess.Mode != domain.AuthAnonymous, nil
}

func nonFocusDynamicParams(params []*domain.Parameter, focusA, focusB *domain.Parameter) []*domain.Parameter {
	var out []*domain.Parameter
	for _, p := range params {
		if p == nil || (focusA != nil && p.ID == focusA.ID) || (focusB != nil && p.ID == focusB.ID) {
			continue
		}
		if isDynamicTokenName(p.Name) {
			out = append(out, p)
		}
	}
	return out
}

func dynamicTokenNames(params []*domain.Parameter) []string {
	set := make(map[string]struct{}, len(params))
	for _, p := range params {
		if p != nil {
			set[p.Name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func dynamicTokenPlaceholder(name string) string { return "FRESH_" + name + "_VALUE" }

// redactDynamicTokenValues edits only non-focus dynamic-token parameters in
// the rendered request. Values are replaced in the request's own encoding
// (URL/form/JSON/header/cookie), so neither the stale value nor a misleading
// stale hidden field reaches the downloadable artifact.
func redactDynamicTokenValues(req *httpengine.Request, params []*domain.Parameter) error {
	if len(params) == 0 {
		return nil
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return err
	}
	query := u.Query()
	var form url.Values
	formLoaded := false
	var jsonBody map[string]json.RawMessage
	jsonLoaded := false

	for _, p := range params {
		if p == nil || !isDynamicTokenName(p.Name) {
			continue
		}
		placeholder := dynamicTokenPlaceholder(p.Name)
		switch p.Location {
		case domain.LocationQuery:
			query.Set(p.Name, placeholder)
		case domain.LocationPath:
			if idx, ok := discovery.ParsePathSegmentParamName(p.Name); ok {
				segments := discovery.PathSegments(u.Path)
				if idx >= 0 && idx < len(segments) {
					segments[idx] = placeholder
					u.Path = discovery.JoinPathSegments(segments)
					u.RawPath = ""
				}
			}
		case domain.LocationForm:
			if !formLoaded {
				form, err = url.ParseQuery(string(req.Body))
				if err != nil {
					return fmt.Errorf("parse form body: %w", err)
				}
				formLoaded = true
			}
			form.Set(p.Name, placeholder)
		case domain.LocationJSON:
			if !jsonLoaded {
				if err := json.Unmarshal(req.Body, &jsonBody); err != nil {
					return fmt.Errorf("parse JSON body: %w", err)
				}
				if jsonBody == nil {
					jsonBody = make(map[string]json.RawMessage)
				}
				jsonLoaded = true
			}
			encoded, err := json.Marshal(placeholder)
			if err != nil {
				return err
			}
			jsonBody[p.Name] = encoded
		case domain.LocationHeader:
			for name := range req.Headers {
				if strings.EqualFold(name, p.Name) {
					req.Headers[name] = placeholder
				}
			}
		case domain.LocationCookie:
			for _, cookie := range req.Cookies {
				if cookie != nil && cookie.Name == p.Name {
					cookie.Value = placeholder
				}
			}
			for name, value := range req.Headers {
				if strings.EqualFold(name, "Cookie") {
					req.Headers[name] = redactCookieHeader(value, p.Name, placeholder)
				}
			}
		}
	}

	u.RawQuery = query.Encode()
	req.URL = u.String()
	if formLoaded {
		req.Body = []byte(form.Encode())
	}
	if jsonLoaded {
		encoded, err := json.Marshal(jsonBody)
		if err != nil {
			return err
		}
		req.Body = encoded
	}
	return nil
}

func redactCookieHeader(header, cookieName, placeholder string) string {
	parts := strings.Split(header, ";")
	for i, part := range parts {
		name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name == cookieName {
			parts[i] = name + "=" + placeholder
		}
	}
	return strings.Join(parts, ";")
}

// findCandidateForAttempt resolves the verified attempt's full candidate
// record (which carries Location/ParameterB/LocationB/ValueB — fields the
// lighter-weight verificationAttempt does not) from the finding's own
// Detail.Candidates, matched by dedup key (the stable identity every
// planned candidate carries) and falling back to a value match, then to
// the sole candidate when there is exactly one — defensive, not expected to
// be needed, since appendUniqueCandidate always records every distinct
// candidate that reached correlation.
func findCandidateForAttempt(cands []detection.Candidate, att *verificationAttempt) *detection.Candidate {
	for i := range cands {
		if att.CandidateDedupKey != "" && cands[i].DedupKey == att.CandidateDedupKey {
			c := cands[i]
			return &c
		}
	}
	for i := range cands {
		if cands[i].Value == att.CandidateValue {
			c := cands[i]
			return &c
		}
	}
	if len(cands) == 1 {
		c := cands[0]
		return &c
	}
	return nil
}

// allLinkable reports whether every location in locs, for method, is fully
// carryable by a static HTML artifact with no further operator action:
// Query/Path (a plain link — the override is already part of the URL) or
// Form on a POST request (an auto-submitting <form>, see pocFormFields).
// Header, Cookie, and JSON never are — see the file doc comment.
func allLinkable(locs []domain.ParamLocation, method domain.HTTPMethod) bool {
	for _, loc := range locs {
		switch loc {
		case domain.LocationQuery, domain.LocationPath:
			continue
		case domain.LocationForm:
			if method != domain.MethodPOST {
				return false
			}
			continue
		default: // Header, Cookie, JSON, or anything unrecognized
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

const pocCSS = `<style>
body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:860px;margin:2em auto;padding:0 1em;line-height:1.5;color:#1a1a1a}
h1{font-size:1.3em} h2{font-size:1.05em;margin-top:1.6em;border-top:1px solid #ddd;padding-top:1em}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace}
pre{background:#f4f4f4;padding:0.8em;border-radius:4px;overflow-wrap:anywhere;white-space:pre-wrap}
.meta{color:#555;font-size:0.95em} .warn{color:#8a5300;background:#fff6e5;padding:0.6em;border-radius:4px}
.warn-block{color:#7a1313;background:#fdecec;padding:0.8em 1em;border-radius:4px;margin:1em 0}
button{font-size:1em;padding:0.5em 1em;cursor:pointer}
</style>`

// renderPoCHTML builds the standalone HTML artifact. It never embeds a
// candidate/payload value inside a <script> block (which would need
// JavaScript-string escaping on top of HTML escaping, a needless extra
// escaping surface); the one-click mechanisms are a <meta> refresh (GET/
// Path/Query — needs no JavaScript at all) and a plain-id form.submit()
// call that references the form only by its static id (POST+Form) — see
// internal/browser/playwright.go's formHTML, the same technique.
func renderPoCHTML(p *PoC, req *httpengine.Request) []byte {
	var b bytes.Buffer
	b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	fmt.Fprintf(&b, "<title>Indago PoC — finding %s</title>\n", html.EscapeString(string(p.FindingID)))
	isGetLike := p.OneClick && p.Method != domain.MethodPOST
	if isGetLike {
		fmt.Fprintf(&b, `<meta http-equiv="refresh" content="0; url=%s">`+"\n", html.EscapeString(req.URL))
	}
	b.WriteString(pocCSS)
	b.WriteString("</head>\n")

	bodyAttr := ""
	if p.OneClick && p.Method == domain.MethodPOST {
		bodyAttr = ` onload="document.getElementById('indago-poc-form').submit()"`
	}
	fmt.Fprintf(&b, "<body%s>\n", bodyAttr)

	b.WriteString("<h1>Indago — Reflected XSS Proof of Concept</h1>\n")
	fmt.Fprintf(&b, "<p class=\"meta\">Finding <code>%s</code> — <strong>Verdict: Confirmed</strong>. ",
		html.EscapeString(string(p.FindingID)))
	switch {
	case p.RequestTemplate:
		b.WriteString("This is a request template—not an exact runnable request. Replace the fresh CSRF/session placeholders before replay.</p>\n")
	case p.OneClick:
		b.WriteString("This exact request is the one Indago's browser verification confirmed executes; it is based only on the confirmed finding.</p>\n")
	default:
		b.WriteString("The request details and equivalent curl command below reproduce the confirmed request; this HTML stays inert because the request uses a carrier a browser link/form cannot set.</p>\n")
	}
	fmt.Fprintf(&b, "<p class=\"meta\">Parameter: <code>%s</code> (%s)%s</p>\n",
		html.EscapeString(p.Parameter), html.EscapeString(string(p.Location)), combinedNote(p))

	if p.OneClick {
		switch {
		case p.Method == domain.MethodPOST:
			b.WriteString(pocFormFields(req))
			b.WriteString("<p>Opening this file auto-submits a real POST request to the target — " +
				"the same technique Indago's own browser verifier uses for POST verification " +
				"(<code>browser.Page.NavigateForm</code>, a throwaway auto-submitting hidden &lt;form&gt;). " +
				"If your browser blocked the automatic submission, click the button below.</p>\n")
			b.WriteString(`<p><button type="button" onclick="document.getElementById('indago-poc-form').submit()">Submit PoC request</button></p>` + "\n")
		default:
			b.WriteString("<p>Opening this file navigates straight to the exploit URL below — one click, no further action. " +
				"If your browser did not redirect automatically, use the link.</p>\n")
			fmt.Fprintf(&b, `<p><a id="poc-link" href="%s">%s</a></p>`+"\n", html.EscapeString(req.URL), html.EscapeString(req.URL))
		}
	} else {
		b.WriteString(pocNotOneClickExplanation(p))
	}

	b.WriteString(pocRequestDetails(req, p.RequestTemplate))
	fmt.Fprintf(&b, "<h2>Equivalent curl command</h2>\n<pre>%s</pre>\n", html.EscapeString(curlCommand(req, p.AuthenticatedSession)))
	b.WriteString("</body></html>\n")
	return b.Bytes()
}

func combinedNote(p *PoC) string {
	if !p.Combined {
		return ""
	}
	return fmt.Sprintf(" + <code>%s</code> (%s) — <strong>⚠ combined (multi-parameter) finding</strong>: BOTH overrides must be in the SAME request, not single-parameter bugs individually; this artifact carries both.",
		html.EscapeString(p.ParameterB), html.EscapeString(string(p.LocationB)))
}

// pocFormFields renders the auto-submit form's hidden inputs from the
// already-built request's form-encoded body, mirroring
// internal/browser/playwright.go's formHTML exactly (same id, same
// attribute-value escaping of the exact byte value — this is well-
// formedness, not filtering: the candidate's own characters are preserved
// byte for byte, e.g. a literal `"` becomes `&#34;` so the attribute stays
// well-formed but still carries the same value when the form submits).
func pocFormFields(req *httpengine.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<form id="indago-poc-form" method="post" action="%s">`+"\n", html.EscapeString(req.URL))
	if vals, err := url.ParseQuery(string(req.Body)); err == nil {
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range vals[k] {
				fmt.Fprintf(&b, `<input type="hidden" name="%s" value="%s">`+"\n", html.EscapeString(k), html.EscapeString(v))
			}
		}
	}
	b.WriteString("</form>\n")
	return b.String()
}

// pocNotOneClickExplanation is rendered instead of any auto-navigating
// mechanism when OneClick is false. It deliberately does nothing by
// itself — see the file doc comment on why no HTML trick can carry a
// Header/Cookie/JSON override, so pretending otherwise would silently fail
// to reproduce the real bug.
func pocNotOneClickExplanation(p *PoC) string {
	var reasons []string
	locs := []domain.ParamLocation{p.Location}
	if p.Combined {
		locs = append(locs, p.LocationB)
	}
	seen := map[domain.ParamLocation]bool{}
	for _, loc := range locs {
		if seen[loc] {
			continue
		}
		seen[loc] = true
		switch loc {
		case domain.LocationHeader:
			reasons = append(reasons, "a plain navigation, link, or form submission cannot set an arbitrary request header — browsers only allow a fixed, small set of headers on cross-context requests, and this finding's override lives in a request header")
		case domain.LocationCookie:
			reasons = append(reasons, "a static PoC page cannot set a cookie for a DIFFERENT origin than its own (the browser's same-origin policy), and this finding's override lives in a cookie belonging to the target's own domain")
		case domain.LocationJSON:
			reasons = append(reasons, "no HTML form can carry an application/json request body, and this finding's override lives in a JSON body field")
		}
	}
	if p.AuthenticatedSession {
		reasons = append(reasons, "this scan used a non-anonymous authenticated session; its session cookies are intentionally not embedded")
	}
	if len(p.DynamicTokenNames) > 0 {
		reasons = append(reasons, fmt.Sprintf("non-focus dynamic token parameter(s) %s have their captured values redacted", strings.Join(p.DynamicTokenNames, ", ")))
	}
	var b strings.Builder
	b.WriteString(`<div class="warn-block">` + "\n")
	b.WriteString("<h2>⚠ No one-click PoC is possible for this finding</h2>\n<p>")
	b.WriteString(html.EscapeString(strings.Join(reasons, "; and ")))
	if p.RequestTemplate {
		b.WriteString(". This is a request template, not an exact runnable request. ")
		if p.AuthenticatedSession {
			b.WriteString("Use your own authorized authenticated session; session cookies are not embedded. Set <code>INDAGO_COOKIE_JAR</code> to your own authorized cookie-jar file for curl. ")
		} else {
			b.WriteString("If the target requires authentication, use your own authorized authenticated session; session cookies are not embedded. ")
		}
		b.WriteString("Before replay, refresh current CSRF token(s) from the token-issuing page. Token refresh is manual; PoC generation does not contact the target. Replace the fresh CSRF/session placeholders before replay.</p>\n")
		b.WriteString("</div>\n")
		return b.String()
	}
	b.WriteString(". Opening this file does nothing by itself — it is intentionally inert rather than silently claiming to reproduce a request it cannot actually send. Use the exact HTTP request below, or the curl command, to reproduce this finding.</p>\n")
	b.WriteString("</div>\n")
	return b.String()
}

// pocRequestDetails labels a fully observed request as exact and a request
// with auth/CSRF placeholders as a template. Values remain escaped text, never
// active markup.
func pocRequestDetails(req *httpengine.Request, requestTemplate bool) string {
	var b strings.Builder
	if requestTemplate {
		b.WriteString("<h2>Request template — replace fresh CSRF/session placeholders</h2>\n<pre>")
	} else {
		b.WriteString("<h2>Exact HTTP request this reproduces</h2>\n<pre>")
	}
	fmt.Fprintf(&b, "%s %s\n", html.EscapeString(req.Method), html.EscapeString(req.URL))
	keys := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", html.EscapeString(k), html.EscapeString(req.Headers[k]))
	}
	if req.ContentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", html.EscapeString(req.ContentType))
	}
	for _, c := range req.Cookies {
		fmt.Fprintf(&b, "Cookie: %s=%s\n", html.EscapeString(c.Name), html.EscapeString(c.Value))
	}
	if len(req.Body) > 0 {
		b.WriteString("\n")
		b.WriteString(html.EscapeString(string(req.Body)))
		b.WriteString("\n")
	}
	b.WriteString("</pre>\n")
	return b.String()
}

// curlCommand renders req as a runnable curl command. For authenticated
// scans it refers only to an operator-provided cookie jar, never saved state.
func curlCommand(req *httpengine.Request, authenticated bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "curl -i -X %s %s", req.Method, shellQuote(req.URL))
	keys := make([]string, 0, len(req.Headers))
	for k := range req.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " \\\n  -H %s", shellQuote(k+": "+req.Headers[k]))
	}
	if authenticated {
		fmt.Fprintf(&b, " \\\n  -b \"$INDAGO_COOKIE_JAR\"")
	}
	for _, c := range req.Cookies {
		if c != nil {
			fmt.Fprintf(&b, " \\\n  -b %s", shellQuote(c.Name+"="+c.Value))
		}
	}
	if req.ContentType != "" {
		fmt.Fprintf(&b, " \\\n  -H %s", shellQuote("Content-Type: "+req.ContentType))
	}
	if len(req.Body) > 0 {
		fmt.Fprintf(&b, " \\\n  --data-raw %s", shellQuote(string(req.Body)))
	}
	return b.String()
}

// shellQuote wraps s in single quotes, escaping any embedded single quote —
// safe for the common POSIX shells (bash/zsh/sh) the generated curl command
// is meant to be pasted into.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

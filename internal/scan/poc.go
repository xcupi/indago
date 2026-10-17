package scan

// This file generates a standalone, browser-openable Proof-of-Concept (PoC)
// artifact for a CONFIRMED reflected-XSS Finding. It is purely presentation
// over data the scan already produced — reusing the SAME request-building
// logic (buildRequest) and the SAME POST-navigation technique the browser
// verifier itself uses (browser.Page.NavigateForm's auto-submitting hidden
// <form>, see internal/browser/playwright.go's formHTML) rather than
// reinventing either. No new detection/exploitation logic: the candidate
// value and request shape are replayed byte-for-byte exactly like browser
// verification already did (AGENTS.md §2–§3 are untouched by this file).
//
// Evidence integrity (AGENTS.md §2.6): a PoC may be generated ONLY for a
// Finding whose STORED Verdict is Confirmed — generating one for a Pending/
// Rejected/Inconclusive finding would fabricate evidence of a vulnerability
// that was never actually confirmed. See GeneratePoC's guard, enforced
// before anything else runs.
//
// Faithfulness over polish: a Query/Path override is fully carried by a
// plain link, and a POST+form-encoded override by an auto-submitting
// <form> — both are TRUE one-click reproductions opened directly in any
// browser. A Header or Cookie override is NOT, and no HTML trick changes
// that: a plain navigation/form submission cannot set an arbitrary request
// header (the "forbidden header name" rules every browser enforces), and a
// static page on an unrelated origin cannot set a cookie for the target's
// origin (same-origin policy — document.cookie only affects the page's OWN
// origin). For those, GeneratePoC refuses to render a fake auto-navigating
// artifact that would silently fail to reproduce the real bug: the HTML
// says so explicitly and gives the exact HTTP request and curl command
// instead. A POST+JSON override is likewise never one-click (no HTML form
// can carry an application/json body) — and, per the documented standing
// limitation that a POST+JSON candidate can never be browser-verified, can
// never actually reach GeneratePoC on a real Confirmed finding; handled
// defensively here rather than assumed.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/detection"
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
	// OneClick is true when the generated HTML, opened directly in a
	// browser with no further action, fully reproduces the confirmed
	// request (every override is Query/Path/Form). False when a Header,
	// Cookie, or JSON override is involved — the HTML still documents the
	// exact request and a working curl command, but intentionally does
	// NOT auto-navigate/auto-submit, since doing so would not actually
	// carry that override (see file doc comment).
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

	inj := &injection{param: focusA, value: cand.Value}
	if focusB != nil {
		inj.paramB, inj.valueB = focusB, cand.ValueB
	}
	// Reuse the EXACT request-building logic the candidate step and
	// browser verification already used — the same function, the same
	// other-parameters-at-observed-value behavior, never a re-derivation
	// that could silently drift from what was actually confirmed.
	req, err := buildRequest(ep, params, inj)
	if err != nil {
		return nil, fmt.Errorf("poc: rebuild the exact confirmed request: %w", err)
	}

	p := &PoC{
		FindingID: f.ID, Method: ep.Method, URL: req.URL,
		Parameter: focusA.Name, Location: focusA.Location,
	}
	locs := []domain.ParamLocation{focusA.Location}
	if cand.Combined {
		p.Combined = true
		p.ParameterB, p.LocationB = cand.ParameterB, cand.LocationB
		locs = append(locs, focusB.Location)
	}
	p.OneClick = allLinkable(locs, ep.Method)
	p.HTML = renderPoCHTML(p, req)
	return p, nil
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
	fmt.Fprintf(&b, "<p class=\"meta\">Finding <code>%s</code> — <strong>Verdict: Confirmed</strong> "+
		"(this artifact replays the exact request Indago's own browser verification already confirmed executes; it fabricates nothing new).</p>\n",
		html.EscapeString(string(p.FindingID)))
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

	b.WriteString(pocRequestDetails(req))
	fmt.Fprintf(&b, "<h2>Equivalent curl command</h2>\n<pre>%s</pre>\n", html.EscapeString(curlCommand(req)))
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
	var b strings.Builder
	b.WriteString(`<div class="warn-block">` + "\n")
	b.WriteString("<h2>⚠ No one-click PoC is possible for this finding</h2>\n<p>")
	b.WriteString(html.EscapeString(strings.Join(reasons, "; and ")))
	b.WriteString(". Opening this file does nothing by itself — it is intentionally inert rather than silently claiming to reproduce a request it cannot actually send. " +
		"Use the exact HTTP request below, or the curl command, to reproduce this finding.</p>\n")
	b.WriteString("</div>\n")
	return b.String()
}

// pocRequestDetails renders the exact HTTP request this PoC reproduces as
// plain, escaped text — useful on its own, and the same information the
// curl command below encodes as a runnable command.
func pocRequestDetails(req *httpengine.Request) string {
	var b strings.Builder
	b.WriteString("<h2>Exact HTTP request this reproduces</h2>\n<pre>")
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

// curlCommand renders req as a runnable curl command — the fallback that is
// always correct regardless of location (headers and cookies a browser
// link/form cannot carry are trivial for curl to set directly).
func curlCommand(req *httpengine.Request) string {
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
	if len(req.Cookies) > 0 {
		parts := make([]string, 0, len(req.Cookies))
		for _, c := range req.Cookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		fmt.Fprintf(&b, " \\\n  -b %s", shellQuote(strings.Join(parts, "; ")))
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

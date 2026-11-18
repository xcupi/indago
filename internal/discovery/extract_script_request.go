package discovery

import (
	"regexp"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// Bounded, static harvesting of the request shapes a page's own inline
// JavaScript declares with literal arguments.
//
// Why static: the browser only reports requests it actually observed during
// the observation window. A page that binds its XML or JSON call to a button
// click, a condition that never holds during a crawl, or a timer longer than
// the window is invisible to network capture — so its real endpoint, and the
// request body only that endpoint accepts, is never registered. Engines that
// key on an observed body (XXE above all) then have nothing to probe, even
// though the page itself declares the endpoint and its content type.
//
// Two canonical declaration shapes are recognized, both with literal arguments
// only:
//
//	var x = new XMLHttpRequest();
//	x.open("POST", "/api/thing");
//	x.setRequestHeader("Content-Type", "application/soap+xml");
//	x.send("<envelope/>");
//
//	fetch("/api/thing", {method: "POST",
//	  headers: {"Content-Type": "text/xml"}, body: "<envelope/>"});
//
// Anything computed at runtime (a variable URL, a template literal, a
// JSON.stringify body) is skipped: guessing what it evaluates to would create
// endpoints and bodies the application never declared. jQuery's $.ajax is not
// recognized either; its option bag is the same shape as fetch's but its call
// forms vary too much to parse with the same bounded rules.
//
// Two entry points share one parser:
//
//   - ExtractScriptRequests reads a DOCUMENT and parses each inline <script>
//     body. This is what a server-rendered page needs.
//   - ExtractScriptRequestsFromJS reads one raw JavaScript SOURCE (an external
//     SPA bundle) with no <script> wrapper to unwrap. A modern SPA declares its
//     API calls in the bundle it ships, not in the HTML shell, so the browser
//     never reports a fetch bound to a click and the crawler's path-literal
//     scan (ExtractScriptEndpointLiterals) only sees bare GET paths. Reading
//     the declaration recovers the method and body the bundle itself declares.
//
// A bundle is read from a body the caller already fetched for its route
// harvest, so this adds no request of its own. The per-source cap
// (maxScriptRequests) bounds how much one bundle can contribute, and callers
// only inspect the same small, non-vendor bundle set they already fetch.
//
// Nothing here sends a request or decides anything: the result is discovery
// input. The collector scope-checks and deduplicates every candidate, and the
// executor's state-changing opt-ins still decide whether a body-carrying
// request may ever be sent.
const (
	// maxScriptRequests bounds how many declarations one page may contribute.
	maxScriptRequests = 8
	// maxScriptRequestURLLen rejects minified blobs and embedded data.
	maxScriptRequestURLLen = 2048
	// maxScriptRequestOptsLen bounds the options object read after fetch(url, {.
	maxScriptRequestOptsLen = 4096
	// maxScriptRequestBodyLen bounds a literal body; the collector caps the
	// stored value again (maxEndpointRequestBody).
	maxScriptRequestBodyLen = 8192
)

// ScriptRequest is one request shape declared in a page's inline script.
type ScriptRequest struct {
	// URL is the declared target, exactly as written (relative values are
	// resolved by the caller against the page URL).
	URL string
	// Method is the declared HTTP method.
	Method domain.HTTPMethod
	// ContentType is the declared request content type, when the script sets
	// one explicitly ("" otherwise).
	ContentType string
	// Body is the declared request body literal, when one is declared.
	Body string
}

var (
	// scriptXHRHandleRE finds the handle a script assigns an XMLHttpRequest to.
	// The assignment itself is optional in JavaScript (bWAPP's lesson assigns a
	// var-less global), so no var/let/const keyword is required.
	scriptXHRHandleRE = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+XMLHttpRequest\s*\(`)

	// scriptFetchRE finds fetch(url, ...) with a literal first argument.
	scriptFetchRE = regexp.MustCompile(`\bfetch\s*\(\s*("[^"]*"|'[^']*')`)

	// scriptFetchMethodRE / scriptFetchContentTypeRE / scriptFetchBodyRE read
	// literal members of a fetch options object.
	scriptFetchMethodRE      = regexp.MustCompile(`\bmethod\s*:\s*("[^"]*"|'[^']*')`)
	scriptFetchContentTypeRE = regexp.MustCompile(`(?i)(?:"content-type"|'content-type'|content-type)\s*:\s*("[^"]*"|'[^']*')`)
	scriptFetchBodyRE        = regexp.MustCompile(`\bbody\s*:\s*("[^"]*"|'[^']*')`)
)

// scriptRequestSet accumulates parsed shapes under the extractor's shared cap
// and dedup rule, so both entry points behave identically.
type scriptRequestSet struct {
	out  []ScriptRequest
	seen map[string]struct{}
}

func (s *scriptRequestSet) full() bool { return len(s.out) >= maxScriptRequests }

func (s *scriptRequestSet) add(req ScriptRequest) {
	if s.full() {
		return
	}
	req = sanitizeScriptRequest(req)
	if req.URL == "" || !req.Method.IsValid() {
		return
	}
	key := string(req.Method) + " " + req.URL
	if _, dup := s.seen[key]; dup {
		return
	}
	s.seen[key] = struct{}{}
	s.out = append(s.out, req)
}

// collectSource parses one JavaScript source text — an inline <script> body or
// a whole external bundle — for XHR/fetch declarations. It is the single
// parsing path both extractors use.
func (s *scriptRequestSet) collectSource(script string) {
	for _, m := range scriptXHRHandleRE.FindAllStringSubmatch(script, maxScriptMatches) {
		if s.full() {
			return
		}
		if req, ok := scriptXHRRequest(script, m[1]); ok {
			s.add(req)
		}
	}
	for _, req := range scriptFetchRequests(script) {
		if s.full() {
			return
		}
		s.add(req)
	}
}

// ExtractScriptRequests returns the request shapes a document's inline scripts
// declare with literal arguments, in source order and deduplicated by method +
// URL. It is bounded and syntax-light: an unparseable or computed call is
// skipped rather than guessed at.
func ExtractScriptRequests(body string) []ScriptRequest {
	if body == "" {
		return nil
	}
	set := &scriptRequestSet{seen: make(map[string]struct{}, maxScriptRequests)}
	for _, block := range scriptBlockRE.FindAllStringSubmatch(body, maxScriptBlocks) {
		if set.full() {
			break
		}
		set.collectSource(block[1])
	}
	return set.out
}

// ExtractScriptRequestsFromJS returns the request shapes one raw JavaScript
// source declares with literal arguments — the same bounded XHR/fetch parse as
// ExtractScriptRequests, without requiring <script> tags. It exists for
// external SPA bundles, where the application's API calls live and the page's
// HTML shell carries none of them.
//
// The caller is expected to hand it a body it already fetched for another
// purpose (route-literal mining), and to respect its own per-bundle and
// per-render caps. Like the document extractor, it registers nothing and sends
// nothing.
func ExtractScriptRequestsFromJS(js string) []ScriptRequest {
	if js == "" {
		return nil
	}
	set := &scriptRequestSet{seen: make(map[string]struct{}, maxScriptRequests)}
	set.collectSource(js)
	return set.out
}

// scriptXHRRequest reads one XMLHttpRequest handle's open/setRequestHeader/send
// calls. A handle with no literal open(method, url) yields nothing.
func scriptXHRRequest(script, handle string) (ScriptRequest, bool) {
	openRE := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(handle) +
		`\s*\.\s*open\s*\(\s*("[^"]*"|'[^']*')\s*,\s*("[^"]*"|'[^']*')`)
	m := openRE.FindStringSubmatch(script)
	if m == nil {
		return ScriptRequest{}, false
	}
	method := domain.HTTPMethod(strings.ToUpper(unquoteScriptLiteral(m[1])))
	req := ScriptRequest{Method: method, URL: unquoteScriptLiteral(m[2])}
	if !req.Method.IsValid() {
		return ScriptRequest{}, false
	}

	headerRE := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(handle) +
		`\s*\.\s*setRequestHeader\s*\(\s*("[^"]*"|'[^']*')\s*,\s*("[^"]*"|'[^']*')`)
	for _, h := range headerRE.FindAllStringSubmatch(script, maxScriptMatches) {
		// Last one wins, matching the browser: a later setRequestHeader with
		// the same name replaces the earlier value.
		if strings.EqualFold(unquoteScriptLiteral(h[1]), "content-type") {
			req.ContentType = unquoteScriptLiteral(h[2])
		}
	}

	sendRE := regexp.MustCompile(`(?s)\b` + regexp.QuoteMeta(handle) +
		`\s*\.\s*send\s*\(\s*("[^"]*"|'[^']*')`)
	if s := sendRE.FindStringSubmatch(script); s != nil {
		req.Body = unquoteScriptLiteral(s[1])
	}
	return req, true
}

// scriptFetchRequests reads every literal fetch(url, options) call in a block.
func scriptFetchRequests(script string) []ScriptRequest {
	locs := scriptFetchRE.FindAllStringSubmatchIndex(script, maxScriptMatches)
	if len(locs) == 0 {
		return nil
	}
	out := make([]ScriptRequest, 0, len(locs))
	for _, loc := range locs {
		req := ScriptRequest{Method: domain.MethodGET, URL: unquoteScriptLiteral(script[loc[2]:loc[3]])}
		// Options, when present, are the object immediately following the URL
		// as the second argument. Requiring that shape (instead of scanning for
		// any later '{') keeps an unrelated block from being read as options.
		rest := strings.TrimLeft(script[loc[1]:], " 	\r\n")
		if strings.HasPrefix(rest, ",") {
			rest = strings.TrimLeft(rest[1:], " 	\r\n")
			if strings.HasPrefix(rest, "{") {
				start := len(script) - len(rest)
				if obj, ok := scriptBalancedObject(script, start, maxScriptRequestOptsLen); ok {
					if m := scriptFetchMethodRE.FindStringSubmatch(obj); m != nil {
						req.Method = domain.HTTPMethod(strings.ToUpper(unquoteScriptLiteral(m[1])))
					}
					if m := scriptFetchContentTypeRE.FindStringSubmatch(obj); m != nil {
						req.ContentType = unquoteScriptLiteral(m[1])
					}
					if m := scriptFetchBodyRE.FindStringSubmatch(obj); m != nil {
						req.Body = unquoteScriptLiteral(m[1])
					}
				}
			}
		}
		if !req.Method.IsValid() {
			continue
		}
		out = append(out, req)
	}
	return out
}

// sanitizeScriptRequest enforces the extractor's bounds and drops a shape that
// cannot be replayed: an empty or oversized URL, a non-http(s) scheme, or a
// method no request can carry.
func sanitizeScriptRequest(req ScriptRequest) ScriptRequest {
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" || len(req.URL) > maxScriptRequestURLLen {
		return ScriptRequest{}
	}
	if req.Method == "" {
		req.Method = domain.MethodGET
	}
	// A scheme prefix is only a scheme when it is not part of a relative path,
	// a query value or a fragment (e.g. "/a?next=b:c" stays relative).
	if !strings.HasPrefix(req.URL, "/") && !strings.HasPrefix(req.URL, ".") && !strings.HasPrefix(req.URL, "?") {
		if i := strings.IndexByte(req.URL, ':'); i > 0 && !strings.ContainsAny(req.URL[:i], "/?#") {
			scheme := strings.ToLower(req.URL[:i])
			if scheme != "http" && scheme != "https" {
				return ScriptRequest{}
			}
		}
	}
	if len(req.ContentType) > 256 {
		req.ContentType = ""
	}
	// A backslash means the literal uses a JavaScript escape sequence, so the
	// raw text between the quotes is NOT the string the page sends. Rather than
	// replay a guessed value, keep the endpoint and drop the ambiguous part.
	if strings.ContainsRune(req.URL, '\\') {
		return ScriptRequest{}
	}
	if len(req.Body) > maxScriptRequestBodyLen || strings.ContainsRune(req.Body, '\\') {
		req.Body = ""
	}
	// A GET/HEAD body is not a request shape this scanner replays: form, JSON
	// and XML bodies all travel on a body-carrying method.
	if req.Method == domain.MethodGET || req.Method == domain.MethodHEAD {
		req.Body, req.ContentType = "", ""
	}
	return req
}

// unquoteScriptLiteral strips the matching quotes of a JavaScript string
// literal. A value without quotes is returned unchanged.
func unquoteScriptLiteral(raw string) string {
	if len(raw) < 2 {
		return raw
	}
	first, last := raw[0], raw[len(raw)-1]
	if (first == '"' || first == '\'') && first == last {
		return raw[1 : len(raw)-1]
	}
	return raw
}

// scriptBalancedObject returns the balanced {...} object that starts at s[open]
// (which must be '{'), bounded to maxLen bytes. Braces inside string literals
// are not counted, and a nested headers/params object is part of the extent.
func scriptBalancedObject(s string, open, maxLen int) (string, bool) {
	if open < 0 || open >= len(s) || s[open] != '{' {
		return "", false
	}
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		if i-open > maxLen {
			return "", false
		}
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[open : i+1], true
			}
		}
	}
	return "", false
}

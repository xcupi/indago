package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"strings"
	"sync"
	"time"

	pw "github.com/mxschmitt/playwright-go"
)

// IsTimeout reports whether err represents a navigation/action timeout — either
// the context's own deadline or the browser engine's own timeout (Playwright's
// TimeoutError). It is a neutral classification, like the rest of this package:
// it says what kind of error occurred, never whether anything is exploitable.
// Playwright is intentionally confined to this file; callers elsewhere (e.g.
// internal/verification) use this instead of depending on playwright-go
// directly.
func IsTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, pw.ErrTimeout)
}

// This file is the real, Chromium-via-Playwright implementation of the driver
// abstraction. It is compiled by default; integration tests that actually launch
// a browser are gated behind the `browser_integration` build tag.

// newPlaywrightDriver starts a Playwright engine.
// exe, when non-empty, is the Chromium binary to launch. disableSandbox is the
// operator's explicit opt-out of Chromium's process sandbox; the zero value
// keeps it ON.
func newPlaywrightDriver(exe string, disableSandbox bool) (driver, error) {
	p, err := pw.Run()
	if err != nil {
		return nil, fmt.Errorf("run playwright (install the driver: go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 --version): %w", err)
	}
	return &pwDriver{pw: p, exe: exe, disableSandbox: disableSandbox}, nil
}

type pwDriver struct {
	pw             *pw.Playwright
	exe            string
	disableSandbox bool
}

func (d *pwDriver) Launch(headless bool) (browserHandle, error) {
	// Playwright adds --no-sandbox unless chromiumSandbox is exactly true, so
	// the sandbox must be requested explicitly: leaving the option unset would
	// silently disable it.
	opts := pw.BrowserTypeLaunchOptions{
		Headless:        pw.Bool(headless),
		ChromiumSandbox: pw.Bool(!d.disableSandbox),
	}
	if d.exe != "" {
		opts.ExecutablePath = pw.String(d.exe)
	}
	b, err := d.pw.Chromium.Launch(opts)
	if err != nil {
		return nil, err
	}
	return &pwBrowser{b: b}, nil
}

func (d *pwDriver) Stop() error { return d.pw.Stop() }

type pwBrowser struct{ b pw.Browser }

func (b *pwBrowser) NewContext(storageStatePath, proxyServer string, extraHeaders map[string]string, allow func(string) bool) (contextHandle, error) {
	opts := pw.BrowserNewContextOptions{}
	if storageStatePath != "" {
		opts.StorageStatePath = pw.String(storageStatePath)
	}
	if proxyServer != "" {
		opts.Proxy = &pw.Proxy{Server: proxyServer}
	}
	if len(extraHeaders) > 0 {
		opts.ExtraHttpHeaders = extraHeaders
	}
	c, err := b.b.NewContext(opts)
	if err != nil {
		return nil, err
	}
	pc := &pwContext{c: c, allow: allow}
	if allow != nil {
		// Abort directly disallowed requests before they leave the browser.
		// Playwright's route callback only sees the original request in an HTTP
		// redirect chain, so each managed page also installs a CDP response-stage
		// gate that checks Location before Chromium follows any redirect.
		if err := c.Route("**/*", pc.onRoute); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("install scope gate and request override: %w", err)
		}
	}
	return pc, nil
}

func (b *pwBrowser) Close() error { return b.b.Close() }

type jsonNavigationOverride struct {
	url         string
	body        []byte
	contentType string
	timeout     time.Duration
	applied     bool
	err         error
}

type pwContext struct {
	c     pw.BrowserContext
	allow func(string) bool

	mu           sync.Mutex
	jsonOverride *jsonNavigationOverride
}

func (c *pwContext) onRoute(route pw.Route) {
	req := route.Request()
	rawURL := req.URL()
	if c.allow != nil && isNetworkURL(rawURL) && !c.allow(rawURL) {
		_ = route.Abort("blockedbyclient")
		return
	}
	override := c.takeJSONNavigationOverride(req)
	if override == nil {
		_ = route.Continue()
		return
	}
	headers, err := req.AllHeaders()
	if err != nil {
		c.failJSONNavigationOverride(override, fmt.Errorf("read navigation headers: %w", err))
		_ = route.Abort()
		return
	}
	if headers == nil {
		headers = map[string]string{}
	}
	delete(headers, "content-length")
	delete(headers, "transfer-encoding")
	if _, ok := headers["content-type"]; !ok {
		headers["content-type"] = override.contentType
	}
	method := "POST"
	maxRedirects := 0
	timeoutMS := float64(override.timeout.Milliseconds())
	response, err := route.Fetch(pw.RouteFetchOptions{
		Method: &method, PostData: override.body, Headers: headers,
		MaxRedirects: &maxRedirects, Timeout: &timeoutMS,
	})
	if err != nil {
		c.failJSONNavigationOverride(override, fmt.Errorf("fetch JSON navigation response: %w", err))
		_ = route.Abort()
		return
	}
	defer func() { _ = response.Dispose() }()
	status := response.Status()
	body, err := response.Body()
	if err != nil {
		c.failJSONNavigationOverride(override, fmt.Errorf("read JSON navigation response: %w", err))
		_ = route.Abort()
		return
	}
	responseHeaders := response.Headers()
	delete(responseHeaders, "content-length")
	delete(responseHeaders, "content-encoding")
	delete(responseHeaders, "transfer-encoding")
	if status >= 300 && status < 400 {
		// Playwright treats a request and its redirect chain as one route; the
		// browser would follow Location without a second scope check. Fetch with
		// MaxRedirects=0 above, then remove redirect controls when fulfilling so
		// no redirect can leave the checked in-scope URL.
		delete(responseHeaders, "location")
		delete(responseHeaders, "refresh")
	}
	if err := route.Fulfill(pw.RouteFulfillOptions{Status: &status, Headers: responseHeaders, Body: body}); err != nil {
		c.failJSONNavigationOverride(override, fmt.Errorf("fulfill JSON navigation response: %w", err))
		_ = route.Abort()
	}
}

func (c *pwContext) takeJSONNavigationOverride(req pw.Request) *jsonNavigationOverride {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.jsonOverride
	if o == nil || o.applied || !req.IsNavigationRequest() || req.Method() != "GET" || req.URL() != o.url {
		return nil
	}
	o.applied = true
	return o
}

func (c *pwContext) failJSONNavigationOverride(o *jsonNavigationOverride, err error) {
	c.mu.Lock()
	if c.jsonOverride == o {
		o.err = err
	}
	c.mu.Unlock()
}

func (c *pwContext) setJSONNavigationOverride(rawURL, contentType string, body []byte, timeout time.Duration) (*jsonNavigationOverride, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.allow == nil {
		return nil, errors.New("browser: JSON POST navigation requires an explicit scope gate")
	}
	if c.jsonOverride != nil {
		return nil, errors.New("browser: another JSON POST navigation is already pending")
	}
	o := &jsonNavigationOverride{url: rawURL, contentType: contentType, body: append([]byte(nil), body...), timeout: timeout}
	c.jsonOverride = o
	return o, nil
}

func (c *pwContext) finishJSONNavigationOverride(o *jsonNavigationOverride) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jsonOverride == o {
		c.jsonOverride = nil
	}
	return o.applied, o.err
}

func (c *pwContext) NewPage() (pageHandle, error) {
	p, err := c.c.NewPage()
	if err != nil {
		return nil, err
	}
	return &pwPage{p: p, ctx: c}, nil
}

func (c *pwContext) AddCookies(cookies []Cookie) error {
	opt := make([]pw.OptionalCookie, 0, len(cookies))
	for _, ck := range cookies {
		oc := pw.OptionalCookie{Name: ck.Name, Value: ck.Value}
		if ck.URL != "" {
			oc.URL = pw.String(ck.URL)
		}
		if ck.Domain != "" {
			oc.Domain = pw.String(ck.Domain)
		}
		if ck.Path != "" {
			oc.Path = pw.String(ck.Path)
		}
		opt = append(opt, oc)
	}
	return c.c.AddCookies(opt)
}

func (c *pwContext) Cookies() ([]Cookie, error) {
	cks, err := c.c.Cookies()
	if err != nil {
		return nil, err
	}
	out := make([]Cookie, 0, len(cks))
	for _, ck := range cks {
		out = append(out, Cookie{
			Name:     ck.Name,
			Value:    ck.Value,
			Domain:   ck.Domain,
			Path:     ck.Path,
			Secure:   ck.Secure,
			HTTPOnly: ck.HttpOnly,
		})
	}
	return out, nil
}

func (c *pwContext) SaveStorageState(path string) error {
	_, err := c.c.StorageState(pw.BrowserContextStorageStateOptions{Path: pw.String(path)})
	return err
}

func (c *pwContext) Close() error { return c.c.Close() }

type pwPage struct {
	p   pw.Page
	cdp pw.CDPSession
	ctx *pwContext

	bodyMu                 sync.Mutex
	capturedJSONBodyBytes  int
	capturedJSONBodyEvents int
}

func (p *pwPage) Goto(url, referer, waitUntil string, timeout time.Duration) (int, string, error) {
	opts := pw.PageGotoOptions{}
	if timeout > 0 {
		opts.Timeout = pw.Float(float64(timeout.Milliseconds()))
	}
	if waitUntil != "" {
		ws := pw.WaitUntilState(waitUntil)
		opts.WaitUntil = &ws
	}
	if referer != "" {
		opts.Referer = pw.String(referer)
	}
	resp, err := p.p.Goto(url, opts)
	if err != nil {
		return 0, "", err
	}
	status := 0
	if resp != nil {
		status = resp.Status()
	}
	return status, p.p.URL(), nil
}

// GotoJSON performs one top-level POST navigation after the context route
// converts the initial GET request into the exact bounded JSON request. The
// context route continues to run its scope check before applying the override.
func (p *pwPage) GotoJSON(rawURL string, body []byte, contentType, waitUntil string, timeout time.Duration) (int, string, error) {
	if p.ctx == nil {
		return 0, "", ErrJSONPostUnsupported
	}
	override, err := p.ctx.setJSONNavigationOverride(rawURL, contentType, body, timeout)
	if err != nil {
		return 0, "", err
	}
	status, finalURL, navErr := p.Goto(rawURL, "", waitUntil, timeout)
	applied, routeErr := p.ctx.finishJSONNavigationOverride(override)
	if navErr != nil {
		return 0, "", navErr
	}
	if routeErr != nil {
		return 0, "", routeErr
	}
	if !applied {
		return 0, "", errors.New("browser: JSON POST navigation override was not applied")
	}
	return status, finalURL, nil
}

// GotoForm submits a real, top-level POST navigation by rendering a throwaway
// auto-submitting <form> (method=POST, action=url) whose hidden inputs carry
// fields, then letting the BROWSER submit it — the same mechanism an ordinary
// HTML form uses. This is how a POST/form-encoded candidate gets the same
// chance to execute on page load that a GET candidate already gets via Goto;
// it is not simulated interaction to force an otherwise-inert payload (see
// AGENTS.md §3) since it only reproduces the HTTP method/body the candidate
// step already sent, carrying the EXACT field values (including the one
// holding the candidate's own breakout) byte-for-byte.
func (p *pwPage) GotoForm(method, url string, fields map[string]string, waitUntil string, timeout time.Duration) (int, string, error) {
	if err := p.p.SetContent(formHTML(method, url, fields)); err != nil {
		return 0, "", err
	}
	navOpts := pw.PageExpectNavigationOptions{}
	if timeout > 0 {
		navOpts.Timeout = pw.Float(float64(timeout.Milliseconds()))
	}
	if waitUntil != "" {
		ws := pw.WaitUntilState(waitUntil)
		navOpts.WaitUntil = &ws
	}
	resp, err := p.p.ExpectNavigation(func() error {
		_, evalErr := p.p.EvalOnSelector("#indago-form", "form => form.submit()", nil)
		return evalErr
	}, navOpts)
	if err != nil {
		return 0, "", err
	}
	status := 0
	if resp != nil {
		status = resp.Status()
	}
	return status, p.p.URL(), nil
}

// formHTML renders a minimal, auto-submitting form carrying fields as hidden
// inputs. Values are placed in the "value" attribute (never as text content,
// which would put them in an HTML_TEXT context instead of reproducing the
// exact form field the candidate step sent) and HTML-attribute-escaped only
// for well-formedness — this preserves the field's byte value, it does not
// alter or filter it.
func formHTML(method, url string, fields map[string]string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><body><form id="indago-form" method="`)
	b.WriteString(htmlAttrEscape(method))
	b.WriteString(`" action="`)
	b.WriteString(htmlAttrEscape(url))
	b.WriteString("\">\n")
	for k, v := range fields {
		b.WriteString(`<input type="hidden" name="`)
		b.WriteString(htmlAttrEscape(k))
		b.WriteString(`" value="`)
		b.WriteString(htmlAttrEscape(v))
		b.WriteString("\">\n")
	}
	b.WriteString("</form></body></html>")
	return b.String()
}

// htmlAttrEscape escapes the characters that would break out of a double-quoted
// HTML attribute value. This is well-formedness, not XSS filtering: the field
// value reaches the server exactly as given, because the browser decodes the
// entity back to the original byte before putting it in the submitted form
// field — identical to how a real <form> carries any character.
func htmlAttrEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", `"`, "&quot;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func (p *pwPage) Content() (string, error) { return p.p.Content() }

func (p *pwPage) Screenshot(fullPage bool) ([]byte, error) {
	return p.p.Screenshot(pw.PageScreenshotOptions{FullPage: pw.Bool(fullPage)})
}

func (p *pwPage) Evaluate(script string, arg any) (any, error) {
	if arg == nil {
		return p.p.Evaluate(script)
	}
	return p.p.Evaluate(script, arg)
}

const maxCapturedJSONPostDataBytes = 64 << 10

func isJSONRequestContentType(raw string) bool {
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func mayInspectJSONRequest(method, contentType, rawURL string, allow func(string) bool) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
		return false
	}
	return isJSONRequestContentType(contentType) && isNetworkURL(rawURL) && (allow == nil || allow(rawURL))
}

func boundedJSONRequestBodySize(bodySize int) bool {
	return bodySize > 0 && bodySize <= maxCapturedJSONPostDataBytes
}

func shouldCaptureJSONRequestBody(method, contentType string, bodySize int, rawURL string, allow func(string) bool) bool {
	return mayInspectJSONRequest(method, contentType, rawURL, allow) && boundedJSONRequestBodySize(bodySize)
}

func networkEventFromCDP(params map[string]interface{}, allow func(string) bool, captureBody bool, bodyBudget int) (NetworkEvent, int, bool) {
	request, ok := params["request"].(map[string]interface{})
	if !ok {
		return NetworkEvent{}, 0, false
	}
	url, _ := request["url"].(string)
	method, _ := request["method"].(string)
	resourceType, _ := params["type"].(string)
	headers, _ := request["headers"].(map[string]interface{})
	contentType := ""
	for name, value := range headers {
		if strings.EqualFold(name, "content-type") {
			contentType, _ = value.(string)
			break
		}
	}
	event := NetworkEvent{
		URL: url, Method: method, ResourceType: strings.ToLower(resourceType),
		ContentType: contentType, At: time.Now(),
	}
	// CDP may omit postData when a request exceeds maxPostDataSize. The
	// one-byte sentinel lets us reject any included body above the retention
	// limit; we never fetch an omitted body later.
	observedBodyBytes := 0
	if captureBody && bodyBudget > 0 && mayInspectJSONRequest(method, contentType, url, allow) {
		if body, ok := request["postData"].(string); ok {
			observedBodyBytes = len(body)
			if boundedJSONRequestBodySize(observedBodyBytes) && observedBodyBytes <= bodyBudget {
				event.PostData = body
			}
		}
	}
	return event, observedBodyBytes, true
}

func cdpNumber(value any) (int, bool) {
	switch n := value.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		parsed, err := n.Int64()
		return int(parsed), err == nil
	default:
		return 0, false
	}
}

func cdpRedirectTarget(params map[string]interface{}) (target string, isRedirect, invalid bool) {
	status, ok := cdpNumber(params["responseStatusCode"])
	if !ok || status < 300 || status >= 400 || status == 304 {
		return "", false, false
	}
	var location string
	if entries, ok := params["responseHeaders"].([]interface{}); ok {
		for _, entry := range entries {
			header, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := header["name"].(string)
			if strings.EqualFold(name, "location") {
				location, _ = header["value"].(string)
				break
			}
		}
	}
	if location == "" {
		return "", false, false
	}
	// WHATWG URL parsing treats backslashes as slashes for HTTP(S), while
	// net/url preserves them as escaped path bytes. Reject them rather than
	// compare two different interpretations of a redirect destination.
	if strings.Contains(location, `\`) {
		return "", true, true
	}
	request, ok := params["request"].(map[string]interface{})
	if !ok {
		return "", true, true
	}
	current, _ := request["url"].(string)
	base, err := url.Parse(current)
	if err != nil || current == "" {
		return "", true, true
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", true, true
	}
	resolved := base.ResolveReference(ref)
	if resolved == nil || (resolved.Scheme != "http" && resolved.Scheme != "https") {
		return "", true, true
	}
	return resolved.String(), true, false
}

func enableRedirectScopeGate(cdp pw.CDPSession, allow func(string) bool) error {
	cdp.On("Fetch.requestPaused", func(params map[string]interface{}) {
		requestID, _ := params["requestId"].(string)
		if requestID == "" {
			return
		}
		method := "Fetch.continueRequest"
		args := map[string]any{"requestId": requestID}
		if target, redirect, invalid := cdpRedirectTarget(params); redirect && (invalid || !allow(target)) {
			method = "Fetch.failRequest"
			args["errorReason"] = "BlockedByClient"
		}
		// CDP event handlers run on the protocol dispatcher. Send the response
		// asynchronously so waiting for the command reply cannot block delivery
		// of that reply on the same dispatcher. If sending fails, the request
		// remains paused rather than escaping the scope check.
		go func() { _, _ = cdp.Send(method, args) }()
	})
	patterns := []any{map[string]any{"urlPattern": "*", "requestStage": "Response"}}
	if _, err := cdp.Send("Fetch.enable", map[string]any{"patterns": patterns}); err != nil {
		return fmt.Errorf("enable response-stage redirect scope gate: %w", err)
	}
	return nil
}

func (p *pwPage) OnRequest(fn func(NetworkEvent), allow func(string) bool) error {
	cdp, err := p.p.Context().NewCDPSession(p.p)
	if err != nil {
		return fmt.Errorf("create CDP request observer: %w", err)
	}
	cdp.On("Network.requestWillBeSent", func(params map[string]interface{}) {
		p.bodyMu.Lock()
		bodyBudget := maxObservedJSONBodyBytesPerPage - p.capturedJSONBodyBytes
		captureBody := p.capturedJSONBodyEvents < maxObservedJSONBodyEventsPerPage
		event, observedBodyBytes, ok := networkEventFromCDP(params, allow, captureBody, bodyBudget)
		if observedBodyBytes > 0 {
			p.capturedJSONBodyEvents++
			if observedBodyBytes >= bodyBudget {
				p.capturedJSONBodyBytes = maxObservedJSONBodyBytesPerPage
			} else {
				p.capturedJSONBodyBytes += observedBodyBytes
			}
		}
		p.bodyMu.Unlock()
		if ok {
			fn(event)
		}
	})
	if _, err := cdp.Send("Network.enable", map[string]interface{}{"maxPostDataSize": maxCapturedJSONPostDataBytes + 1}); err != nil {
		// The owning Context.NewPage path closes the page target on observer
		// setup failure; that also detaches this CDP session without a wait.
		return fmt.Errorf("enable bounded CDP request observer: %w", err)
	}
	if allow != nil {
		if err := enableRedirectScopeGate(cdp, allow); err != nil {
			return err
		}
	}
	p.cdp = cdp
	return nil
}

func (p *pwPage) OnConsole(fn func(ConsoleMessage)) {
	p.p.OnConsole(func(m pw.ConsoleMessage) {
		fn(ConsoleMessage{Type: m.Type(), Text: m.Text()})
	})
}

func (p *pwPage) OnDialog(fn func(string)) {
	p.p.OnDialog(func(d pw.Dialog) {
		fn(d.Message())
		// Dismiss so the page stays responsive. We make no verdict here.
		_ = d.Dismiss()
	})
}

func (p *pwPage) OnPageError(fn func(string)) {
	p.p.OnPageError(func(err error) { fn(err.Error()) })
}

func (p *pwPage) WaitForURL(glob string, timeout time.Duration) error {
	opts := pw.PageWaitForURLOptions{}
	if timeout > 0 {
		opts.Timeout = pw.Float(float64(timeout.Milliseconds()))
	}
	return p.p.WaitForURL(glob, opts)
}

// AddInitScript installs script via Playwright's own init-script mechanism
// (runs before any of the page's own scripts, on every navigation this page
// makes from here on).
func (p *pwPage) AddInitScript(script string) error {
	return p.p.AddInitScript(pw.Script{Content: pw.String(script)})
}

func (p *pwPage) Close() error {
	// Closing the page target automatically detaches its CDP session. Avoid a
	// synchronous Detach here: Playwright can wait indefinitely for the session
	// response while an in-flight request is deliberately hanging.
	err := p.p.Close()
	p.cdp = nil
	return err
}

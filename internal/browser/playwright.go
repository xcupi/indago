package browser

import (
	"context"
	"errors"
	"fmt"
	"time"

	pw "github.com/playwright-community/playwright-go"
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
// exe, when non-empty, is the Chromium binary to launch.
func newPlaywrightDriver(exe string) (driver, error) {
	p, err := pw.Run()
	if err != nil {
		return nil, fmt.Errorf("run playwright (is it installed? try `playwright install`): %w", err)
	}
	return &pwDriver{pw: p, exe: exe}, nil
}

type pwDriver struct {
	pw  *pw.Playwright
	exe string
}

func (d *pwDriver) Launch(headless bool) (browserHandle, error) {
	opts := pw.BrowserTypeLaunchOptions{Headless: pw.Bool(headless)}
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

func (b *pwBrowser) NewContext(storageStatePath string, allow func(string) bool) (contextHandle, error) {
	opts := pw.BrowserNewContextOptions{}
	if storageStatePath != "" {
		opts.StorageStatePath = pw.String(storageStatePath)
	}
	c, err := b.b.NewContext(opts)
	if err != nil {
		return nil, err
	}
	if allow != nil {
		// Abort disallowed requests before they leave the browser. Redirect hops
		// are routed as requests of their own, so each is checked too.
		err := c.Route("**/*", func(route pw.Route) {
			u := route.Request().URL()
			if isNetworkURL(u) && !allow(u) {
				_ = route.Abort("blockedbyclient")
				return
			}
			_ = route.Continue()
		})
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("install scope gate: %w", err)
		}
	}
	return &pwContext{c: c}, nil
}

func (b *pwBrowser) Close() error { return b.b.Close() }

type pwContext struct{ c pw.BrowserContext }

func (c *pwContext) NewPage() (pageHandle, error) {
	p, err := c.c.NewPage()
	if err != nil {
		return nil, err
	}
	return &pwPage{p: p}, nil
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
	_, err := c.c.StorageState(path)
	return err
}

func (c *pwContext) Close() error { return c.c.Close() }

type pwPage struct{ p pw.Page }

func (p *pwPage) Goto(url, waitUntil string, timeout time.Duration) (int, string, error) {
	opts := pw.PageGotoOptions{}
	if timeout > 0 {
		opts.Timeout = pw.Float(float64(timeout.Milliseconds()))
	}
	if waitUntil != "" {
		ws := pw.WaitUntilState(waitUntil)
		opts.WaitUntil = &ws
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

func (p *pwPage) OnRequest(fn func(NetworkEvent)) {
	p.p.OnRequest(func(r pw.Request) {
		fn(NetworkEvent{
			URL:          r.URL(),
			Method:       r.Method(),
			ResourceType: r.ResourceType(),
			At:           time.Now(),
		})
	})
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

func (p *pwPage) Close() error { return p.p.Close() }

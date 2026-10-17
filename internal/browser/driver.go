package browser

import "time"

// This file defines the internal driver abstraction that the Manager is written
// against. The real implementation is Playwright-backed (playwright.go); tests
// substitute a fake. Keeping this seam small makes lifecycle, pooling, context
// isolation, cancellation, and cleanup testable without launching a browser.

// driver is a browser engine (a running Playwright instance).
type driver interface {
	// Launch starts a browser instance (headless or headful).
	Launch(headless bool) (browserHandle, error)
	// Stop shuts the engine down, releasing all resources.
	Stop() error
}

// browserHandle is one launched browser (the unit of the reusable pool).
type browserHandle interface {
	// NewContext creates an isolated context. storageStatePath, when non-empty,
	// seeds it with saved session material (persistent authenticated context).
	// proxyServer, when non-empty, routes every request this context makes
	// through that proxy (operator-supplied; see ContextOptions.ProxyServer).
	// extraHeaders, when non-empty, is merged into every request this context
	// makes (see ContextOptions.ExtraHeaders). allow, when non-nil, gates
	// every http(s) request: disallowed requests must be aborted before they
	// are sent.
	NewContext(storageStatePath, proxyServer string, extraHeaders map[string]string, allow func(url string) bool) (contextHandle, error)
	// Close closes the browser and all its contexts.
	Close() error
}

// contextHandle is an isolated browser context (cookies/storage not shared).
type contextHandle interface {
	NewPage() (pageHandle, error)
	AddCookies(cookies []Cookie) error
	Cookies() ([]Cookie, error)
	// SaveStorageState writes cookies + localStorage to path.
	SaveStorageState(path string) error
	Close() error
}

// pageHandle is a single page/tab within a context.
type pageHandle interface {
	// Goto navigates to url and returns the HTTP status and final URL.
	Goto(url, waitUntil string, timeout time.Duration) (status int, finalURL string, err error)
	Content() (string, error)
	Screenshot(fullPage bool) ([]byte, error)
	// Evaluate runs a JS expression with an optional argument and returns the
	// result (used for localStorage/sessionStorage access).
	Evaluate(script string, arg any) (any, error)
	// OnRequest registers a network-request observer (call before navigation).
	OnRequest(func(NetworkEvent))
	// OnConsole registers a console observer.
	OnConsole(func(ConsoleMessage))
	// OnDialog registers a dialog observer; the driver dismisses the dialog after
	// reporting its message so the page stays responsive.
	OnDialog(func(message string))
	// OnPageError registers an observer for uncaught exceptions in the page's own
	// JavaScript (as opposed to OnConsole, which only sees explicit console.*
	// calls). This is a neutral runtime observation, like console/dialog
	// messages: the driver reports the exception's message and makes no verdict
	// about it.
	OnPageError(func(message string))
	// WaitForURL blocks until navigation reaches a URL matching glob (used for
	// interactive login).
	WaitForURL(glob string, timeout time.Duration) error
	// AddInitScript installs script to run in this page BEFORE any of the
	// page's own scripts, on this navigation and every subsequent one in
	// this page (Playwright's own init-script mechanism). Used by DOM-XSS
	// probing (internal/scan/domxss.go) to install sink hooks that must be
	// in place before a page's own onload-style handler can run — a
	// listener attached via Evaluate AFTER the page has already loaded
	// would miss a handler that already fired.
	AddInitScript(script string) error
	Close() error
}

// newDriverFunc constructs a driver. NewManager uses the Playwright factory;
// tests inject a fake.
type newDriverFunc func() (driver, error)

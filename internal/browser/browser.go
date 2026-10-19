// Package browser is Indago's headless-browser layer. It manages the Chromium
// (via Playwright) lifecycle and a reusable browser pool, creates isolated and
// optionally persistent (authenticated) contexts, and exposes navigation,
// cookie/localStorage/sessionStorage access, network observation, and screenshot
// capture. It also supports interactive login/MFA through a visible browser.
//
// Boundaries:
//   - Scope enforcement is the caller's responsibility (as with the HTTP engine).
//   - This package performs NO XSS detection, verification, payload generation,
//     or anti-bot/WAF evasion. It is neutral browser automation that gathers the
//     runtime evidence a later verification phase will reason about.
//
// Design: the pool/lifecycle logic (Manager) is written against a small internal
// driver abstraction (see driver.go). The real driver is Playwright-backed
// (playwright.go); tests exercise the Manager against a fake driver.
package browser

import (
	"context"
	"errors"
	"time"

	"github.com/indago/indago/internal/ratelimit"
)

// Errors.
var (
	// ErrNotImplemented is returned by the Stub browser.
	ErrNotImplemented = errors.New("browser: not implemented")
	// ErrClosed is returned when using a Manager/Context/Page after Close.
	ErrClosed = errors.New("browser: closed")
	// ErrNoBrowser indicates the pool has no available browser.
	ErrNoBrowser = errors.New("browser: no browser available")
)

// Load-state values for navigation readiness.
const (
	WaitLoad             = "load"
	WaitDOMContentLoaded = "domcontentloaded"
	WaitNetworkIdle      = "networkidle"
	WaitCommit           = "commit"
)

// MaxJSONNavigationBodyBytes bounds one browser-verification POST/JSON replay.
// It is larger than the discovery per-body cap to allow a benign candidate to
// expand an otherwise-maximal observed body without permitting unbounded data.
const MaxJSONNavigationBodyBytes = 128 << 10

// Config tunes the browser Manager.
type Config struct {
	// Headless runs Chromium without a visible window (default true). Interactive
	// login always launches a visible browser regardless of this setting.
	Headless bool
	// PoolSize is the number of reusable browser instances (default 1). Contexts
	// are created from the pool round-robin.
	PoolSize int
	// NavigationTimeout is the default per-navigation timeout (default 30s).
	NavigationTimeout time.Duration
	// ExecutablePath launches this Chromium binary instead of the one the
	// Playwright driver expects. It lets a driver and an installed browser of
	// different revisions be used together. Empty falls back to
	// $INDAGO_CHROMIUM_PATH, then to the driver's own browser.
	ExecutablePath string
	// ShutdownTimeout bounds how long Close waits for contexts/browsers/the
	// driver to close. These are synchronous calls into the Playwright
	// process with no cancellation of their own; if that process is wedged,
	// Close would otherwise block forever — and so would the whole program's
	// graceful shutdown. Past this timeout Close logs a warning and returns
	// anyway, leaving the underlying Chromium process orphaned rather than
	// hanging.
	ShutdownTimeout time.Duration
	// DisableSandbox launches Chromium with its process sandbox turned OFF
	// (--no-sandbox). The zero value keeps the sandbox ON: this is an explicit,
	// operator-chosen reduction of isolation, never a default and never an
	// automatic fallback. See docs/browser-sandbox.md.
	DisableSandbox bool
}

// DefaultConfig returns conservative defaults.
func DefaultConfig() Config {
	return Config{Headless: true, PoolSize: 1, NavigationTimeout: 30 * time.Second, ShutdownTimeout: 30 * time.Second}
}

func (c Config) withDefaults() Config {
	if c.PoolSize <= 0 {
		c.PoolSize = 1
	}
	if c.NavigationTimeout <= 0 {
		c.NavigationTimeout = 30 * time.Second
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	return c
}

// Cookie is a browser cookie (subset of fields Indago uses).
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	URL      string `json:"url,omitempty"` // used when adding cookies without domain/path
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}

// NetworkEvent is an observed browser network request. PostData is ephemeral,
// used only to discover bounded JSON request fields; it is omitted from
// serialization so full request bodies cannot leak through NetworkEvent JSON.
type NetworkEvent struct {
	URL          string    `json:"url"`
	Method       string    `json:"method"`
	ResourceType string    `json:"resource_type"`
	ContentType  string    `json:"content_type,omitempty"`
	PostData     string    `json:"-"` // ephemeral JSON request body for discovery; never serialized
	At           time.Time `json:"at"`
}

// ConsoleMessage is an observed browser console message.
type ConsoleMessage struct {
	Type string `json:"type"` // log, info, warning, error, debug, …
	Text string `json:"text"`
}

// ContextOptions configure an isolated browser context.
type ContextOptions struct {
	// AllowRequest, when non-nil, is the scope gate for every http(s) request the
	// browser would make (page loads, subresources, XHR/fetch, redirect hops).
	// Disallowed requests are ABORTED before they leave the browser — no traffic
	// reaches the host — and are recorded as blocked rather than as network
	// observations. nil allows everything (the caller then owns scope).
	//
	// Limitation: WebSocket and service-worker traffic is not intercepted.
	AllowRequest func(url string) bool
	// StorageStatePath, when set, seeds the context with previously saved session
	// material (cookies + localStorage), yielding a persistent authenticated
	// context.
	StorageStatePath string
	// ProxyServer, when set, routes every request this context makes (page
	// loads, subresources, XHR/fetch) through the given proxy
	// ("http://host:port", "socks5://host:port", optionally with embedded
	// credentials). "" (the default) uses no proxy — a direct connection.
	// Indago never picks or supplies a proxy itself; this is operator-provided
	// infrastructure (AGENTS.md's "evade target-side identity/rate defenses
	// only via infrastructure the operator explicitly supplies and opts into,
	// never infrastructure Indago invents or manages itself").
	ProxyServer string
	// ExtraHeaders, when set, are merged into every request this context
	// makes (page navigation + subresources), on top of the browser's own
	// defaults — used to carry a Header-location XSS candidate's override
	// (User-Agent, Referer, X-Forwarded-For, …) into the verifying browser,
	// so a header reflection gets the same real-browser confirmation chance
	// a query/form/JSON reflection already gets. nil/empty changes nothing.
	ExtraHeaders map[string]string
}

// NavOptions control a single navigation.
type NavOptions struct {
	WaitUntil string        // one of the Wait* constants ("" → load)
	Timeout   time.Duration // 0 → Manager default
	// Limiter, when non-nil, paces this navigation (one permit per navigation,
	// taken before the request is sent). It is the scan's shared limiter, so
	// browser navigations count against the same RequestsPerSecond as HTTP.
	Limiter *ratelimit.Limiter
	// Referer, when non-empty, overrides the Referer HTTP header sent with
	// this navigation (threaded to pageHandle.Goto's own referer
	// parameter). "" leaves the browser's normal referer behavior
	// unchanged. Used by DOM-XSS's document.referrer source
	// (internal/scan/domxss.go) — see docs/dom-xss.md.
	Referer string
}

// NavResult is the outcome of a navigation.
type NavResult struct {
	Status   int
	FinalURL string
}

// ScreenshotOptions control screenshot capture.
type ScreenshotOptions struct {
	FullPage bool
}

// LoginOptions configure interactive login/MFA.
type LoginOptions struct {
	LoginURL         string        // page to open for the operator to log in
	SuccessURLGlob   string        // navigation to this URL glob signals success
	StorageStatePath string        // where to save the authenticated session
	Timeout          time.Duration // overall wait for the operator (0 → 5m)
}

// LoginResult is returned after a successful interactive login.
type LoginResult struct {
	StorageStatePath string
	FinalURL         string
}

// AutoLoginOptions configure a non-interactive, auto-filled login (AuthMode
// "password"): Indago itself submits operator-supplied credentials into a
// login form, headless, with no human present. This is ordinary browser
// automation to establish an authenticated session — distinct from, and
// never in tension with, AGENTS.md's "no simulated user activation"
// boundary, which is specifically about never faking interaction to force
// an XSS candidate to execute (see AGENTS.md §2.2).
type AutoLoginOptions struct {
	LoginURL string
	Username string
	Password string
	// UsernameSelector/PasswordSelector/SubmitSelector are CSS selectors
	// that override the built-in heuristic (see autoLoginScript) for a
	// login form it can't guess correctly. Empty uses the heuristic.
	UsernameSelector string
	PasswordSelector string
	SubmitSelector   string
	// SuccessURLGlob is REQUIRED (unlike LoginOptions.SuccessURLGlob,
	// optional for a human-watched interactive login): with no operator
	// present to judge success, Indago needs an objective, programmatic
	// signal before it ever saves a session file — a fully silent success
	// would otherwise save an UNAUTHENTICATED state the moment the form
	// submits, however long that actually takes.
	SuccessURLGlob   string
	StorageStatePath string
	Timeout          time.Duration // overall wait (0 → 2m; shorter than interactive's 5m since no human step is involved)
}

// PoolStats is a snapshot of Manager resources.
type PoolStats struct {
	Browsers     int
	OpenContexts int
}

// RenderOptions controls how a page is loaded by the convenience Render method.
type RenderOptions struct {
	// AllowRequest is the scope gate; see ContextOptions.AllowRequest.
	AllowRequest func(url string) bool
	// SessionStatePath points at stored session material to reuse the scan's
	// authenticated session.
	SessionStatePath string
	// WaitUntil is a navigation readiness hint (one of the Wait* constants).
	WaitUntil string
	// ObservationWindow keeps a page alive for this bounded duration after
	// navigation and content retrieval so asynchronous request events can settle.
	ObservationWindow time.Duration
	// Timeout overrides the Manager default navigation timeout.
	Timeout time.Duration
	// Screenshot requests a screenshot be captured.
	Screenshot bool
	// Limiter paces the navigation; see NavOptions.Limiter.
	Limiter *ratelimit.Limiter
}

// RenderResult captures observations from loading a page. Fields are generic so
// the same result serves multiple verification engines later.
type RenderResult struct {
	FinalURL       string
	Status         int
	HTML           string
	Screenshot     []byte // PNG bytes when requested
	ConsoleLogs    []string
	ConsoleErrors  []string
	PageErrors     []string       // uncaught JS exceptions (see OnPageError)
	DialogMessages []string       // alert/confirm/prompt messages observed
	Network        []NetworkEvent // observed (allowed) requests
	Blocked        []string       // requests aborted by AllowRequest (never sent)
	// ExecutedMarkers is reserved for the verification phase (marker execution
	// detection). The browser layer leaves it empty — it makes no verdicts; it only
	// hands verification the raw, neutral observations above (ConsoleErrors,
	// PageErrors, DialogMessages, HTML) to inspect.
	ExecutedMarkers []string
}

// Browser renders pages in a real browser context (the simple facade).
type Browser interface {
	// Render loads url and returns runtime observations. Callers must ensure the
	// URL is in scope before calling.
	Render(ctx context.Context, url string, opts RenderOptions) (*RenderResult, error)
	// Close releases browser resources.
	Close() error
}

// Stub is a no-op browser. Render returns ErrNotImplemented so no browser is
// launched. Useful in tests and where the real Manager is not wired.
type Stub struct{}

// Render implements Browser.
func (Stub) Render(context.Context, string, RenderOptions) (*RenderResult, error) {
	return nil, ErrNotImplemented
}

// Close implements Browser.
func (Stub) Close() error { return nil }

var _ Browser = Stub{}

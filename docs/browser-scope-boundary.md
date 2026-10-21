# Scoped browser target boundary (slice 1)

## Authorization boundary

When `AllowRequest` is non-nil, `BrowserContext.Route("**/*")` pauses the
first HTTP(S) request, including the first request of a newly opened popup.
Before `Continue` or the JSON replay override, the driver requires a request
frame whose owning page is in its managed-page registry. Missing/early frames
and unregistered pages are **aborted**, even when the first URL is in scope.
Only `Context.NewPage` can register a page: it creates the inert `about:blank`
page, installs its CDP response-stage redirect guard, and then publishes that
page to callers. Context page events do not authorize or attach guards to
unmanaged targets. No target-page event listener, mutation observer or
`window.open` replacement participates in authorization.

For approved pages, ordinary route checks enforce the initial URL and CDP
`Fetch` response interception enforces each HTTP redirect destination before
Chromium follows it. CDP replies remain asynchronous in event callbacks;
registry locks are not held across protocol I/O. Closing a page closes its
sessions via target teardown rather than synchronously waiting on `Detach`.

The pinned Playwright runtime itself had an early-popup publication race in
`Request.Frame` / internal `safePage` (including `Route.Abort`). A minimal local
runtime copy synchronizes those reads and publishes only fully initialized
pages. See [the patch inventory](../third_party/playwright-go/INDAGO-PATCH.md)
and its upstream SHA256 manifest. This does not change the Playwright driver
version, Chromium flags, or process sandbox policy.

## Login flows (B1)

Password auto-login and interactive/MFA login now require a non-nil
`AllowRequest` gate. Both reject an initial login URL denied by that gate
**before launching a login browser**, and pass the gate to the fresh context.
The scan controller derives it from the project's actual `domain.Scope.Permits`,
including host/path exclusions; it checks the login URL before credentials are
read or login is launched. There is no separate authentication allowlist.

Standalone `POST /api/auth/login` now requires `project_id`. Missing/unknown
projects, absent/empty scope, and out-of-scope login URLs return 400 without
calling the login driver. The dashboard passes the selected project's ID;
CLI callers must use `auth login -project PID -login-url URL` (optional
`-success-url GLOB`). The server loads that project's scope, not a scope
supplied by the client. A browser-disabled server still returns 501.

All login requests use the existing context enforcement described above:
redirects, subresources, same-tab form submissions and popup requests are not
exempt. Explicitly add **only authorized** SSO/identity-provider hosts and
required paths through Projects → Scope before login. Scope is never expanded
from a redirect, success glob, or login URL. This also authorizes those hosts
for normal project scanning; do not add an identity provider you lack permission
to test. Popup-dependent SSO is unsupported (even in-scope popups are denied);
use a same-tab flow. Service workers remain blocked and WebSockets closed.

`TestIntegrationLoginScopeBoundary` exercises real Chromium against loopback
servers: initial denial, canonical cross-host redirect denial, credential form
submission denial, subresource/popup denial, successful scoped login, and an
explicitly included SSO host. Server-side request and dummy-credential counters
are the assertions. Interactive/MFA policy plumbing uses fake-driver tests;
no real operator MFA challenge is exercised. `TestUILoginCarriesProjectScope`
checks the dashboard request in Chromium. `TestIntegrationCreateScanLoginScope`
checks the real controller-to-password-login path without starting a scan.
All three real-browser roots are required by the CI preflight, including
rejection of skipped/failed descendants.

## Redirect `Location` parsing (B2)

The CDP redirect gate resolves each 3xx `Location` with Go's `net/url` and asks
the scope about the result. Chromium parses it with the WHATWG algorithm, which
for a special scheme skips any run of slashes before the authority:
`Location: ///host/x` is `http://host/x` to Chromium but a path on the current
host to `net/url`. A real-Chromium test showed the browser reaching an
out-of-scope host through that form while the gate allowed it.

`cdpRedirectTarget` now fails closed (the request is aborted) on every form where
the two readings can differ: backslashes, leading/trailing whitespace, any
control character (WHATWG removes tab/CR/LF anywhere), opaque references
(`http:host/x`, `mailto:`), a scheme with no host (`http:///host/x`) and a
scheme-less reference whose path starts with `//` after parsing (`///host/x`).
Ordinary redirects are unchanged: plain paths, queries, `../` references,
`//host/x` network-path references and absolute `http(s)://host/...`.

`TestIntegrationScopeGateBlocksParserDifferentialRedirects` asserts a hit counter
on a second host name (`localhost` against the in-scope `127.0.0.1`) for each
shape, and `TestIntegrationParserDifferentialControlReachesTheSecondHost` proves
an ungated browser does reach that host, so a zero is meaningful. Unit tests pin
both the rejected forms and the forms that must keep working. Both integration
roots are required by the CI preflight.

Not covered: only the `Location` header of a 3xx is examined. `Refresh` headers
and `<meta http-equiv=refresh>` are not examined here and have no dedicated test
(reasoned, not verified: they should be new navigations that reach the route
gate), and redirects inside cross-site iframes or workers are still unverified.

What the scope matcher compares (hostname only; port and scheme ignored; loose
path prefixes; no IP-level policy in the browser) is documented in
[scope-semantics.md](scope-semantics.md).

## Compatibility and deliberate limits

- Main managed-page navigation, same-page forms, child frames, fetch/XHR,
  subresources and allowed redirects remain supported.
- Popups/new unmanaged targets are unsupported for scanning: even an entirely
  in-scope popup cannot send an HTTP(S) request. A blank/non-network target may
  still exist or execute local script until its context is closed. This is
  request denial, not a promise that no target object can be created.
- Requests with no attributable page are denied. Dedicated workers are not a
  newly supported surface; page-attributed worker traffic uses the managed
  page's guard, and frame-less worker traffic is refused. Service workers stay
  blocked, all WebSockets stay closed.
- Target-controlled DOM mutation and closed shadow trees do not affect request
  authorization. The fixture explicitly covers late anchor/form target mutation,
  closed-shadow anchors, direct denied popups, `window.open`, blank-then-navigate
  and submitter overrides, with an unscoped traffic-producing control for each.
- Form POST and bounded JSON top-level document replay retain method/body/media
  type and cookies. JSON replay still never follows a redirect (even in scope).
  Existing scan-level state-changing opt-in, session/proxy and shared navigation
  limiter contracts are unchanged. These are not new exploit-delivery claims.
- This is not an OS-wide network firewall or exhaustive Chromium protocol audit.
  No claim is made about browser background traffic, external handlers, WebRTC,
  WebTransport, every cross-process worker/frame configuration, or Chromium bugs.
  Tests use only owned loopback destinations. Popup-dependent app behavior is
  intentionally impaired rather than explored optimistically.
- This slice does **not** fix UI or candidate grammar findings from the
  readiness audit. Verdict provenance/isolation, logout crawl policy and CSRF
  refresh are covered by [verdict-provenance.md](verdict-provenance.md).

## Regression and required runtime contract

`internal/browser/popup_scope_integration_test.go` asserts actual destination
hit counters, not just browser logs. Behavioral RED on the original revision
showed `redirect_hits=1, outside_hits=1` for each of the three reproduced
bypasses; the ordinary targeted-anchor control was already blocked. GREEN
requires zero hits at both popup destinations. Positive controls require each
unscoped popup to hit its actual destination. Managed child-frame/subresource
redirects and exact cookie-bearing JSON/form replay have separate positive
checks. Existing scope/redirect, pending-response observer/close, cancellation
and lifecycle tests remain in place.

The mandatory `scripts/ci-browser-check.py` additionally requires:

- `TestIntegrationScopeGateRejectsUnmanagedTargets`
- `TestIntegrationScopeGateManagedFramesAndSubresources`
- `TestIntegrationScopeGatePreservesBodyReplay`

The deployment parser contract explicitly rejects missing/skipped/failed roots
and skipped/failed popup/replay descendants. It was behaviorally RED before the
required list was extended. A successful root cannot hide a skipped child.
Use the required inventory in the script, not historical root counts in old
validation records. The nested dependency race test also needs explicit
`(cd third_party/playwright-go && go test -race ./...)`.

Commands/evidence for the local run are recorded separately in the slice-1
validation report. Full tagged race and hosted/Docker gates are separate claims;
local targeted checks alone do not establish them.

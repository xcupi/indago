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

Other navigation and fetch surfaces, measured (`redirect_surfaces_integration_test.go`,
15 shapes, each with an ungated control that must reach the second host):
`Refresh` header, `<meta http-equiv=refresh>`, `location.href`, iframes (same-site
and cross-site, the latter served from `127.0.0.2` so Chromium isolates the frame
in its own process), a 3xx inside an iframe, and dedicated, shared and blob
workers (`fetch`, `importScripts`, and a worker started from a cross-site frame).
**No HTTP request reached the out-of-scope host in any of the 15 shapes, with one
exception that was found by this work and fixed: `SharedWorker`.**

**SharedWorker bypassed the gate (fixed).** A `fetch` from a shared worker reached
the out-of-scope host with a real HTTP request, 6 of 6 times once the page was kept
alive long enough for the worker to run (dedicated, blob, and cross-site-frame
workers stayed clean 6 of 6 under the same conditions). It looked intermittent
(2 of 8, then 2 of 4) only because the context sometimes closed before the worker
ran; a pass in that state proves nothing. Playwright's route interception does not
cover a shared worker's network traffic, so the surface is removed at launch with
`--disable-blink-features=SharedWorker` (`pwDriver.Launch`), not patched with a
script-level listener. Measured: with the flag the shape no longer reaches the
second host even from a page with no gate (the interface is gone), and the gated
test passes; without it the gated test fails 5 of 5. The shape's control therefore
runs in a plain Chrome (it cannot run inside Indago any more). Consequences: pages
that use `SharedWorker` lose that feature in every Indago-launched browser
(including interactive login); `new SharedWorker(...)` throws. Other
cross-process targets that a route cannot see were not enumerated and may exist.

The earlier "reasoned, not verified" statement for `Refresh`, meta-refresh and
cross-site iframes/workers is now measured for requests.

**Known gap: connections.** The gate refuses *requests*; it does not prevent
Chromium from opening a *connection*. For six shapes that start a navigation to an
out-of-scope URL (`Refresh` header, meta-refresh, `location.href`, `<iframe src>`,
meta-refresh inside an iframe, meta-refresh inside a cross-site iframe) the
out-of-scope host still sees TCP connections while no request arrives:
- `http://` target: one TCP connection, zero bytes sent (measured with a raw
  listener).
- `https://` target: two connections, each starting a TLS handshake. The first
  bytes are a ClientHello (`0x16`), which carries the host name in the SNI in the
  clear (measured with a raw listener on loopback; no real server was contacted).
- A Chrome net-log shows the cause: an `HTTP_STREAM_JOB_CONTROLLER` with
  `is_preconnect: true` for the navigation URL. It is a Chromium preconnect for the
  navigation target and it happens regardless of the later `route.Abort`.
- Not affected (zero connections, measured): a 3xx `Location` redirect, and every
  subresource and worker fetch (`<img>`, `fetch`, `importScripts`, blob and shared
  workers).
- Seven launch flags and feature switches were tried and none changed it
  (`--dns-prefetch-disable`, `--disable-quic`, `PreconnectFromKeyedService`,
  `LoadingPredictorLimitPreconnectSocketCount`, `PreconnectManagerDirectFastPath`,
  `NavigationPredictorPreconnectHoldback`, and a bundle of prediction/prefetch
  features). This is not a proof that no switch exists; the cause was not traced to
  a specific Chromium feature.

What that means in practice: no request, cookie, path or payload reaches an
out-of-scope host, but the host can see the scanner's address connect and, for
https, can read its own name in the SNI. A page that embeds a third-party
`<iframe src="https://…">` (embeds, ads, captchas) triggers this for each one. A
person browsing the same page makes the same connections. If a program forbids
*any* contact with out-of-scope infrastructure, the browser path does not meet
that on its own: enforce it with egress filtering outside Indago, or a
scope-enforcing proxy (not implemented). The test records the gap with
`KNOWN GAP` log lines and asserts only what is true (zero requests everywhere,
zero connections for non-navigations); if a future Chromium or a fix closes it,
the log lines change and this section must be updated.

Not covered: `Location` and the surfaces above are measured on loopback names with
Chrome 155 only. Early Hints (103), speculation rules/prerender, `<a ping>`, Server-Sent
Events/EventSource, WebTransport and service workers' own fetches (blocked, not
re-measured here) were not tried, and the connection gap was observed only through
Indago's launch, not traced inside Chromium.

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

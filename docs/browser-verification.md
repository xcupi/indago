# Indago — Browser Verification

For a candidate that reflected, verification answers the one question nothing
earlier in the pipeline can: **does it actually run?** "Reflection alone is NOT
a confirmed XSS" — this is the authority that promotes a candidate to
`confirmed`, or demotes it to `rejected`/`inconclusive`, backed by real browser
evidence. Code: `internal/verification/browser.go` (the Verifier) and
`internal/scan/verify.go` (the job that drives it).

## The deterministic signal, not a heuristic

Every built-in candidate (`internal/detection/candidate.go`) is, at the exact
position it targets, nothing but the **bare marker token** used as a
JavaScript expression:

- HTML text/attribute: `<svg onload=TOKEN>` — the `onload` handler's entire
  body is `TOKEN`.
- JS string breakout: `";TOKEN//` — closes the string, then `TOKEN` is its own
  statement.
- JS code position: just `TOKEN`.

`TOKEN` is never declared anywhere. Referencing an undeclared identifier as
code does exactly one thing in JavaScript: the engine throws
`ReferenceError: TOKEN is not defined` **the moment it is evaluated** — which,
for an `onload` handler, is the browser's own `load` event; for inline script,
it's synchronous page parsing. So "was `TOKEN` evaluated as code" and "did the
browser report an exception naming `TOKEN`" are the same question.

This is why the signal needs no payload, no timing heuristic, and no simulated
user action. The verdict authority is the engine's own exception record
(`internal/verification/provenance.go`, `internal/browser/provenance_playwright.go`):
the paused instruction must be the bare marker identifier in the main frame.
Page-controlled text (`console.*`, `pageerror` strings, `Error.stack`) is not
evidence merely because it names the marker, and a page that throws or logs a
forged `ReferenceError: TOKEN is not defined` is `Inconclusive`, not
`Confirmed`. `matchExecutionSignal` remains only as a diagnostic matcher for
legacy log text. See [verdict-provenance.md](verdict-provenance.md).
Nothing is executed *by* the verifier — the candidate either reaches an
evaluated position or it doesn't, and the browser reports the difference on
its own.

## The three-way decision (`decide`)

| Observed | Verdict | Confidence |
|---|---|---|
| the browser reports the marker as an unresolved JavaScript identifier | `confirmed` | high |
| the candidate is in the rendered page, but no such signal | `rejected` | high |
| the marker isn't even found in the rendered page this time | `inconclusive` | low |

No LLM, no scoring, no "likely exploitable" — three cases, one deterministic
function (`internal/verification/browser.go:decide`). A merely-reflected
`javascript:` URL in an `<a href>` is the textbook case for `rejected`: nothing
activates it on passive page load, so it must never read as confirmed.

## What actually happens (`BrowserVerifier.Verify`)

1. The candidate URL is checked against scope and replayed in a fresh,
   isolated browser context — seeded with the scan's saved session
   (`domain.Session.StatePath`) when one exists. Supported replays are GET/HEAD,
   POST/form via a real HTML form, and POST/JSON via a bounded (128 KiB)
   top-level document replay preserving the observed JSON media type and body.
   POST/JSON remains behind the state-changing opt-in; invalid, oversized, or
   unsupported bodies are not attempted. For POST/JSON, Playwright submits the
   body through `Route.Fetch` with redirects disabled, then fulfills the
   top-level document response for Chromium to parse and execute.
2. Direct browser requests are checked by the same `AllowRequest` scope gate.
   Playwright only routes the original request in an HTTP redirect chain, so
   each managed page also has a CDP response-stage gate: it resolves every 3xx
   `Location` against the responding URL and fails the redirect before Chromium
   follows it when the destination is outside scope. Raw backslash characters in
   `Location` are rejected because Chromium's WHATWG URL parser and Go's
   `net/url` can interpret them differently. In-scope redirects continue
   normally; real-browser tests cover multi-hop navigation and subresource
   redirects.
3. POST/JSON is intentionally stricter: its Playwright route fetch disables
   automatic redirects, and `Location`/`Refresh` is removed before the response
   is fulfilled as a document. No redirect is followed, even to an in-scope URL;
   a redirected destination is therefore not verified in this phase.
4. Scoped contexts abort every request from an unapproved target at the context
   route boundary, including the popup's first request when its frame is not yet
   available. Only explicitly managed pages are approved after their CDP redirect
   gate is installed. Child frames and managed subresources remain supported;
   popup HTTP(S) flows are unsupported even when in scope. Service workers stay
   blocked and WebSockets stay closed. No mutable target-page JS listener is the
   authorization boundary. See [browser-scope-boundary.md](browser-scope-boundary.md)
   for compatibility, local dependency race patch, and limits.
5. The page is waited for `load` (a real browser event, not an arbitrary
   sleep), then its console errors, uncaught exceptions, and rendered HTML are
   read back.
6. If the candidate declares a non-load trigger, reflected the marker, and
   produced no load-time signal, ONE activation is performed — see
   "Activation classes" below. It is methodology, never evidence: the verdict
   still comes only from the marker-specific observation, so a page that
   reflects the same value without a handler stays `Rejected` after it.
7. The decision above is applied, and a screenshot, the rendered DOM, and the
   combined browser log are captured as evidence.

## Activation classes

A candidate's `Trigger` decides whether anything is activated at all.
`TriggerLoad` (and an empty legacy trigger) is never activated; a declared
interaction is activated once, by exactly one of:

| class | method | used for |
|---|---|---|
| `focus` | `element.focus()` (or one `FocusEvent` when not focusable) | autofocus/onfocus |
| `resize` | `window.dispatchEvent(new Event('resize'))` | onresize |
| `click` | `element.click()` | `javascript:` URLs, onclick |
| `animation` | `element.beginElement()` | SMIL onbegin |
| `keyboard` | `keyboard.press('Alt+Shift+<k>')` | a candidate declaring `accesskey` |

The keyboard class presses the platform's access-key shortcut
(`Alt+Shift+<key>`; `Control+Alt+<key>` on macOS) for the key the candidate
declares, through the browser's real input path — CDP
`Input.dispatchKeyEvent` with `keyDown` carrying both `text` and
`unmodifiedText`. That detail is load-bearing: Playwright's own
`Keyboard.Press` leaves `unmodifiedText` empty for character keys, and
Chromium's access-key matching reads exactly that field, so a Playwright press
delivers a keydown that runs no access-key action. A page-side half of the
class first locates the element that carries the marker and declares that exact
key (read-only); if it is missing the record is `failed` with the error stated,
and no chord is pressed.

Activation is one attempt, never a retry loop, followed by the bounded
`ActivationSettle` window (default 300 ms, hard cap 2 s) for the browser's
asynchronous exception report. The persisted `Activation` record names the
class, the exact method, the element, the attempt count, that window, and any
failure — it is evidence about methodology, never a verdict input. Real-browser
tests cover each class's positive case, a handler-stripped negative control, a
removed-element failure, and that load-trigger candidates are never activated.


**POST/JSON interpretation boundary:** `Confirmed` means the exact candidate
marker executed in Chromium while parsing the response as a top-level document.
It does not emulate the application's fetch/XHR or DOM-sink flow and does not
prove that an attacker can cause the cross-origin request (for example, through
CORS/CSRF constraints). Treat it as deterministic response-execution evidence,
not complete proof of attacker delivery.

## Pipeline wiring (`internal/scan/verify.go`)

A candidate `JobTest` that reflects does two things before it completes:
creates a `Finding` at `VerdictPending`, and enqueues a `JobVerify` job carrying
that candidate and the Finding's ID when its method/body combination is
supported (GET/HEAD, POST/form, or bounded POST/JSON). A
`JobVerify` job (handled by `verifyExecutor`, its own worker group —
`BrowserConcurrency`) resolves the target exactly like a test job, re-applies
the state-changing safeguard, calls the `Verifier`, and on completion:

- persists the verification `Report` into the `TestCase.Detail` and the
  screenshot/DOM/browser-log as `Evidence` rows (`EvidenceScreenshot`,
  `EvidenceDOM`, `EvidenceBrowserLog`);
- updates the `Finding`'s `Verdict`, `Confidence`, `EvidenceIDs`, and
  `Provenance.VerifiedAt` — the **only** place a Finding leaves `pending`.

A timeout or cancellation leaves the Finding untouched (still `pending`); only
a completed attempt decides it. No browser configured for the scan →
`verification.Stub` → the job is recorded `skipped`, not failed, and the
Finding stays `pending`.

## Boundaries

No LLM verdict, no DOM XSS (the same marker/candidate is replayed, never a new
one chosen from the live DOM), no simulated activation (a `javascript:` URL is
never clicked for it), no anti-bot/WAF evasion, no exploit payloads — see
`AGENTS.md` §2–§3.

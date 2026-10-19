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
user action: `internal/verification/signal.go`'s `matchExecutionSignal` just
scans the browser's own uncaught-exception (`page_error`) and console-error
channels for the exact marker-specific ReferenceError signature, after
navigation reaches `load`. Generic application output (for example,
`console.error(userControlledValue)`) is not evidence merely because it
contains the marker. Chromium's Playwright page-error event omits the error
class but reports an unresolved bare marker as `playwright: TOKEN is not
defined`; the matcher accepts that exact form only on the page-error channel.
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
4. The response-stage redirect checks are verified for explicitly managed pages
   (main navigations and subresources). Scoped contexts suppress `window.open`,
   targeted links/forms, and direct form submission to non-self targets before
   those popup requests start. Service workers are blocked before their script is
   fetched, and all WebSocket connections are closed. These restrictions can
   change application behavior; alternate popup-creation mechanisms are not
   independently verified.
5. The page is waited for `load` (a real browser event, not an arbitrary
   sleep), then its console errors, uncaught exceptions, and rendered HTML are
   read back.
6. The decision above is applied, and a screenshot, the rendered DOM, and the
   combined browser log are captured as evidence.

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

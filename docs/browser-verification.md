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
channels for the exact token, after navigation reaches `load`. Nothing is
executed *by* the verifier — the candidate either reaches an evaluated position
or it doesn't, and the browser reports the difference on its own.

## The three-way decision (`decide`)

| Observed | Verdict | Confidence |
|---|---|---|
| the marker names an uncaught exception / console error | `confirmed` | high |
| the candidate is in the rendered page, but no such signal | `rejected` | high |
| the marker isn't even found in the rendered page this time | `inconclusive` | low |

No LLM, no scoring, no "likely exploitable" — three cases, one deterministic
function (`internal/verification/browser.go:decide`). A merely-reflected
`javascript:` URL in an `<a href>` is the textbook case for `rejected`: nothing
activates it on passive page load, so it must never read as confirmed.

## What actually happens (`BrowserVerifier.Verify`)

1. The candidate's exact URL (GET/HEAD only — browser navigation carries no
   request body; POST/body-carrying reflections stay `pending`) is checked
   against scope and, if it passes, navigated to in a fresh, isolated browser
   context — seeded with the scan's saved session (`domain.Session.StatePath`)
   when one exists, so verification runs authenticated exactly like the rest of
   the scan.
2. Every request the page itself makes (subresources, redirects) is gated by
   the same `AllowRequest` scope check the HTTP engine uses — nothing
   out-of-scope ever leaves the browser.
3. The page is waited for `load` (a real browser event, not an arbitrary
   sleep), then its console errors, uncaught exceptions, and rendered HTML are
   read back.
4. The decision above is applied, and a screenshot, the rendered DOM, and the
   combined browser log are captured as evidence.

## Pipeline wiring (`internal/scan/verify.go`)

A candidate `JobTest` that reflects (and whose method is GET/HEAD) does two
things before it completes: creates a `Finding` at `VerdictPending`, and
enqueues a `JobVerify` job carrying that candidate and the Finding's ID. A
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

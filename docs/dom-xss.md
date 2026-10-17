# Indago — DOM XSS (first slice)

This document describes the FIRST, deliberately narrow slice of a DOM-XSS
detection engine — see `AGENTS.md` §3, which until this slice listed DOM
XSS as "designed for, not built". Reflected XSS only ever inspects the
**server's** HTTP response body for a marker reflection; `location.hash`
(the URL fragment, everything after `#`) is **never sent to the server by
the browser**, so a page whose own client-side JavaScript does something
like

```js
document.getElementById('x').innerHTML = location.hash.substring(1);
```

is a genuine, exploitable DOM-based XSS that Indago's entire
request/response-based pipeline is structurally blind to. This engine
actually renders the page in a real browser, lets its OWN JavaScript run,
and observes the live DOM/JS runtime — the fundamentally new capability
this slice adds, not a tweak to the existing Reflected XSS pipeline.

**This is explicitly NOT "DOM XSS is done."** It is one narrow, honestly
scoped, real, end-to-end vertical slice. See "Out of scope" below for
everything this does not yet cover.

---

## Scope of this slice

| Axis | Implemented |
|---|---|
| Source | Exactly ONE: `location.hash` (`detection.DOMSourceHash`) |
| Sink category | Exactly ONE, HTML injection: `Element.prototype.innerHTML` / `outerHTML` setters, `document.write` / `document.writeln` (`detection.DOMXSSSink`) |
| Pairs tested per endpoint | At most ONE — the first reachable sink, by whichever the page's own script happened to call first (see "Two-phase design" below) |
| Methods probed | GET/HEAD-navigable endpoints only (navigating a URL is always a GET request; probing a discovered POST endpoint this way would not exercise the method the operator actually cares about) |

Every navigation this engine performs goes through the **same**
scope-enforcing `browser.Manager` the rest of the product already uses
(`AllowRequest` is checked on every request — page loads, redirects,
subresources — exactly like discovery and Reflected XSS verification).
Nothing here bypasses scope, rate limits, or the evidence-integrity rules
in `AGENTS.md` §2.

## Architecture: source/sink model

Unlike Reflected XSS, a DOM-XSS "site" is identified by
**(Endpoint, source, sink)**, not **(InjectionPoint, category, context)**
— there is no HTTP request/response cycle, parameter, or injection point
to key on at all. `internal/detection/domxss.go` adds the two genuinely
new, minimal domain concepts this needs:

- `detection.DOMXSSSource` — currently only `DOMSourceHash`.
- `detection.DOMXSSSink` — currently `DOMSinkInnerHTML`, `DOMSinkOuterHTML`,
  `DOMSinkDocumentWrite` (the last covers `document.writeln` too — same
  hook, same report).

Everything else deliberately **reuses** the existing
`detection.Candidate` shape (see `DOMXSSPayloadFor`'s doc comment for the
field repurposing: `Category` is always `CatDOMXSS`, `Context` carries the
**sink** name, `ContextSub` carries the **source** name) rather than
inventing a parallel type — so every existing presentation surface that
already renders a `Candidate`'s `Category`/`Context`/`Value`/`Rationale`
(CLI `finding show`, the web API's `parsed_detail`, markdown/HTML reports)
renders a DOM-XSS candidate too, with no new plumbing. Likewise,
`internal/scan/domxss.go`'s Finding correlation (`upsertDOMXSSFinding`,
`correlateDOMXSSVerification`) reuses `scan.findingDetail` and
`scan.verificationAttempt` (the exact structs Reflected XSS's correlation
already uses) and the **same** monotonic verdict lattice
(`scan.verdictRank`: pending < inconclusive < rejected < confirmed,
confirmed sticky) — the only new thing is the dedup key shape
(`domXSSFindingDedupKey`: endpoint + a disjoint `"dom_xss"` tag + source +
sink, so a DOM-XSS finding can never collide with a Reflected-XSS one even
sharing a raw endpoint ID).

## Two-phase design: canary reachability, then payload verification

Mirrors Reflected XSS's own reflect-then-verify split, and reuses its
exact verification mechanism:

### Phase 1 — Reachability (canary)

For each discovered, GET/HEAD-navigable Endpoint (reused from the scan's
existing Endpoint registry — never a parallel discovery mechanism — see
`enqueueDOMXSSProbes`/`selectDOMXSSEndpoints`), the engine:

1. Derives a deterministic marker the same way Reflected XSS does:
   `detection.NewProbe(scanID, endpointID).Token`.
2. Builds a benign, **inert** canary value: `detection.DOMXSSCanary(marker)`
   — a string containing the marker as a plain substring, with no `<`/`>`
   at all (AGENTS.md §2.2: a canary is a detection probe, never a
   payload).
3. Installs an init-script harness via `browser.Page.AddInitScript`
   **before** navigating — this ordering is load-bearing: a listener
   attached via `Evaluate` *after* the page has already loaded would miss
   an onload-style handler that already fired. The harness
   (`domXSSHarnessScript`) monkey-patches:
   - `Element.prototype.innerHTML` and `.outerHTML`'s property setters
     (via `Object.defineProperty`, wrapping the original setter so the
     real assignment still happens — this is passive observation, not
     interception/blocking);
   - `document.write` / `document.writeln` (plain function overrides).

   Whenever a value **containing the marker substring** reaches one of
   these, the harness reports it via a uniquely-prefixed `console.log`
   (`__INDAGO_DOMXSS__` + a small JSON payload naming the sink and an
   excerpt of the value) — Playwright's own console-message channel,
   scraped back by `parseDOMXSSReachability` in Go. No exposed binding was
   needed; `console.log` plus the existing `OnConsole`/`ConsoleMessages()`
   plumbing (already used for CAPTCHA/block detection elsewhere in this
   codebase) was the simplest, most reliable option available.
4. Navigates to `endpointURL#<percent-encoded canary>` and waits for
   `load`.
5. Reads back the page's console messages and extracts the DISTINCT
   reachable sinks (`parseDOMXSSReachability`), in first-seen order.

**A canary reaching a hooked sink is a REACHABILITY signal only — never
itself a confirmed vulnerability.** If no sink is reachable, the probe
ends here: no Finding is created at all (see "Negative case" below). If
one or more sinks ARE reachable, only the FIRST (by whichever the page's
own script called first) is carried into phase two for this probe pass —
a deliberate scope boundary for this first slice, not an oversight.

### Phase 2 — Verification (real payload)

1. `detection.DOMXSSPayloadFor(sink, marker)` builds the real,
   deterministic verification candidate — a bare
   `<img src=x onerror=MARKER>`, the SAME markup-breakout idea
   `internal/detection/candidate.go`'s `html_text` `onLoad` templates use
   (`<svg onload=M>`, `<img src=x onerror=M>`, …), adapted for a value
   assigned WHOLESALE to a sink rather than reflected into existing HTML
   markup: being assigned to `.innerHTML`/`.outerHTML`, or passed to
   `document.write`, is actually a SIMPLER context than reflected HTML
   text, since there is no existing tag/attribute context to break out of
   first — the bare markup string parses and fires as-is the moment the
   sink sets/writes it.
2. A Finding is created at `VerdictPending` for this (Endpoint, source,
   sink) — reachability alone, matching AGENTS.md §2.6/§3's "never fabricate
   evidence, never confirm without a real deterministic signal".
3. The engine navigates AGAIN — a fresh page, same harness installed
   before navigation — to `endpointURL#<percent-encoded payload>`.
4. Confirmation uses the **EXACT SAME deterministic signal** Reflected XSS
   verification already uses, literally the same code:
   `verification.MatchExecutionSignal` and `verification.Decide` (both new,
   trivial exported wrappers around the existing, private
   `matchExecutionSignal`/`decide` in `internal/verification`) — scanning
   the page's own uncaught-exception (`page_error`) and console-error
   channels for the exact marker token. `MARKER` is a bare, unquoted JS
   identifier the `onerror` handler evaluates; referencing an undeclared
   identifier as code does exactly one thing in JavaScript: the engine
   throws `Uncaught ReferenceError: MARKER is not defined` the moment it
   is evaluated. Observing this (page_error or console_error) → Confirmed.
   The marker reaching the DOM but no signal → Rejected (e.g. CSP blocking
   inline event handlers, or a downstream sanitizer). Neither → Inconclusive.
5. Verification attribution follows the same anti-false-positive
   discipline `BrowserVerifier.Verify` already uses: a brand-new page per
   navigation (never reused across attempts), so there is no pre-existing
   page activity that could be mistaken for this navigation's signal.

### Percent-encoding and why it matters

Building the navigation URL, both the canary and the real payload are
percent-encoded with `jsEncodeURIComponent` — a Go re-implementation of
JavaScript's `encodeURIComponent` (NOT Go's `url.QueryEscape`, which turns
a space into `+`, form-encoding semantics a page doing
`decodeURIComponent(location.hash)` would not reverse correctly). This
also matches real browser behavior: the WHATWG URL parser itself always
percent-encodes space/`"`/`<`/`>`/`` ` `` in a URL fragment, regardless of
what is sent — so a payload needing `<`/`>` can only ever reach a page
that explicitly `decodeURIComponent`s its hash before using it. This is
not a limitation to work around; it is exactly the realistic, common
DOM-XSS pattern this engine targets (a page that reads `location.hash`
and deliberately decodes it before treating it as HTML is precisely the
vulnerable shape), and it means a page that reads the hash WITHOUT
decoding genuinely cannot be exploited via these characters through this
vector — correctly, not as a false negative.

## Wiring into the scan

- **Domain**: `domain.JobDOMXSS` (new `JobType`), dispatched to the SAME
  `GroupBrowser` worker group as `JobVerify` (it needs a real browser,
  never the HTTP engine — the whole point is that `location.hash` never
  reaches the server).
- **One-time pass**: `enqueueDOMXSSProbes` runs exactly once per scan
  execution, triggered from `execution.go`'s `evaluate()` right after the
  existing combined-candidate fallback pass goes quiet (same
  `domXSSPassDone atomic.Bool` shape as `combinedPassDone`) — one
  `JobDOMXSS` per distinct, GET/HEAD-navigable discovered Endpoint URL.
- **Executor**: `domXSSExecutor` (`internal/scan/domxss.go`), wired into
  `defaultHandlers` alongside the existing `executor`/`verifyExecutor`,
  sharing the same `findingsMu` (Finding correlation lock) and the
  concrete `*browser.Manager` (via the new `Controller.browserManager()`
  helper, mirroring `verifier()`'s own type assertion). No browser
  configured for the scan → every probe is recorded `Skipped` (never
  failed), the exact same contract `verifyExecutor` already has for "no
  browser configured".
- **Registry**: `internal/detection/engine.go`'s `DefaultRegistry()` now
  also registers a DOM-XSS entry (`domxssEngine`) so
  `Registry.Classes()` enumerates it — but, like Reflected XSS's own entry,
  its `Detect` method is never called by the running product; this
  Phase-0-era `detection.Engine`/`Input` interface cannot express what
  DOM XSS actually needs (an Endpoint to navigate plus a source/sink pair,
  not a server-side injection point). The real engine is
  `internal/scan/domxss.go`.

## Presentation

CLI `finding list`/`finding show`, the web API's
`GET /api/scans/{id}/findings` and `/findings/{fid}`, and the web UI's
Findings tab all render a `dom_xss` Finding using the SAME generic
rendering Reflected XSS findings already use (`report.NewFindingView`,
`findingDetailOut` in `cmd/indago/cli.go`) — no new fields were needed on
any of those because the Candidate/Attempt reuse described above already
carries everything: Title, Verdict/Severity/Confidence, `Parameter`
("location.hash"), `Context` ("innerHTML"/"outerHTML"/"document.write"),
the verified candidate value, both attempts (reachability + verification),
and all evidence (screenshot, rendered DOM, browser log). Live-verified:
the web UI's findings list and detail view render a confirmed `dom_xss`
finding correctly, with no JS console errors, right alongside ordinary
Reflected XSS findings.

## Out of scope for this slice (explicitly, not an oversight)

To avoid anyone assuming "DOM XSS is done" — the following are real,
deliberate exclusions for a future, separate piece of work:

- **Sources**: `postMessage`, `document.referrer`, `window.name`,
  `localStorage`/`sessionStorage`, a query-string value read by the
  page's own JavaScript (as opposed to reflected by the server). Only
  `location.hash` is implemented.
- **Sinks**: `eval`/`Function`, `location`/`src` assignment sinks (e.g.
  `location.href = ...`, `<script src>` assignment), `setTimeout`/
  `setInterval` with a string argument, `insertAdjacentHTML`,
  `Range.createContextualFragment`. Only the three HTML-injection sinks
  listed above are hooked.
- **More than one reachable pair per endpoint per probe pass**: if a page
  reaches TWO or more hooked sinks from the hash, only the first
  (deterministic, by call order) is tested; the others are not yet probed
  in the same pass.
- **Stored DOM XSS** (a source that itself came from a stored/server-side
  value rather than purely client-side) — out of scope for the whole
  product, not just this slice (AGENTS.md §3).
- **Any sink/source combination this slice does not list above** — not
  silently incomplete, explicitly future work.

## Boundaries (same as Reflected XSS, AGENTS.md §2)

No LLM verdict (the signal match/decide functions are the SAME
deterministic Go code Reflected XSS verification uses — `verification.
MatchExecutionSignal`/`Decide`), no evasion, no simulated user
interaction, no exfiltration/weaponized payloads (every candidate is a
benign bare-marker probe, never `alert(`/`document.cookie`/`fetch(`),
every navigation goes through the SAME scope-enforcing `browser.Manager`
the rest of the product uses, and evidence (screenshot, rendered DOM,
browser log) is always captured and never fabricated.

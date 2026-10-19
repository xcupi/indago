# Verdict provenance, attempt isolation and authenticated-crawl safety

This documents the contract behind `Confirmed` for reflected and DOM XSS after
the readiness audit (revision `36d6d44`), plus two authenticated-scan fixes. It
states what the scanner now establishes and, just as importantly, what it still
does not. Validation evidence: [p0-slice2-3-validation.md](p0-slice2-3-validation.md).

## What `Confirmed` means

`Confirmed` means Chromium itself reported that the bare, per-attempt marker
identifier was evaluated as code **in the main frame**. The browser engine, not
page-authored text, is the authority:

- A CDP session (`Debugger.setPauseOnExceptions: uncaught`) records the
  uncaught exception together with the script id, position and frame id of the
  paused instruction. `internal/browser/provenance_playwright.go` reads script
  source and node metadata only; it never calls `Runtime.evaluate` or
  `Runtime.callFunctionOn`, so it does not run anything of its own in the page.
- `markerAtPosition` accepts the position only when the source text at the
  engine's `(line, column)` is the marker as a bare statement-start identifier
  in ordinary code. The `(line, UTF-16 column)` pair is mapped with V8's own
  line-terminator rules (`\r`, `\r\n`, `\n`, U+2028, U+2029). Mapping with `\n`
  alone let a script containing a bare `\r` make the engine's real throw
  position and the scanner's reading of the source disagree, which placed a
  marker identifier after a forged `throw`. It is a deliberately conservative lexer: template literals,
  regexes, non-ASCII prefixes, property reads, `throw MARKER` and markers
  inside strings or comments are refused rather than guessed.
- `verification.MatchRuntimeExecution` additionally requires the exception to
  be in the main frame, a `ReferenceError`, with a description starting
  `ReferenceError: <marker> is not defined`, and a recorded source digest.
- `verification.DecideWithProvenance` is the single verdict rule used by both
  reflected and DOM verification.

Text that a page controls is evidence only and can never confirm anything:
`console.*` output, `pageerror` strings, `Error.stack` and `sourceURL`.

### Fail-closed outcomes are `Inconclusive`, never `Rejected`

- Provenance unavailable (unsupported driver, enable failure) or the main frame
  unknown: `Inconclusive`, low confidence, replay manually.
- A page exception whose **message line** names the marker while it is not a
  main-frame evaluation of the marker identifier is the shape of a forged
  error, or genuine execution in a child frame: `Inconclusive`. Only the first line is compared. CDP appends the stack
  to the description and the stack carries the page URL, which holds the payload
  and therefore the marker, so matching the whole description would flag every
  error on every reflected page.
- Unrelated page errors are ignored. Real sites throw them constantly and they
  say nothing about a candidate. Such an exception costs one debugger pause and
  resume, but no source fetch and no evidence budget, so a page that throws
  constantly cannot starve the real signal.

In the DOM executor a probe whose provenance is unavailable becomes an errored
test case, not a negative result: an attempt that cannot be attributed must not
read as "not reachable" or "not vulnerable".

## DOM reachability is verified too

The sink-hook harness reports through `console.log`, which a page can imitate.
`Runtime.Reports` therefore only contains console calls whose top stack frame is
a script whose source is **exactly** the installed init script (bare, or in
Playwright's fixed `(() => {\n      …\n    })();` wrapper; containment is
refused so a page cannot embed the harness text in a comment). Reachability and
the fragment-insertion check read only those reports.

If the public console contains harness-shaped reports for the marker but none is
traced to the installed harness, the probe fails with a visible error
("sink reachability is untested") instead of recording a negative. That also
covers an instrumentation mismatch such as a Playwright wrapper change.

## Attempt isolation (DOM)

- Each selector (query parameter, storage key, fragment route parameter) is
  probed in its own browser context, with one proxy per job. Origin storage
  written for one selector is never visible to the next. Previously a
  `localStorage` key `a` payload remained while key `b` was tested, so both were
  `Confirmed` although only `a` reached a sink.
- Fragment route parameters are separate findings. The dedup key now includes
  the selector for `location.hash` when a route parameter is present, so `a` and
  `b` no longer collapse into one finding titled `a`.
- Execution in a child frame cannot confirm a top-level sink: the exception must
  be in the main frame.

## Stated limits that remain

- **Sink attribution is not proven.** Execution is proven by the engine; the
  sink label is the first hooked sink that received the canary. Every confirmed
  DOM note says so, and says when more than one hooked sink received the payload
  or none did. A page that sends the same input to an unhooked path (for example
  `insertAdjacentHTML`) can still execute while the label names another sink.
  Hooking a new sink is a new engine category and was not done here.
- **postMessage delivery is the scanner's own.** The sender is a
  scanner-created sandboxed child frame. A handler that trusts a particular
  `event.source` or `event.origin` may be exploitable by the scanner's sender
  and not by a real attacker; the note asks for manual delivery confirmation.
- **Storage poisoning is not shown.** A confirmed storage finding does not
  establish that an attacker can write that key.
- The lexer is an allow-list. It can produce `Inconclusive` for an unusual but
  genuine execution position; that is a recall cost accepted in exchange for not
  confirming a forgery.
- Provenance covers uncaught exceptions. Execution that completes without
  throwing is not a signal this verifier ever used.
- Evidence budgets bound memory, not correctness. Only exceptions whose message
  names the marker are recorded (cap 64; overflow is dropped, and if every kept
  one is forged the verdict is already `Inconclusive`). After the first genuine
  marker evaluation the scanner stops pausing on exceptions, so a string timer
  that throws every tick costs one hit. Script metadata is kept for up to 8192
  scripts; a script beyond that cannot be attributed and its attempt ends
  `Inconclusive`, it does not flip the whole page to unavailable. Each read waits
  up to 300 ms for an event handler that is still running; an exception raised
  after the read is not seen, as with the old page-error channel.
- **A hostile page can still evaluate its own copy of the marker on purpose.**
  The marker appears in the URL, so a page can read it and run
  `setTimeout(marker)` or `new Function(marker)()`. That is indistinguishable
  from a real sink: what is proven is "the marker was evaluated as code", not
  "attacker input reached a sink unsanitized". Review the sink path for any
  finding on a page you do not trust.
- The lexer is an allow-list over ASCII source. A script with non-ASCII text
  before the marker, a regex or template literal, or an unusual statement shape
  yields `Inconclusive` instead of `Confirmed`. Event-handler bodies and the
  canonical timer string forms are the shapes it is built for.

## Authenticated discovery never requests session-terminating URLs

`Collector.AllowFetch(url, source)` is the single policy: on an authenticated
scan a discovered URL that looks like logout/sign-out is neither registered nor
requested. Sources ask before sending a request they initiate:

- the crawler before queueing a link for the next level (a queued link is
  requested by `fetchPage` before the sink sees it, so refusing registration
  alone still sent the request), and it no longer follows a link the sink refused;
- content discovery before probing a candidate path;
- the sitemap source before requesting a nested sitemap URL listed in a sitemap
  index. That URL is document content, so it is also checked against scope.

An operator-provided seed is explicit intent and is still requested.
Unauthenticated scans skip nothing. The top-level `/sitemap.xml` and
`/robots.txt` are fixed paths under the seed origin; URLs they list are
registered through the same collector check. Not covered: requests made by the
browser network-capture source while it renders a page, a link that looks
harmless but redirects to a logout endpoint, a logout triggered through the
query string (`?action=logout`; the check is path-only on purpose), and
CamelCase names such as `LogoutServlet`. `looksSessionTerminating` is a name
heuristic, with `_` and `-` treated as separators (`user_logout` is matched). The session monitor still checks that the state file exists, not
that the target still considers the session valid.

## Query CSRF token refresh

`refreshDynamicParams` already fetched the current token, but `buildRequest`
kept a query value that the endpoint URL already carried, so a stale `?token=old`
beat the fresh value and the request was rejected before reaching the reflecting
code (reading as "not reflected"). A non-injected query parameter whose name
looks like a rotating token (`token|csrf|xsrf|nonce`) now takes its (refreshed)
`Example`. Other query values already in the URL remain the observed value, and
an empty refreshed value (a hidden field a script fills in later) never erases a
token the URL carries. If the refresh itself fails, `Example` is the discovery-time value, equally stale as
the URL's, so nothing is lost.

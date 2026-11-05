# DOM marker-window validation (bounded sink value evidence)

This note records one bounded fix in the DOM-XSS harness. It is not a coverage
or readiness claim for DOM XSS as a whole.

## Defect

The init-script harness (`domXSSHarnessTemplate` in `internal/scan/domxss.go`)
checked the FULL sink value for the marker but emitted
`v.slice(0, 500)`. `parseDOMXSSReachability` then required the marker to be
present in that emitted value. A supported `location.hash` → `innerHTML` sink
whose page prepends 600 harmless characters therefore executed the benign
marker natively yet was recorded as a clean "no sink reachable" negative: no
finding, no verification attempt.

Reproducer (prior evidence, other checkout):
`/home/udalah/Documents/Developments/indago_lab/second-opinion/dom_acceptance_test.go`
and `/home/udalah/.hermes/cache/scratch/indago-second-opinion/dom-probes.log`.

## Fix

`report()` now emits a marker-centered excerpt, capped at the existing 500
JavaScript UTF-16 code units:

- values of 500 units or fewer are emitted unchanged (existing behavior);
- longer values are clipped around the marker's `indexOf` position, so the
  complete real marker survives even with a long prefix and/or suffix;
- the clip never starts or ends inside a UTF-16 surrogate pair (the marker is
  plain ASCII, so the adjustment can only trim harmless context);
- `String.prototype.slice`, `Math.floor` and `String.prototype.charCodeAt`
  are captured before page scripts run, mirroring the existing
  `console.log`/`JSON.stringify` capture. A page replacing any of them cannot
  un-bound the excerpt or make it drop the marker (v2 correction; v1 read
  `Math.floor`/`charCodeAt` at report time and could still false-negative).

The serialized report schema is unchanged: `{sink, value, connected}`. The
parser's marker check is unchanged and is still required. Every harness
consumer shares this one `report()` path: `innerHTML`/`outerHTML`,
`document.write`/`writeln`, `insertAdjacentHTML`, both the initial and the
`connected:true` `Range.createContextualFragment` reports, and the
primitive-string `setTimeout`/`setInterval` reports.

## Tests

New real-browser roots in `internal/scan/domxss_marker_window_integration_test.go`
(required by `scripts/ci-browser-check.py` and mirrored in
`deploy/ci_runtime_test.go`, including missing/skip/fail acceptance):

- `TestDOMXSSMarkerWindowRetention` — hash → `innerHTML` with zero/short
  prefixes, a marker crossing the old 500 boundary, 600+, 8192/4096
  prefix+suffix, and a 300-emoji (600 UTF-16 unit) surrogate prefix. Each
  positive is paired with an independent native-execution control (fresh
  context, no harness, markup payload in the fragment). Controls: marker
  absent (real negative), escaped long prefix (finding reaches verification,
  Rejected, not Confirmed), forged harness-shaped console-only report with a
  long prefix (probe error, no finding). Positives assert a Confirmed verdict,
  the marker-specific runtime note, and screenshot/DOM/browser-log evidence.
- `TestDOMXSSMarkerWindowSinkPaths` — connected `Range.createContextualFragment`
  with a 600-character prefix (asserts the `connected:true` report survives)
  and a primitive-string `setTimeout` whose handler string starts with a
  600-character comment.
- `TestDOMXSSHarnessMarkerSnippetBounded` — harness contract directly:
  reported value ≤ 500 UTF-16 units, marker retained at start/middle/end,
  complete long value never emitted, no lone surrogate from a split pair.
- `TestDOMXSSMarkerWindowExcerptNatives` — the page reads the hash, then
  replaces `Math.floor`, `String.prototype.charCodeAt` or
  `String.prototype.slice`, then sets `innerHTML` to raw + 600 characters;
  every case must confirm (v2).

A focused unit test (`internal/scan/domxss_marker_window_test.go`) pins the
parser side: a prefix-only excerpt of the old truncation shape stays a
negative, while a marker-bearing bounded excerpt is accepted — the fix did not
remove marker validation.

Adjacent suites re-run: `TestDOMHTMLSourceMatrix` and
`TestDOMStringTimerSourceMatrix` (all seven sources, both sink categories),
`TestDOMCreateContextualFragment*`, `TestDOMInsertAdjacentHTML*`,
`TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed`,
`TestDOMXSSForgedSignalsAreNotConfirmed`,
`TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON`,
`TestDOMXSSStringTimerThrowingEveryTickStillConfirms`,
`TestDOMSetTimeoutExecution`, `TestDOMSetIntervalExecution`, and the reflected
forgery controls. Real `/usr/bin/google-chrome`, sandbox on, `-race -p 1
-count=1`; no skips.

## Correction (v2)

QA review of v1 found that `excerpt()` read page-mutable `Math.floor` and
`String.prototype.charCodeAt` at report time. A page that replaced either
after load could empty the excerpt or make `report()` throw and silently drop
the report, turning a marker-at-start value with a long suffix into the same
false negative the fix was meant to remove (the captured slice alone was not
enough). v2 captures `Math.floor` and `String.prototype.charCodeAt` at
init-script install time, exactly like `slice`, and uses the captured
functions; the 500-unit cap, marker validation, schema and target execution are
unchanged. Source SHA256 of `internal/scan/domxss.go` at handoff:
`067a41853c5fff8da1507db95984773cb9422c843c14adb71ce4c412604d0c09`.

The new real-browser root `TestDOMXSSMarkerWindowExcerptNatives` (hash →
innerHTML, 600-character harmless suffix, native-execution control per case)
covers page replacement of `Math.floor`, `String.prototype.charCodeAt` and
`String.prototype.slice`; it failed on v1 for the first two and passed for the
captured slice, and passes on v2 for all three. The snippet contract adds a
right-edge case (long prefix + marker + ASCII spacer + emoji suffix) that
places the 500-unit right clip inside a surrogate pair; a scratch mutation
removing the end-edge trim fails it with a lone surrogate. The native control
now polls for the marker-specific runtime signal for a bounded,
context-cancellable time instead of reading once after load.

## Limits

- Only the DOM sink-report excerpt changed. No new sink, source, payload,
  verdict rule, scope/redirect/proxy/network behavior, or sandbox policy.
- The separate verification-error propagation bug exercised by the prior
  second-opinion file was intentionally not fixed here.
- The excerpt is now marker-centered, so for a very long value the report
  drops most of the app-controlled prefix rather than the marker; the
  complete value is still absent from evidence by design.
- Worker gates only: focused unit tests, the new tagged roots, adjacent
  provenance/Range/forgery/timer suites and the two source matrices. The full
  `make check`, the full tagged suite and `scripts/ci-browser-check.py` itself
  were not run by this worker; independent QA/QC owns those.

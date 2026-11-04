# DOM-XSS: same-origin external scripts

Status: implemented and validated at the layer it changes (static visibility,
provenance, bounds). **No verdict changed.** The browser's marker-specific
execution signal remains the only authority (AGENTS.md §2.5/§2.6).

## The measured gap

The bounded static pass (`DOMXSSStaticReachability`) parsed only inline
`<script>` bodies. On the lab page

```
GET /            -> <script src="/resources/labheader/js/labHeader.js"></script>
GET /search-results?search=zz -> JSON (an API, no DOM)
labHeader.js     -> location.search -> local variable -> one function argument
                    -> document.write('<img ... searchTerms=' + query + ...>')
```

the sink lives entirely in the external file. The pass returned
`no_tainted_path` with the note "external `<script src=...>` element(s) were not
analysed" — i.e. an *absence it had not established*, and the only place the
sink could be named was nowhere. That is the false negative this slice removes.

## What is fetched, and through what

`internal/detection/domxss_external.go` is pure: it never performs I/O. The
scan supplies a `DOMXSSScriptFetcher`; `internal/scan`'s implementation
(`domXSSPageScriptFetcher`) reads each body **through the already-loaded page**
with a synchronous `XMLHttpRequest`. That means:

- the scan's own session cookies, proxy, rate limiter and the context's
  `AllowRequest` scope gate apply exactly as they do to every other browser
  request the DOM pass makes;
- there is no new network path and no new transport to review;
- only **same-origin** references are resolved (`scheme + hostname + effective
  port`, with the scheme's default port normalised). Cross-origin, `data:`,
  `blob:`, `javascript:` and `mailto:` references are counted as foreign and
  are **never fetched**;
- the body is read from a document the scan already loaded, so the network cost
  is one the navigation had already paid.

## Bounds (stated exactly)

| Bound | Value | Constant |
|---|---|---|
| script files per page | 8 | `DOMXSSScriptFetchLimit` |
| bytes per file | 256 KiB | `DOMXSSScriptByteLimit` |
| new bytes per scan (loader lifetime) | 4 MiB | `DOMXSSScriptScanByteBudget` |
| raw `<script src>` values extracted per page | 64 | `DOMXSSScriptSrcLimit` |
| script-derived query names per endpoint | 12 | `DOMXSSScriptParamLimit` |

A file over the size cap is **skipped whole and recorded** — never truncated.
Half a minified bundle parses into nonsense, and a nonsense "no sink" is worse
than an explicit skip. The per-file cap bounds what is copied across the driver
boundary and handed to the analyser; the browser may already have downloaded
the file as part of the page load the scan performed.

## Cache

`DOMXSSScriptLoader` is one instance per scan (`domXSSExecutor.scripts`), so
the byte budget is scan-wide and safe for concurrent DOM jobs (mutex-guarded).

- **URL cache**: the same script referenced by several pages is fetched once.
- **Content cache**: bodies are keyed by SHA-256, so identical content served
  under different URLs is not fetched twice either, and within one page it is
  parsed once. The first reference keeps the provenance.
- `Stats()` exposes `Pages, Refs, Fetches, CacheHits, HashHits, BytesRead,
  PerPageSkipped, TooLarge, Failed, BudgetRefused, Foreign, Bodies`; the
  discovery note quotes the scan totals.

## Analysis and provenance

`DOMXSSStaticReachabilityWithScripts(pageHTML, pageURL, source, selector, scripts)`
analyses inline and external bodies **in document order**, replacing each
`<script src>` with its body in place, so a value one script binds is visible to
the next exactly as the browser runs them. Each `DOMXSSFlowSite` now carries
`Script`: the resolved same-origin URL for an external body, `""` for inline.

The inline-only `DOMXSSStaticReachability` is unchanged and is still the API for
callers that have no bodies; for pages with no external scripts the two produce
byte-identical results (pinned by `TestDOMXSSStaticInlineOnlyGolden`).

## Failures are recorded, never folded into a negative

Every same-origin reference that cannot be analysed becomes a
`DOMXSSScriptProblem` (`Src`, `URL`, `Reason`, `Detail`) and forces
`DOMXSSFlowUnresolved` unless a site was found anyway. Reasons:
`not same-origin`, `per-page script cap reached`, `exceeds the per-file size
cap`, `fetch failed`, `per-scan byte budget exhausted`, `not fetched`,
`could not be parsed`.

Statement ends follow JavaScript's automatic semicolon insertion: a line break
ends a statement when the expression parser has stopped, and `return` followed
by a line break returns nothing. Ordinary ES5 that omits semicolons (for
example `var a = b.c` on one line and `var d = ...` on the next) therefore
parses. Two statements on ONE line with no separator are still not valid and
still produce `could not be parsed` (`unparsed statement tail near ...`); the
rest of the script is never silently dropped.

A page whose referenced script 404s therefore reports **"could not be
analysed"**, not "no sink". Removing the reference altogether is the only clean
negative.

## Scan wiring (minimum)

`discoverScriptQueryParams` already performed one bounded document load per
query-source endpoint to learn query names from the page's scripts. It now
returns `domXSSPageScripts{HTML, Params, Scripts, Note}`:

- query-name discovery uses the same loaded bodies (no extra fetch);
- `probeDOMXSSCandidate` runs the static pass with those bodies and the selector
  it is about to probe, and appends an **advisory** line to the reachability /
  negative TestCase note:
  `static pass (advisory, no verdict): document.write reachable at <script-URL> line N`.
- The advisory line is produced only when the page has external scripts AND the
  pass has something to add — a reachable site, or a script it could not
  analyse. A page whose external scripts were all analysed and contain no sink
  keeps byte-identical notes, and an inline-only page never reaches this code.

No finding, verdict, confidence, dedup key or candidate value is touched.

## Validation

Lab root: `indago_lab/ps-external-js` (`go run ./indago_lab/ps-external-js`,
loopback only). Endpoints: `/` (external-only sink), `/search-results` (JSON
neighbour), `/noapp` (references a 404 script), `/big` (references a 350 KiB
bundle).

Unit tests (`internal/detection/domxss_external_test.go`, no browser):
provenance (`Script == http://…/app.js`), cross-script flow, missing script
(unresolved + recorded problem, and a truly script-less page as the clean
negative), too-large skipped whole, per-page and per-scan caps on a counting
fetcher, URL+hash cache, third-party never fetched, origin gate, inline-only
golden.

Real Chromium (`internal/scan/domxss_external_script_integration_test.go`,
`-tags browser_integration`):

| Case | Expected | Result |
|---|---|---|
| sink only in `/labHeader.js` | one Confirmed DOM-XSS finding; evidence names the script URL | pass |
| `/noapp` (script 404) | no finding; the unreadable script is recorded | pass |
| `/big` (350 KiB bundle) | no finding; skip recorded with the size-cap reason | pass |

RED evidence at the base revision `8452796`, same fixture, inline-only API:

```
outcome=no_tainted_path externalElements=1 sites=[]
notes=[1 external <script src=...> element(s) were not analysed; this pass only sees inline scripts]
--- FAIL: TestRedExternalScriptSink
```

**Honest note on the measured symptom.** Running the same real-Chromium fixture
against the base revision shows the browser probe already *confirmed* the
external-script sink there — the runtime harness hooks `document.write`
wherever the executing body lives. So this slice does not flip an end-to-end
verdict that was previously wrong; what it fixes is that the engine could not
*see*, name or explain an external-script sink statically, and silently recorded
unreadable/oversized scripts as if they were absent. Pages where the runtime
probe genuinely observes no sink (for example an external script that runs
outside the observation window, or one whose query name was never discovered)
now get an explicit static statement naming the script, instead of a bare
"negative".

## Limits

- The analysed HTML is the document as the browser holds it at
  `page.Content()` time (the scan's existing discovery load), not the raw
  served bytes. Markup a page's own script rewrites before that point is
  therefore analysed in its rewritten form.
- Scripts created dynamically by other scripts are not in the HTML and are not
  fetched; they are invisible to both the name discovery and this pass.
- Third-party scripts are never fetched or analysed by policy, so a sink that
  lives only in a CDN bundle remains out of reach of the static pass (the
  browser can still observe it at runtime if it executes).
- Escaping/sanitisation is still not modelled: a tainted path is a structural
  statement, never a claim that the sink executes.

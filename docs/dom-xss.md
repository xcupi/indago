# Indago — bounded DOM-XSS HTML sink coverage

## P2.1: exactly two additional HTML sink methods

Current HTML sinks: `innerHTML`, `outerHTML`, `document.write`/`writeln`,
**`Element.prototype.insertAdjacentHTML`** and
**`Range.prototype.createContextualFragment`**. No source was added in P2.1.
Seven source types are implemented, with the query/storage bounds below;
implementation inventory does not imply every source/sink pair was validated.

The two new wrappers call the original native method **first**, with the
original receiver and **all arguments**, then return the identical native
result. Native errors propagate unchanged. Successful calls are observed only
when the HTML argument is a **primitive string** (argument 2 for
`insertAdjacentHTML`, argument 1 for `createContextualFragment`). Object,
TrustedHTML, boxed-string and other non-string arguments are passed unchanged
to native code but are **not logged for reachability**: coercing them again to
look for a marker could change application behavior. Failed native calls do not
produce reachability reports. The older setter/document-write hooks are not
redesigned by this bounded change.

The existing inert-canary → benign `<img src=x onerror=MARKER>` phases and
strict marker-specific runtime matcher are retained. DOM confirmation requires
the browser page-error channel; console output is stored as evidence only.
Logging a canary/payload or even a forged `ReferenceError: MARKER is not defined`
via `console.error` cannot confirm DOM execution.

**Fragment creation is not insertion.** Indago never inserts returned
fragments. Chromium can raise an image `onerror` ReferenceError even while an
image remains in a detached fragment (reproduced with native code and no
scanner harness). Therefore this sink additionally requires a MutationObserver
to observe the returned canonical marker-handler element connected to the target
document (not merely an innocent sibling text node), as well as the
marker-specific runtime signal. Browser-log evidence retains both the runtime
error and the connection report. Without observed insertion the result remains
non-Confirmed, with an explicit note. A node appended and removed before the
observer callback, attachment only inside an unobserved shadow tree, delayed
insertion after the observation window, and markup transformed into unrelated
new nodes may be missed. These are conservative coverage limits, not clean
negatives. An escaped text node being connected is not sufficient: the runtime
signal is still mandatory. Partial insertion of a harmless text sibling while
the payload image remains detached is also a tested non-Confirmed control.

### Prerequisite integration policy

This feature branch explicitly integrates the DOM prerequisite branch with P1;
neither feature is merged into main by this work. Raw HTTP redirect hops retain
both per-hop pacing and cookie scope re-evaluation. Browser navigations for
all DOM source mechanisms **and storage-key observation** take the scan's same
limiter; DOM contexts use the scan proxy pool, session storage state and existing
request-scope gate. Pacing remains one permit per explicit browser navigation,
not per browser-generated subresource or redirect hop. Scope enforcement still
covers browser subresources and redirects. No proxy-stack redesign, default
scope change, TLS weakening or sandbox change was made.

### P2.1 behavioral validation

Real Chromium tests independently exercise both new sinks with hash **and query**
sources, inserted markup, text/escaped controls, console-only marker output,
and a Range-created-but-never-inserted fragment. Native contract tests compare
receiver/argument forwarding (including extra arguments), return identity,
coercion count, exact propagated errors, invalid receivers and missing arguments.
The new sink assertions were run RED before each sink was implemented, then
GREEN sequentially. Integration policy tests cover limiter cancellation across
the seven navigation mechanisms plus storage observation, and real proxy/session/
referrer/scope/evidence behavior. This is **not** a claim that all seven sources
were positively exercised against both new sinks. See
`docs/p21-html-sinks-validation.md` for actual CLI routes/results and gates.

## Source slices: design and prior validation

The following sections describe the prerequisite source slices. Historical
appendix inventories are not the current capability map; P2.1 above adds only
the two named methods to their HTML category.


This document describes DOM-XSS detection's THIRD slice — see `AGENTS.md`
§3 and `docs/dom-xss.md`'s own "Out of scope" sections (both updated below)
for what is still, honestly, not covered. The FIRST slice (PR #5, commit
`3676923`) built the whole two-phase harness/engine for exactly ONE source
(`location.hash`) against the HTML-injection sink category (innerHTML/
outerHTML/document.write/writeln). The SECOND slice (commit `44b857b`)
added **query string**, **`window.name`**, and **`postMessage`**. This
THIRD slice adds the final three sources against that SAME sink
category — **`document.referrer`**, **`localStorage`**, and
**`sessionStorage`** — reusing the EXACT SAME sink-hook harness, two-phase
canary-then-payload design, and deterministic verification signal; only
the source-side injection mechanism is new per source, exactly like
piece 2. **After this slice, every client-side source this product has
identified is implemented against the HTML-injection sink category — see
"Out of scope" below: only NEW SINK CATEGORIES remain as future work.**
Reflected XSS only ever inspects the **server's** HTTP response body for a
marker reflection; none of these seven sources are ever sent to the server
by the browser in a way the existing pipeline would see, so a page whose
own client-side JavaScript does something like

```js
document.getElementById('x').innerHTML = location.hash.substring(1);
document.getElementById('x').innerHTML = new URLSearchParams(location.search).get('x');
document.getElementById('x').innerHTML = window.name;
window.addEventListener('message', e => { document.getElementById('x').innerHTML = e.data; });
document.getElementById('x').innerHTML = document.referrer;
document.getElementById('x').innerHTML = localStorage.getItem('key');
document.getElementById('x').innerHTML = sessionStorage.getItem('key');
```

is a genuine, exploitable DOM-based XSS that Indago's entire
request/response-based pipeline is structurally blind to. This engine
actually renders the page in a real browser, lets its OWN JavaScript run,
and observes the live DOM/JS runtime — the fundamentally new capability
all three slices add, not a tweak to the existing Reflected XSS pipeline.

**This is explicitly NOT "DOM XSS is done" as a whole product** — the
SOURCE dimension against the HTML-injection sink category is now
complete, but entirely new SINK categories (`eval`/`Function`,
`location`/`src` assignment, `setTimeout`/`setInterval` with a string
argument) are real, deliberate, separate future work. The two HTML method
sinks added by P2.1 are described at the top of this document. See "Out of scope" below.

---

## Scope of this slice

| Axis | Implemented |
|---|---|
| Sources | SEVEN (all client-side sources identified so far): `location.hash` (piece 1); `location.search`/`URLSearchParams`, `window.name`, `postMessage` (piece 2); `document.referrer`, `localStorage`, `sessionStorage` (piece 3 — `detection.DOMXSSSources`) |
| Sink category | Still exactly ONE, HTML injection: `Element.prototype.innerHTML` / `outerHTML` setters, `document.write` / `document.writeln`, `Element.prototype.insertAdjacentHTML`, `Range.prototype.createContextualFragment` (`detection.DOMXSSSink`; P2.1 methods have the primitive-string and insertion limits above) |
| Pairs tested per endpoint/source/selector | At most ONE — the first reachable sink (by the page's own script call order) for each query parameter or storage key; non-selector sources have one pass — see "Two-phase design" below |
| Methods probed | GET/HEAD-navigable endpoints only — UNCHANGED from piece 1 |
| Query source coverage | Every distinct discovered `Location=Query` parameter name, sorted lexicographically for deterministic ordering — each name gets an independent canary/payload pass and finding identity. If no query parameter was discovered, a skipped `TestCase` says the source was not tested (not a clean negative) |
| Storage key coverage | Per backend, union keys already present in target-origin storage (including storage-state-seeded localStorage) and keys named in the page's own `Storage.getItem` calls observed by an init-script hook. Keys are deduplicated and sorted; at most 32 per backend/endpoint are tested, with skipped extras recorded in the discovery `TestCase`. No observed/present key means a skipped/not-tested diagnostic and no synthetic key is seeded |

Every navigation this engine performs still goes through the **same**
scope-enforcing `browser.Manager` the rest of the product already uses
(`AllowRequest` is checked on every request — page loads, redirects,
subresources — exactly like discovery and Reflected XSS verification).
Nothing here bypasses scope, rate limits, or the evidence-integrity rules
in `AGENTS.md` §2.

## Query-string source vs. Reflected XSS — read this before assuming a dup

Indago's EXISTING Reflected-XSS pipeline already tests query parameters —
but that pipeline tests whether the **SERVER** reflects a query parameter
back into the HTTP response body. The new `detection.DOMSourceQuery`
source tests a **DIFFERENT, independent** thing: whether the page's **OWN
CLIENT-SIDE JavaScript** reads `location.search`/`URLSearchParams` and
feeds it into a dangerous sink, regardless of what the server did with
that same parameter. A page can `htmlspecialchars()`-encode a parameter
server-side (defeating Reflected XSS cleanly) while its own JS still
unsafely re-reads the RAW query string from `location.search` and gets
popped anyway — two genuinely different code paths, both legitimately
exploitable, both worth their own Finding.

These two detections are intentionally NEVER deduplicated against each
other, even when they share an endpoint and parameter name — see
`domXSSFindingDedupKey`'s disjoint `"dom_xss"` tag and the explicit
`TestQueryStringDOMXSSFindingDoesNotCollideWithReflectedXSSOnSameParameter`
test (`internal/scan/domxss_test.go`), which creates a Reflected-XSS
Finding and a DOM-XSS (query source) Finding for the SAME endpoint and
parameter "q" and asserts both remain distinct rows. The earlier piece-2
live lab also reflected and re-read one query parameter; this update's CLI
revalidation below focuses on iterating query names and uses a client-side
only query route.

## `window.name` — the navigation-sequencing note

`window.name` is the classic legacy vector: it **persists across a
same-tab navigation, even cross-origin**, in real browsers — unlike Hash/
Query it cannot be set by simply encoding a value into the URL being
navigated to. `navigateWithWindowName` (`internal/scan/domxss.go`) gets
the sequencing right:

1. install the sink-hook harness via `AddInitScript` **before any
   navigation at all** — Playwright's own init-script contract re-runs it
   on EVERY subsequent navigation this same page makes, so it is already
   in place for step 4's target navigation too;
2. navigate the SAME page to a neutral page first — `about:blank` (the
   simplest choice given `browser.Page`'s existing `Navigate`; `about:`
   URLs are never subject to the scope gate at all, see
   `browser.isNetworkURL`, so this step cannot leak a request anywhere);
3. set `window.name` via `page.Evaluate` (a plain JS string-literal
   assignment, JS-quoted the same way the harness itself is — no URL
   percent-encoding involved at all, since this never travels through a
   URL);
4. **THEN** navigate (same page/tab object, never a new one — this is
   load-bearing, since `window.name` is a property of the TAB, not the
   document) to the target endpoint URL.

This exactly reproduces the real-world attack shape: an attacker page sets
`window.name` on a tab it controls, then redirects that SAME tab to the
victim page (a link, `window.location = victimURL`, or a form submission
all work identically in the real world — only the mechanical "how do we
set window.name before the target loads" matters for this probe).

## `postMessage` — testing methodology (opaque sender, no attacker host)

The realistic vulnerable pattern is a page with its own
`window.addEventListener('message', ...)` handler that uses `event.data`
in a dangerous sink **without validating** `event.origin`/`event.source`.
An attacker can reach such a listener from another frame, popup, or page
that holds a reference to the target window. Indago must not simulate this
by calling `window.postMessage` from inside the target itself: that produces
the target's own origin and `event.source === window`, so same-origin/self-
only validation falsely appears vulnerable.

`navigateWithPostMessage` now uses a local sandboxed `srcdoc` iframe as the
sender:

1. Install the sink-hook harness via `AddInitScript`, then navigate the same
   page directly to the in-scope target. Its initial load and every
   subresource remain gated by the browser context's `AllowRequest` check.
2. Create an iframe with `sandbox="allow-scripts"` and deliberately omit
   `allow-same-origin`. Its `srcdoc` script sends `parent.postMessage(value,
   '*')` after the target has loaded and registered its listener.
3. The sender's sandboxed document has a unique opaque origin, serialized
   as `"null"`; the target receives `event.origin === "null"` and
   `event.source` equal to the sender iframe's WindowProxy, not its own
   `window`. This exercises origin/source guards rather than bypassing them.
4. Wait briefly for asynchronous `message` handling, then read the target
   page's normal console, uncaught-error, sink-hook, DOM, and screenshot
   observations. The target stays in the top-level frame, so the existing
   page abstraction captures the relevant signals directly; no interface
   extension is needed.

The sender is a local `srcdoc` document and makes no network request. No
attacker host is navigated. An earlier attempt to use a `data:` top-level
parent with the in-scope target in a child iframe was not reliable in the
installed Chromium against the local lab: the iframe did not reach the
server even though direct in-scope navigation did. That approach is not used;
the sandboxed `srcdoc` sender avoids that browser behavior while preserving
opaque-origin semantics. If a target's own policy prevents the sender frame
from running, the probe fails closed (no canary reachability and therefore
no Confirmed finding).

The real-browser integration tests cover both sides: a handler that assigns
`event.data` to `innerHTML` reaches the canary and emits the same deterministic
ReferenceError signal used for confirmation; a handler that returns when
`event.origin !== location.origin || event.source !== window` does not reach
the sink and emits no Confirmed-capable signal. A separate control proves
that self-posting to the same handler would satisfy both checks and reproduce
the old false positive.

## `document.referrer` — the Referer-override mechanism, and a real browser gotcha

Unlike every other source, the browser automation layer already exposed a
direct mechanism for this: Playwright's `page.Goto` accepts a `Referer`
option that overrides the HTTP Referer header for a single navigation —
threaded all the way down through this product's own `browser.NavOptions`
→ `pageHandle.Goto` interface (previously `Goto(url, waitUntil string,
timeout time.Duration)`, now `Goto(url, referer, waitUntil string,
timeout time.Duration)` — the interface, the real Playwright
implementation, AND the `manager_test.go` fake test double were all
updated together, the documented repo pattern). So `navigateWithReferrer`
is a ONE-STEP navigation, simpler than WindowName/Storage: install the
harness, then navigate once with the Referer override set to the probe
value — no neutral pre-navigation needed.

**A real, empirically-discovered gotcha, worth documenting precisely**:
Chromium silently IGNORES the Referer override unless the given string is
itself a well-formed absolute URL. A bare canary/payload string like
`indago-domxss-canary-abc123` or `<img src=x onerror=M>` is rejected
outright — not an error, `document.referrer` on the target page simply
reflects whatever the browser's own default referrer computation would
have produced instead (typically empty, for a fresh navigation with no
page history), which silently looks like "the source doesn't reach
anything" rather than "the mechanism was never actually engaged". This
was caught by a live-lab run, not a unit test: the FIRST implementation
passed the raw canary/payload value straight as `NavOptions.Referer` and
every probe came back "no HTML-injection sink reachable from
document.referrer" even though the lab's own inline script read it
directly. `domXSSRefererURL` (`internal/scan/domxss.go`) fixes this by
wrapping the value in a synthetic absolute URL on a fixed, RFC 2606
reserved `.invalid` host (never resolved/dereferenced — this is a header
value only, no network request is ever made to it):

```go
func domXSSRefererURL(fragmentValue string) string {
    return "https://indago-domxss-probe.invalid/" + jsEncodeURIComponent(fragmentValue)
}
```

A second, equally load-bearing consequence of needing an absolute URL:
the browser's own URL parser ALWAYS percent-encodes `<`/`>`/space in the
path when constructing the Referer header — there is no way to get a
literal, unescaped `<` into a real browser's `document.referrer` at all.
This is a genuine HTTP/URL-spec-level constraint, not an Indago
limitation, and it means the SAME realistic vulnerable pattern the
`location.hash` source targets applies here too: a page that reads
`document.referrer` and explicitly `decodeURIComponent`s it (or a
substring of it) before using it as markup is exploitable through this
vector; a page that uses the raw, still-percent-encoded string is not —
correctly, not a false negative (see "Percent-encoding and why it
matters" in the piece 1 appendix below for the exact same rationale
applied to the hash source). The live-lab route below is built this way
deliberately, mirroring the hash lab's own `decodeURIComponent
(location.hash)` requirement.

## `localStorage` / `sessionStorage` — target-derived keys, ORIGIN-scoped

Unlike `window.name` (persists across any same-tab navigation, even
cross-origin), `localStorage`/`sessionStorage` are **ORIGIN-scoped**. A
value written from a different origin is invisible to the target. Storage
source selection therefore uses the target page's real browser context,
not an assumed product-wide key:

1. Create the scan's isolated Playwright context, seeded only with the
   scan's configured storage state (if any), and navigate through the
   existing scope-enforcing manager to the target page.
2. Before the target's scripts run, install an init-script observer on
   `Storage.prototype.getItem`. It records the backend and requested key,
   preserves the API's string conversion, calls the native method, and
   returns that native result unchanged. This observation pass does not
   write or replace storage values.
3. On the loaded target origin, enumerate existing keys with
   `Storage.key(i)` (including localStorage keys seeded by storage state),
   then union them with the page's observed `getItem` keys. Deduplicate and
   sort names deterministically, separately for localStorage and
   sessionStorage.
4. If a backend has no present or requested keys, record a skipped
   TestCase saying that source was **not tested**. Indago does not seed a
   magic/default key and does not imply a negative result.
5. For each discovered key, up to a ceiling of **32 keys per backend per
   endpoint**, run the ordinary two phases independently. For each phase,
   install the sink harness, navigate the same page to the target's own
   origin root, write the canary or payload under that exact discovered
   key, then navigate to the target. All writes are confined to the scan's
   isolated browser context. If more than 32 keys are observed, the key
   discovery TestCase records the observed count, the ceiling, and how
   many additional keys were skipped.

`localStorage` and `sessionStorage` remain TWO distinct
`detection.DOMXSSSource` values and finding labels. Each candidate carries
its storage key in `Candidate.Parameter`; the backend is carried in
`ContextSub`, the title and test notes name both backend and key, and the
finding dedup identity includes the key. This lets operators distinguish
(e.g.) `localStorage` key `profile_note` from `sessionStorage` key
`profile_note`.

A confirmed sink execution proves only that the value Indago wrote in its
isolated context reaches the sink and can execute. It does **not** establish
that an attacker can write or poison that key. Treat storage exploitability
as a manual check of attacker-relevant write paths unless the target's
existing application flow itself demonstrates that control; the finding
rationale and verification note state this limitation.

Still the SAME **(Endpoint, source, sink)** identity piece 1 established for
sources without a named selector; query and storage candidates extend that
identity with the query parameter name or storage key (storage backend is
already distinct in `source`):
`detection.DOMXSSSource` now has seven values:

```go
DOMSourceHash           DOMXSSSource = "location.hash"        // piece 1
DOMSourceQuery          DOMXSSSource = "location.search"       // piece 2
DOMSourceWindowName     DOMXSSSource = "window.name"           // piece 2
DOMSourcePostMessage    DOMXSSSource = "postMessage"            // piece 2
DOMSourceReferrer       DOMXSSSource = "document.referrer"      // piece 3
DOMSourceLocalStorage   DOMXSSSource = "localStorage"           // piece 3
DOMSourceSessionStorage DOMXSSSource = "sessionStorage"         // piece 3
```

`detection.DOMXSSPayloadFor` takes `source` as an explicit first
parameter (was implicitly always `DOMSourceHash`) and still reuses the
EXISTING `detection.Candidate` shape — `Context` carries the **sink** name,
`ContextSub` the **source/backend** name, and query/storage candidates also
carry the selected name in `Candidate.Parameter` (query candidates set
`Location=Query`). The source plus selector appear in the finding title,
detail, and dedup identity; different query parameters and storage keys
therefore remain distinguishable. The existing disjoint `"dom_xss"` tag
still guarantees that a DOM-XSS query finding never collides with a
Reflected-XSS finding on the same endpoint and query parameter.

## Two-phase design: canary reachability, then payload verification

UNCHANGED from piece 1, see below for the full description — reused
IDENTICALLY by all seven sources. The only new work per source is HOW the
canary/payload value reaches the browser before each navigation
(`domXSSExecutor.navigateSource`'s dispatch, `internal/scan/domxss.go`):

| Source | Injection mechanism | New Go helper |
|---|---|---|
| `location.hash` | encode into the URL fragment | `domXSSHashURL` (piece 1) |
| `location.search` | encode into a URL query parameter (one discovered name per independent probe; see below) | `domXSSQueryURL` (piece 2) |
| `window.name` | `Evaluate` on a neutral page, then navigate same page to target | `navigateWithWindowName`/`setWindowNameScript` (piece 2) |
| `postMessage` | navigate to target, then create an opaque-origin sandboxed `srcdoc` sender frame that posts to the target | `navigateWithPostMessage`/`postMessageScript` (piece 2; corrected to preserve untrusted sender origin/source semantics) |
| `document.referrer` | wrap in a synthetic absolute URL, pass as the navigation's Referer override | `navigateWithReferrer`/`domXSSRefererURL` (piece 3) |
| `localStorage` / `sessionStorage` | observe the target's present/read keys; for each bounded key, navigate to the same-origin root, write that exact key, THEN navigate to target | `discoverStorageKeys`/`navigateWithStorage` |

The sink-hook harness (`domXSSHarnessScript`), the reachability parser
(`parseDOMXSSReachability`), and the phase-2 verification signal
(`verification.MatchExecutionSignal`/`Decide`) are **the exact same code**
for every source — nothing about them changed in this slice.

### Why the query-string source uses a DIFFERENT encoder than the hash source

`domXSSQueryURL` deliberately uses Go's standard `net/url` query encoding
(`application/x-www-form-urlencoded` semantics, `"+"` for a space) rather
than `jsEncodeURIComponent` (which piece 1 built specifically for the hash
source). This is NOT an inconsistency to fix: unlike a URL **fragment**
(read raw via `location.hash`, with no built-in decoding at all), the
WHATWG URL parser **decodes a query string's `"+"` as a space itself**,
and `URLSearchParams` — the realistic way a page reads `location.search`,
and the API `detection.DOMSourceQuery`'s own doc comment names — implements
exactly that spec behavior. The two sources need, and get, genuinely
different encoders, matching how real browsers actually decode each one.

### How the query source selects parameters

A DOM-XSS "site" has no server-side parameter for Hash/WindowName/
PostMessage — but Query needs a parameter NAME to set. For the query source,
`domXSSExecutor.queryParamNames` reads the same
`store.Parameters().ListByEndpoint` registry that Reflected XSS populates,
selects every distinct non-empty `Location=Query` name, and sorts names
lexicographically before probing. Each name gets its own canary reachability
and payload verification pass; query names are not capped. The tested name
is carried in the candidate's `Parameter`, the finding's `ParameterName`,
the title/test notes, and the DOM-XSS dedup key. Thus multiple query
parameters at the same endpoint/source/sink produce separate findings.

An endpoint with no discovered query parameter is recorded as a skipped
TestCase saying `location.search` was **not tested** because no candidate
parameter was available. This is not a clean negative and is not silently
reported as safe.

## Wiring into the scan (extended)

- `enqueueDOMXSSProbes` now enqueues one `JobDOMXSS` per
  **(distinct navigable endpoint URL, source)** pair — i.e. up to SEVEN
  jobs per endpoint, one per `detection.DOMXSSSources` entry, instead of
  piece 1's one job per endpoint. `domXSSJob` gained a `Source` field;
  `parseDOMXSSJob` now requires it to be one of the seven valid values.
- `domXSSExecutor.Handle` now enumerates all query parameter names for the
  query source (sorted/deduplicated) and independently probes each one. For
  localStorage/sessionStorage it runs the observation-only target pass,
  enumerates present keys and intercepted `getItem` names, then tests up to
  32 sorted keys per backend; empty key sets and over-cap skips are explicit
  in TestCase notes.
- `domXSSExecutor.navigateSource` remains one source-generic navigation
  dispatcher, with source-specific injection mechanics. Query candidates
  receive the parameter name; storage candidates receive the key, while the
  backend remains the source label. Finding title/detail/dedup identity now
  distinguish each selector without changing Reflected-XSS correlation.
- Test-count impact: `internal/scan/executor_integration_test.go`'s
  `countDistinctNavigableURLs` test helper multiplies its endpoint count
  by `len(detection.DOMXSSSources)` (now 7, was 4) to independently
  re-derive the expected DOM-XSS job count — because this is computed
  from `len(detection.DOMXSSSources)` rather than a hardcoded literal,
  every integration test that asserts an exact job/test-case total
  against this helper picked up the new count AUTOMATICALLY, with no
  test edit needed (`TestScanCompletesAfterDiscoveryAndJobs`,
  `TestRestartRecoversAndResumesScan`, etc. — see
  `internal/scan/recovery_test.go`/`integration_test.go`) — this is
  exactly the fix piece 2 put in place for this recurring pitfall, now
  paying off on its own for piece 3.
- `browser.NavOptions` gained a `Referer` field, threaded through
  `pageHandle.Goto` (interface in `driver.go`, real implementation in
  `playwright.go`, fake test double in `manager_test.go` — all three
  updated together, per the documented repo pattern for interface
  extensions) — see "`document.referrer` — the Referer-override
  mechanism" above.

## Presentation

Live-verified (see "Live validation" below): all sources render on the
existing presentation surfaces with their source labels. Query findings
also show the selected query parameter; localStorage/sessionStorage findings
show the distinct backend and key. Non-parameterized sources retain the
source value in the existing `Parameter` field.

## Live validation

Piece 2's earlier live lab exercised `location.search`, `window.name`, and
`postMessage`; piece 3's earlier lab exercised `document.referrer`. The
source-selection changes in this update were revalidated with the actual
`indago` CLI and Chromium against a disposable, scope-limited local lab
(not a unit-test-only run):

- `/query?first=unused&x=unused` had a page script that reads only `x` and
  assigns it to `innerHTML`. Discovery found both query names. The first
  candidate (`first`) completed with `no HTML-injection sink reachable`;
  the independent `x` canary reached `innerHTML`, and its payload produced
  the browser signal `playwright: <marker> is not defined`.
- `/local` read `localStorage.getItem('profile_note')`; the CLI reported a
  Confirmed finding titled `DOM XSS: localStorage key "profile_note"
  reaches innerHTML at GET /local` and included the attacker-control caveat
  in both the finding summary and candidate rationale.
- `/session` read `sessionStorage.getItem('tab_note')`; the CLI reported a
  Confirmed finding titled `DOM XSS: sessionStorage key "tab_note" reaches
  innerHTML at GET /session`, with the same caveat.
- `/safe` read no storage value. The completed scan had zero DOM-XSS
  findings for that endpoint, and its localStorage/sessionStorage TestCases
  were both `skipped` with explicit `not tested: no storage key was present
  and no getItem key was observed` notes.

The CLI scan completed with 5 endpoints, 17 discovered parameters, 57
completed jobs, 3 Confirmed findings, 0 failed jobs, and no pending
findings. `finding show` identified the query parameter `x`, localStorage
key `profile_note`, and sessionStorage key `tab_note`; all three stored the
actual browser execution signal. The query TestCase notes show the inert
first parameter did not reach a sink before the `x` pass confirmed.

The latest scan does not claim storage exploitability from an Indago-only
write: it documents the manual attacker-control check in each storage
finding. All setup writes occurred in isolated Playwright contexts. The
existing `.invalid` Referer override behavior and its `decodeURIComponent`
requirement remain as described above; prior piece-3 live validation
confirmed that source separately.


## Out of scope for this slice (updated — explicitly, not an oversight)

To avoid anyone assuming "DOM XSS is done" — the following are real,
deliberate exclusions for future, separate pieces of work:

- **Sources**: ALL client-side sources identified so far are now
  implemented (hash, query-string, window.name, postMessage,
  document.referrer, localStorage, sessionStorage — see
  `detection.DOMXSSSources`). A genuinely new source not yet identified
  would still be new work, but nothing on the current list remains.
- **Sinks**: HTML injection only: innerHTML/outerHTML/document.write/writeln
  plus the two P2.1 methods above. `eval`/`Function`, `location`/`src`
  assignment (including script-src), and string timers remain excluded.
  Other HTML methods are not implicitly covered. Source-specific limits and
  the first-reachable-sink bound still apply; this is not exhaustive DOM XSS.
- **More than one reachable pair per endpoint/source/selector per probe
  pass**: if a page reaches TWO or more hooked sinks from the SAME selector,
  only the first (deterministic, by call order) is tested — unchanged
  boundary from piece 1, now applying to each query parameter/storage key.
- **Query parameter coverage when no query parameter was discovered**:
  an endpoint with no discovered `Location=Query` name has no candidate to
  test. Indago records a skipped/not-tested diagnostic, not a clean negative.
- **Storage keys not present or requested on the target page**: a backend
  with no existing keys and no observed `getItem` names is likewise marked
  skipped/not tested; no arbitrary key is seeded. The bounded 32-key cap is
  explicit in the storage discovery TestCase.
- **Stored DOM XSS** (a source that itself came from a stored/server-side
  value rather than purely client-side) — out of scope for the whole
  product, not just this slice (AGENTS.md §3).
- **Any sink/source combination this doc does not list above** — not
  silently incomplete, explicitly future work.

## Boundaries (same as Reflected XSS and piece 1, AGENTS.md §2)

No LLM verdict (the signal match/decide functions are the SAME
deterministic Go code Reflected XSS verification uses —
`verification.MatchExecutionSignal`/`Decide`, unchanged), no evasion, no
simulated user interaction, no exfiltration/weaponized payloads (every
candidate across all seven sources is a benign bare-marker probe, never
`alert(`/`document.cookie`/`fetch(`), every navigation goes through the
SAME scope-enforcing `browser.Manager` the rest of the product uses
(including the new neutral `about:blank` hop for window.name, itself never
subject to or evading the scope gate — `about:` URLs simply never leave
the browser), and evidence (screenshot, rendered DOM, browser log) is
always captured and never fabricated.

---

# Appendix: piece 1's original design (location.hash, for reference)

The sections below are piece 1's original content, preserved for the
mechanics that are UNCHANGED (the two-phase design, the harness, the
verification signal, percent-encoding rationale for the hash source
specifically).



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

## Out of scope for this slice (PIECE 1, HISTORICAL — see the top-level
## "Out of scope for this slice (updated)" section above for the CURRENT,
## accurate list; postMessage/window.name/query-string/document.referrer/
## localStorage/sessionStorage are now ALL implemented — only new SINK
## categories remain)

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

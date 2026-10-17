# Indago — DOM XSS (third slice: document.referrer, localStorage, sessionStorage)

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
argument, `insertAdjacentHTML`, `Range.createContextualFragment`) are
real, deliberate, separate future work. See "Out of scope" below.

---

## Scope of this slice

| Axis | Implemented |
|---|---|
| Sources | SEVEN (all client-side sources identified so far): `location.hash` (piece 1); `location.search`/`URLSearchParams`, `window.name`, `postMessage` (piece 2); `document.referrer`, `localStorage`, `sessionStorage` (piece 3 — `detection.DOMXSSSources`) |
| Sink category | Still exactly ONE, HTML injection: `Element.prototype.innerHTML` / `outerHTML` setters, `document.write` / `document.writeln` (`detection.DOMXSSSink`) — UNCHANGED from pieces 1/2, reused as-is |
| Pairs tested per endpoint per source | At most ONE — the first reachable sink, by whichever the page's own script happened to call first (see "Two-phase design" below) — same boundary as piece 1, now per source |
| Methods probed | GET/HEAD-navigable endpoints only — UNCHANGED from piece 1 |
| Query source coverage | Only endpoints with at least one DISCOVERED `Location=Query` parameter (reused from the SAME Parameter registry Reflected XSS already populates) — an endpoint with no discovered query parameter has nothing for this source to target, so it is skipped for that endpoint (documented, not silently incomplete) |

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

**These two detections are intentionally NEVER deduplicated against each
other**, even when they share an endpoint and parameter name — see
`domXSSFindingDedupKey`'s disjoint `"dom_xss"` tag (unchanged from piece
1) and the new, explicit
`TestQueryStringDOMXSSFindingDoesNotCollideWithReflectedXSSOnSameParameter`
test (`internal/scan/domxss_test.go`), which builds exactly this scenario
— a Reflected-XSS Finding and a DOM-XSS (query source) Finding on the SAME
endpoint and parameter name "q" — and asserts both exist as two distinct
Finding rows. Live-validated too: see "Live validation" below, where the
disposable lab's `/query` route reflects `x` server-side AND reads it
client-side, and the real scan produces exactly one `reflected_xss`
Finding and one separate `dom_xss` Finding for the same endpoint.

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

## `postMessage` — testing methodology (one of the least obvious sources)

The realistic vulnerable pattern is a page with its own
`window.addEventListener('message', ...)` handler that uses `event.data`
in a dangerous sink **without validating** `event.origin`/`event.source`
— in the real world this is exploitable by ANY other page/frame/popup that
holds a reference to this window (an `<iframe>` embed, a `window.open()`
popup, or a malicious page the victim visits that opens this one in a new
tab/window). Reproducing that exactly would need a second,
attacker-controlled origin actually hosting a page and getting the victim
to visit it or embed the target.

`navigateWithPostMessage` does the **mechanically equivalent thing without
a second origin**: navigate to the ALREADY-LOADED target page (same
browser context, same sink-hook harness every other source already uses),
then use `page.Evaluate` to run `window.postMessage(value, '*')` **directly
against that same, already-loaded page**. This faithfully simulates an
untrusted message arriving: the page's own listener has **no way to tell**
a message delivered this way apart from one delivered by a real
third-party frame — what the listener inspects is `event.origin`/
`event.source`/`event.data`, and none of those differ based on how
`postMessage` was invoked. Since the vulnerability being tested is
precisely "the listener does not validate the sender", nothing needs to be
faked on the sender side to test it validly; `'*'` as the `targetOrigin`
argument is this engine's own sender-side choice (delivers regardless of
the target's current origin, mirroring how trivially an attacker can do
the same) and says nothing about the target's own validation — that is
exactly what is being probed. The `Evaluate` call wraps the `postMessage`
in a short (300ms) `Promise`/`setTimeout`, which `page.Evaluate` awaits,
so the probe waits for the listener's own asynchronous reaction before
reading back console/page-error state.

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

## `localStorage` / `sessionStorage` — ORIGIN-scoped, not tab-scoped

Unlike `window.name` (persists across any same-tab navigation, even
cross-origin), `localStorage`/`sessionStorage` are **ORIGIN-scoped**: a
value written from a page on a DIFFERENT origin is simply invisible to a
page on the target's origin, no matter what tab/context it is in. This is
the one genuinely different piece of sequencing piece 3 needed —
`navigateWithStorage` (`internal/scan/domxss.go`):

1. install the sink-hook harness FIRST (before any navigation at all —
   Playwright re-runs it on every subsequent navigation this page makes,
   including step 4's target navigation, exactly like every other
   source);
2. navigate the SAME page to a harmless, SAME-ORIGIN page first — this
   engine uses the target's own origin ROOT (`domXSSOriginURL`, a pure
   helper that derives `scheme://host/` from the target endpoint URL),
   not a separate discovery step: it is guaranteed same-origin by
   construction and needs no extra lookup. (A 404 for the root path is
   fine — it is still a valid document on the right origin, which is all
   a storage write needs.)
3. set `localStorage`/`sessionStorage` via the browser package's EXISTING
   `Page.SetLocalStorage`/`Page.SetSessionStorage` (added in an earlier
   session, never used by any production code path until now — no new
   browser primitive was needed for this) under a fixed, documented key
   name, `indago_domxss_probe` (`domXSSStorageKey`) — there is no
   server-side parameter to derive a key from for this source, same
   boundary Hash/WindowName/PostMessage/Referrer already have;
4. THEN navigate (same page) to the target URL — the write from step 3 is
   now visible, since both navigations share the same origin.

`localStorage` and `sessionStorage` are modeled as TWO separate
`detection.DOMXSSSource` values (`DOMSourceLocalStorage`,
`DOMSourceSessionStorage`) sharing this ONE navigation helper
parametrized by backend — not two near-duplicate code paths, and not one
source with a hidden "backend" sub-field either: each gets its own,
independently labeled, independently Confirmed Finding (see "Live
validation" below), since the two backends have genuinely different
real-world read patterns (session-only vs. persistent) even though the
exploitation shape and sequencing are identical.

Still the SAME **(Endpoint, source, sink)** identity piece 1 established —
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

`detection.DOMXSSPayloadFor` now takes `source` as an explicit first
parameter (was implicitly always `DOMSourceHash`) and still reuses the
EXISTING `detection.Candidate` shape unchanged — `Context` still carries
the **sink** name, `ContextSub` still carries the **source** name. This is
the field an operator uses to tell a hash-sourced finding apart from a
query/window.name/postMessage-sourced one on every existing presentation
surface (CLI `finding show`, the web API's `parsed_detail`, markdown/HTML
reports) — zero new plumbing needed for this slice either, exactly the
same reuse piece 1 relied on. `domXSSFindingTitle`/`domXSSFindingDedupKey`
(both unchanged function signatures) already took `source` as a parameter
in piece 1's own code, so every new source's Finding is automatically
titled distinctly ("DOM XSS: `window.name` reaches `innerHTML` at GET
/winname") and deduped distinctly, with no further change needed there.

## Two-phase design: canary reachability, then payload verification

UNCHANGED from piece 1, see below for the full description — reused
IDENTICALLY by all seven sources. The only new work per source is HOW the
canary/payload value reaches the browser before each navigation
(`domXSSExecutor.navigateSource`'s dispatch, `internal/scan/domxss.go`):

| Source | Injection mechanism | New Go helper |
|---|---|---|
| `location.hash` | encode into the URL fragment | `domXSSHashURL` (piece 1) |
| `location.search` | encode into a URL query parameter (an EXISTING discovered parameter name — see below) | `domXSSQueryURL` (piece 2) |
| `window.name` | `Evaluate` on a neutral page, then navigate same page to target | `navigateWithWindowName`/`setWindowNameScript` (piece 2) |
| `postMessage` | navigate to target, then `Evaluate` a `postMessage` call against it | `navigateWithPostMessage`/`postMessageScript` (piece 2) |
| `document.referrer` | wrap in a synthetic absolute URL, pass as the navigation's Referer override | `navigateWithReferrer`/`domXSSRefererURL` (piece 3) |
| `localStorage` / `sessionStorage` | navigate to the target's own origin root, `Evaluate`-write via `Page.SetLocalStorage`/`SetSessionStorage`, THEN navigate to target | `navigateWithStorage`/`domXSSOriginURL` (piece 3) |

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

### How the query source picks WHICH parameter to target

A DOM-XSS "site" has no server-side parameter at all for Hash/WindowName/
PostMessage — but Query genuinely needs a parameter NAME to set a value
on. `domXSSExecutor.firstQueryParamName` resolves this by reading the
SAME `store.Parameters().ListByEndpoint` registry Reflected XSS's own
query-injection-point testing already populates, and picks the first
discovered `Location=Query` parameter (deterministic, by store order) — a
deliberate reuse of existing discovery data, never a new parallel
mechanism. An endpoint with no discovered query parameter is skipped for
this source only (recorded as a completed, no-op TestCase, never a
failure) — there is nothing to target without knowing a parameter name a
page's own JS might plausibly read.

## Wiring into the scan (extended)

- `enqueueDOMXSSProbes` now enqueues one `JobDOMXSS` per
  **(distinct navigable endpoint URL, source)** pair — i.e. up to SEVEN
  jobs per endpoint, one per `detection.DOMXSSSources` entry, instead of
  piece 1's one job per endpoint. `domXSSJob` gained a `Source` field;
  `parseDOMXSSJob` now requires it to be one of the seven valid values.
- `domXSSExecutor.Handle` is now source-generic: it resolves the query
  parameter (query source only), then dispatches navigation through
  `navigateSource` — one shared code path for all seven sources, branching
  only on the injection mechanism.
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

UNCHANGED from piece 1 — CLI `finding list`/`finding show`, the web API,
and the web UI's Findings tab all render every source's `dom_xss` Finding
through the SAME generic rendering Reflected XSS findings already use.
Live-verified (see "Live validation" below): all seven sources' findings
render correctly, each with a distinct, correctly-labeled title and
`Parameter` field ("location.hash" / "location.search" / "window.name" /
"postMessage" / "document.referrer" / "localStorage" / "sessionStorage").

## Live validation

Piece 2's disposable lab (`indago-domxss-lab2.py`) covered query-string/
window.name/postMessage; piece 3 used a NEW disposable lab
(`indago-domxss-lab3.py`, NOT part of the repo — same throwaway pattern)
with three routes, each genuinely needing its specific new source:

- `/referrer` — `document.getElementById('sink').innerHTML =
  decodeURIComponent(document.referrer)`. The `decodeURIComponent` call is
  REQUIRED, not cosmetic — see "`document.referrer` — the Referer-override
  mechanism" above for why a real browser's Referer header can never carry
  a literal, unescaped `<`, mirroring the hash source's own documented
  `decodeURIComponent(location.hash)` requirement.
- `/localstorage` — `document.getElementById('sink').innerHTML =
  localStorage.getItem('indago_domxss_probe')`.
- `/sessionstorage` — `document.getElementById('sink').innerHTML =
  sessionStorage.getItem('indago_domxss_probe')`.

A real scan (`indago scan create`/`start`, CLI, not a unit test) against
each route produced exactly one Finding per route, all Confirmed:

```
confirmed  high  dom_xss  DOM XSS: document.referrer reaches innerHTML at GET /referrer
confirmed  high  dom_xss  DOM XSS: localStorage reaches innerHTML at GET /localstorage
confirmed  high  dom_xss  DOM XSS: sessionStorage reaches innerHTML at GET /sessionstorage
```

Three DISTINCT, correctly-labeled Finding rows, each confirmed via the
SAME deterministic bare-marker signal every other source already uses
(`Uncaught ReferenceError: <marker> is not defined`) — proving the new
Referer-override mechanism and the origin-scoped storage pre-navigation
sequencing both actually work against a real Chromium browser, not just
that the Go code compiles. The FIRST attempt against `/referrer` (before
`domXSSRefererURL` existed) came back a clean, honest negative — see
"`document.referrer` — the Referer-override mechanism" above for exactly
what that looked like and why, caught by this live run and not by any
unit test.

## Out of scope for this slice (updated — explicitly, not an oversight)

To avoid anyone assuming "DOM XSS is done" — the following are real,
deliberate exclusions for future, separate pieces of work:

- **Sources**: ALL client-side sources identified so far are now
  implemented (hash, query-string, window.name, postMessage,
  document.referrer, localStorage, sessionStorage — see
  `detection.DOMXSSSources`). A genuinely new source not yet identified
  would still be new work, but nothing on the current list remains.
- **Sinks**: still only the three HTML-injection sinks from piece 1
  (innerHTML/outerHTML/document.write/writeln). `eval`/`Function`,
  `location`/`src` assignment sinks (e.g. `location.href = ...`, `<script
  src>` assignment), `setTimeout`/`setInterval` with a string argument,
  `insertAdjacentHTML`, `Range.createContextualFragment` are all still
  real, deliberate exclusions for a future, separate piece — THIS is now
  the only remaining axis of DOM-XSS coverage, not sources.
- **More than one reachable pair per endpoint per source per probe
  pass**: if a page reaches TWO or more hooked sinks from the SAME source,
  only the first (deterministic, by call order) is tested — unchanged
  boundary from piece 1, now applying per source too.
- **Query-string source without a discovered query parameter**: an
  endpoint whose query parameters were never discovered (e.g. no crawled
  link or user-provided seed ever exposed one) cannot be targeted by this
  source — a real, documented gap, not a silent one.
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

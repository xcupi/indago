# Indago — Reflected XSS Candidate Planner

For each context-classified reflection site, the planner answers one question:
**which breakouts are worth trying here, and in what order?** It produces those
candidates as *data*. It does not send them, and it makes no verdict. Code:
`internal/detection/candidate.go`.

This is the planning half of "context-aware candidate testing": *choosing* the
candidates. *Sending* them (active testing) and judging the result (verdict,
verification) are later, separately-gated phases and remain unbuilt.

## Guarantees

| Property | How it is enforced |
|----------|--------------------|
| **Pure** — no network, browser, LLM, clock, or randomness | `TestPlannerIsPure` parses the planner's real imports and fails on `net`, `os`, `time`, `math/rand`, other internal modules, … |
| **Deterministic** | `TestPlanDeterministic`: 20 runs over a multi-context body serialize byte-identically |
| **Data only, nothing sent** | the planner takes a `ReflectionReport` + bytes and returns candidates; it performs no I/O. The executor's state-changing safeguards are untouched |
| **Benign markers, not weapons** | `TestPlanCandidatesAreBenignMarkers`: every candidate embeds the benign marker and none contains an exfiltration/sink construct (`alert(`, `document.cookie`, `fetch(`, …) |
| **Descriptive & auditable** | every candidate carries a `Rationale`, the expected `Transformation`, and full provenance |

## What a candidate is

A `Candidate` is one planned breakout for one site, embedding a **benign marker**
(the probe token by default — an identifier/element a later verifier can observe,
never `alert(1)`, cookie theft, or network calls):

`Source` (`builtin`; reserved `llm`, advisory only) · `Category` · provenance
(`ScanID`, `InjectionPointID`, `Parameter`, `Location`, `SiteIndex`, `Offset`,
`Context`, `ContextSub`) · `Value` (the string to inject) · `Transformation`
(expected handling of the characters it needs) · `Priority` · `Rationale` ·
`DedupKey`.

Candidates live in the engine-specific `ReflectionReport.Plan` (persisted via
`TestCase.Detail`), so a future advisory source can append `Source:"llm"`
candidates to the same list **without changing the `TestCase` domain model**.

## Categories and the built-in set

Small and canonical by design — one or two breakouts per context, not a payload
library:

| Category | Context | Built-in candidates (marker = `M`) |
|----------|---------|-------------------------------------|
| `html_text` | element text, comment, RCDATA/RAWTEXT | `<svg onload=M>`, `<img src=x onerror=M>`, `<details open ontoggle=M>`, `<body onpageshow=M>` (the parser merges a second body tag's attributes onto the page's real `<body>`), `<svg><animate onbegin=M>` — five independent auto-firing vectors, so a filter blocking any one or two still misses the rest — plus a bare markup probe `<Mx>`; all prefixed with the construct's closer (`-->`, `</title>`, …) where needed |
| `html_attribute` | attribute value / name, tag name | quote-aware `"><svg onload=M>`, an in-tag `autofocus onfocus=M` handler (fires on load, no interaction — same character requirement as the onmouseover one below), and an in-tag `onmouseover=M` handler (which needs only the delimiter, not `<`/`>`) |
| `javascript` | JS string / template / code / comment / regex | quote-aware string escape `";M//`, plus two single-quoted *escape-breakers* for a reader that backslash-escapes the quote: `</script><script>M</script>` (needs no quote at all) and `\';M//` (its leading backslash consumes the reader's escaping backslash); template `${M}`, direct code `M` |
| `url` | URL attribute | `javascript:M` only at a scheme position (`start`, `relative_first_segment`); `data:` where plausible; nothing in a query/path/host |
| `css` | `<style>` body, `style=""` attribute | `</style><svg onload=M>` for the element body; quote-aware `"><svg onload=M>` for the attribute (closing the attribute's quote and the tag reaches markup regardless of whether the CSS before it is valid — same mechanism as any other attribute breakout) |
| `unknown_mixed` | unclassifiable / ambiguous | generic low-priority markup probes |

### Trigger classes and what "rejected" means

Every built-in candidate carries a `Trigger`:

- `load` — the marker is a bare JS expression that runs when the page loads
  (`<svg onload=M>`, `";M//`, `${M}`, direct code `M`, `</style><svg onload=M>`).
  Only these can be **confirmed** by passive browser verification.
- `interaction` — needs a user action the verifier deliberately never
  simulates (`onmouseover=M`, `javascript:M`, `data:text/html,…`).
- `none` — markup probes (`<Mx>`) that show markup is injectable but carry no
  executable reference.

So **Rejected means "no passive execution signal was observed for this
candidate", not "the parameter is not vulnerable"**: an interaction-only
candidate can reflect unescaped yet always ends rejected. This is a deliberate
limit (AGENTS.md §3: no simulated activation) — these findings now surface a
`ReviewReason`/`ReviewReasonLabel` ("needs manual review") instead of reading
as a clean negative; see `report.FindingSection`/`findingReviewReason`.
The coverage gaps it leaves — event handlers that need interaction, DOM-only
sinks, stored sinks — stay out of scope. A filter that only a differently-shaped
breakout would pass is now addressed too, but only as an explicit operator
opt-in (see "Evasion candidates (opt-in)" below), never by default.
Rejected/inconclusive attempts stay stored as diagnostics on the finding.

## Candidate profiles

A profile bounds how many planned candidates are *sent* per injection point. It
only **selects** from what context classification and transformation analysis
already planned (never adds or rewrites a candidate), is a pure function of the
plan, and keeps the plan's deterministic order. After filtering, if a reflection
context would be left with nothing, its best candidate is kept; then the cap is
applied taking one candidate per context first.

| Profile | Cap / injection point | Filter |
|---------|-----------------------|--------|
| `minimal` | 3 | load-trigger only; skip candidates the site neutralizes |
| `standard` (default) | 8 | none |
| `thorough` | 16 | none |

`max_candidates` (CLI `-max-candidates`, API `max_candidates`) overrides the cap
up to a hard ceiling of **32**; larger values are rejected at scan creation
(`ErrBadConfig`). Profiles do not alter rate limits, concurrency, scope checks,
or the state-changing opt-in, and have no bearing on verdicts.

## Transformation-aware priority

Each built-in lists the canary metacharacters (`<`, `>`, `"`, `'`) it depends on.
The planner checks the site's **per-character encoding** (from the reflection
step) and:

- all required characters survive raw → keep the template priority
  (`Transformation: "raw"`);
- some are encoded/stripped → **deprioritize, never drop** — the candidate is
  annotated (`Transformation: html|url|js|stripped|mixed`) and sunk below raw
  ones, so it is still tried if better options fail.

The one subtlety handled explicitly: HTML entity-encoding does **not** neutralize
a character the browser decodes before use. Inside an event-handler / `style` /
`srcdoc` / URL attribute (chain `[html_attr_value, …]`), `&quot;`/`&#39;` are
decoded back before the inner JS/CSS/URL parser sees them, so those candidates
keep full priority; the same encoding inside a `<script>` string does not
(`TestPlanTransformationAware`).

## Reflected JavaScript string contexts (measured)

Three authorized PortSwigger lab readers place a reflected value inside a
JavaScript string under different escaping rules. Each is reproduced byte for
byte by a loopback fixture (`internal/scan/jsstring_fixture_test.go`), which
asserts the exact served bytes and the analyzer's per-character classification
*before* the real-Chromium test (`TestReflectedJSStringContexts`) runs the whole
pipeline against it. This is the "measure before changing" record: the numbers
below are what the pipeline actually produced, not an expectation.

| Reader (served escaping) | Breakout that reaches code | Why |
|---|---|---|
| `var searchTerms = 'VALUE';` with `'`→`\'` and `\`→`\\` | `</script><script>M</script>` | A quote breakout is impossible: the reader escapes the escaping backslash too. The HTML tokenizer ends the `<script>` element at a literal `</script>` regardless of JS string state, and the fresh block's whole body is the marker. Needs no quote at all. |
| `var searchTerms = 'VALUE';` with `<`/`>`/`"` HTML-encoded and `'`→`\'` | `\';M//` | `<` and `>` are unavailable, so the script cannot be closed. The remaining route is the escape rule itself: the leading backslash consumes the backslash the reader inserts, leaving the closing quote raw. |
| ``var searchTerms = `VALUE`;`` with `<` `>` `'` `"` `\` and backtick all `\uXXXX`-escaped | `${M}` (the only shape this reader leaves open; see below) | The literal cannot be closed (backtick escaped) and the script element cannot be ended (`<`/`>` escaped), so interpolation is the only route; `$`, `{` and `}` are left alone. |

### Template-literal interpolation (`${MARKER}`) — escaping rationale

The third reader above is PortSwigger's "template literal" lab. Its rule, applied
to every reflected value, is exactly:

```
<  -> \u003c    >  -> \u003e    '  -> \u0027
"  -> \u0022    \  -> \u005c    `  -> \u0060
```

so a reflected `ind…<>"'end…` comes back as `ind\u003c\u003e\u0022\u0027end…`
inside `` var searchTerms = `…`; ``. Each escaping decision removes one shape and
leaves exactly one:

| Shape | Needs | Verdict for this reader |
|---|---|---|
| `';M//` / `";M//` | a raw quote | impossible: both quotes are `\uXXXX`-escaped |
| `\';M//` (escape-rule bypass) | a raw quote after the reader's own backslash | impossible: the backslash is escaped too |
| `</script><script>M</script>` | raw `<` and `>` | impossible: both are escaped, so the element cannot be ended |
| `` `;M// `` (close the literal) | a raw backtick | impossible: the backtick is escaped |
| `${M}` | nothing that is escaped | **the only route**: substitution evaluates its expression inside the literal |

`${MARKER}` therefore carries no quote, angle bracket, backtick or backslash at
all — it is the bare marker identifier wrapped in an interpolation — and it is
planned for the `js_string`/`template_literal` context at full priority. The
quote-breaking shapes stay planned for the `single_quoted`/`double_quoted`
sub-kinds that can use them; nothing was removed or weakened.

One dependency is deliberately *not* scored: the shape needs `$`, `{` and `}` to
survive, but the probe canary is fixed at `<>"'`
(`detection.canaryChars`), so the reflection step cannot observe what the reader
does to those three characters. The planner's contract is to annotate what it
*measured*, so it neither claims they survived (`raw` would be an unverified
claim) nor that they were neutralised (which would deprioritise the only
executable candidate for this reader): the candidate is planned at full priority
and sent, and a reader that escapes those characters as well keeps it inert
text. A neutralised control must therefore escape `$`, `{`, `}` (or the whole
opener as `\${`) — **HTML-escaping does not neutralise this shape**, because none
of `$`, `{`, `}` is HTML-special and character references are not decoded inside
a `<script>` element.

Both facts are pinned on a loopback fixture that serves the exact lab bytes
(`internal/detection/template_literal_test.go`): the escaped positive, the
byte-level neutralised control (`\u0024\u007b`…`\u007d`), the
`js_string:template_literal` classification with per-character `js` encoding,
and the plan being exactly `${M}`. The end-to-end outcome of that control
(reflected but never executed → **Rejected**) is covered by the `/safe-template`
control of `TestReflectedJSStringContexts`.

Measured verdict for the escaped positive: the candidate reaches an executable
position — Chromium raises `ReferenceError: <marker> is not defined` — but the
finding is **Inconclusive**, not Confirmed, because the shared verdict authority
(`internal/browser/provenance.go`'s `markerAtPosition`) is a conservative ASCII
allow-list that refuses any paused position in a script whose prefix opens a
template literal (`docs/verdict-provenance.md`). That is not a candidate gap and
cannot be fixed from the planner: *every* position inside the literal lives in
that script, so no breakout shape (interpolation or otherwise) can present the
marker in a script the lexer will accept. Teaching the lexer template-literal
state is a change to the shared verdict authority — its own slice, with the
forged-position regressions that must come with it — not something this
planner may work around by loosening the check.

Measured outcomes with the default `standard` profile and real Chromium:

- readers 1 and 2 → **Confirmed** by a marker-naming uncaught `ReferenceError`
  (`</script><script>M</script>` confirms the first; `\';M//` confirms the
  second after the two quote-based shapes correctly fail);
- reader 3 → reaches an executable position — Chromium raises
  `ReferenceError: <marker> is not defined` — but the verdict is
  **Inconclusive**, not Rejected: `internal/browser/provenance.go`'s
  `markerAtPosition` is a deliberately conservative ASCII allow-list that
  refuses any paused position in a script whose prefix contains a backtick
  (`docs/verdict-provenance.md`: "a regex or template literal … yields
  `Inconclusive` instead of `Confirmed`"). Teaching that lexer template
  literals is a change to the shared verdict authority, not a candidate gap;
  the positive is never reported as a clean negative.
- each context's fully-escaped safe control stays **Rejected**, and a
  non-reflecting control produces no finding.

Transformation note: the backslash escape-breaker lists `'` as the canary
character it depends on, so a reader that escapes the quote deprioritizes it
(never drops it) — the planner cannot tell from its canary whether the reader
*also* escapes backslash. The `</script>` escape-breaker needs only `<`/`>`, so
it stays high-priority exactly when those survive (the first reader) and is
deprioritized when they are HTML-encoded (the second). Consequence: the
`minimal` profile's `skip_neutralized` filter keeps only the canonical `';M//`
for the second reader and therefore cannot confirm it; the default `standard`
profile sends all three and does. The `Transformation` annotation on such a
winning candidate still reads `js` (the quote really was escaped); the candidate
is designed for exactly that reader.

## Reflected value inside a `<link>` attribute (canonical link, measured)

The canonical-link lab reflects a value inside
`<link rel="canonical" href='…?search=VALUE'>` in the document head, with `<` and
`>` HTML-encoded (quotes stay raw). Reproduced byte for byte by a loopback
fixture (`internal/scan/canonical_link_fixture_test.go`), which asserts the exact
served bytes before the analyzer sees them.

Measured at the base commit: the analyzer reports the innermost context as
`url:query` with chain `[html_attr_value, url]`, `element=link`,
`attribute=href`, `quote=single` — and `urlTemplates` deliberately plans nothing
for a query component, so the plan was **empty**. A reflecting site was therefore
completely unreported.

`templatesFor`'s `CatURL` case now also plans `linkAttributeTemplates`, which is
gated on the enclosing element being `link` with a real attribute and a known
delimiter:

| template | value | trigger | confirms? |
|---|---|---|---|
| link attribute injection | `' accesskey=x onclick=M y='` (quote style follows the site) | `interaction` | **never** by the passive verifier |

Why this shape and not a tag injection: a `<link>` is metadata. It has no
rendered box, the page never navigates its `href`, and no load-time event fires
on it, so neither `javascript:` nor `<svg onload>` can execute there. The value
is still inside an HTML attribute, though, so the closing quote alone ends it —
which is why encoding `<`/`>` does not stop this vector. That is the reported lab
vector: an `accesskey`/`onclick` pair on the link element itself, executable only
by an operator keypress. The passive verifier never simulates activation
(AGENTS.md §3), so the finding is created (the candidate reflects and is sent)
and honestly stays **Rejected**; the escaped control is Rejected too. Live
outcome, real Chromium: `TestReflectedCanonicalLinkVectorIsPlannedButNeedsActivation`.

Boundaries: the gate is the `link` element only. The same URL-in-attribute
position on an `<a>` the page itself navigates keeps its previous behaviour (no
planned candidate), so this slice adds no requests at ordinary anchors; the
`minimal` profile drops the candidate (it is load-trigger-only) exactly as it
drops the sibling `onmouseover` template.

### Raw-query `href` attribute breakout (measured: canonical-link class)

A **raw query-string** injection point that lands inside an `href` needs a shape
that actually leaves the attribute value. The `<link>` template above already
does that for link metadata, but it is element-gated, so it cannot cover the
general `href` position, and it does not exist for an anchor. `urlTemplates`
plans nothing for a query/path/fragment component, so before this shape a
raw-query URL site could reflect, be classified `url`, and still have no
breakout at all — nothing to activate, nothing that could ever confirm.

`urlHrefBreakoutTemplates` closes that gap with ONE shape per usable quote
style, planned only when the site is a URL nested in an `href` attribute
(`chain[0] == html_attr_value`, `attribute == href`) **and** the injection point
is the raw query string:

| template | value (double-quoted site shown) | trigger | confirms? |
|---|---|---|---|
| href attribute breakout | `"accesskey="x" onclick=M y="` (mirror shape; a single-quoted site gets `'accesskey='x' onclick=M x='` byte for byte) | `interaction` | yes, after the verifier's single click activation |

How it works: the leading delimiter closes the `href` value; the accesskey
attribute names the element — its VALUE is quoted with the same delimiter the
shape closes, so the whole breakout needs exactly one quote byte (the site's
own) to arrive raw — `onclick=M` carries the benign marker as the handler's
whole body; the trailing dummy attribute (`y=` for the double-quote mirror,
`x=` for the single-quote variant) plus the site's own closing delimiter keeps
the rest of the tag well-formed. Nothing but the marker is ever carried —
activating it executes `<marker>`, an unresolved identifier, which the verifier
observes as the marker-specific page error. The candidate declares
`interaction`, so the existing activation step performs exactly one
`element.click()` on the marker-carrying element; without that click the shape
stays inert (and a page with no handler stays Rejected after the click).

Why the accesskey value mirrors the delimiter instead of always using single
quotes: a double-quoted site commonly rewrites or filters `'` (HTML-encoding it
is routine) while leaving its own `"` raw. A hardcoded `accesskey='x'` on such
a site closes the attribute fine but the encoded value is decoded into the
attribute VALUE as the literal characters `'x'`, so the keybinding is lost
while the candidate still looks plannable. Mirroring removes that second,
undeclared dependency: the double-quote family carries no single quote at all,
and the single-quote variant keeps its historical bytes exactly (including
`accesskey='x'`), because there the delimiter and the value quote are the same
character anyway.

Quote handling is taken from the analyser, never assumed: a `double`- or
`single`-quoted site gets its own delimiter, and any other position (including
an unquoted value, which ends at whitespace rather than at a closable
delimiter) gets no shape. The shape is **strict** about it:
`strictSurvives` checks the delimiter with no entity-decoding exemption, because
an HTML-encoded quote (`&quot;`) is decoded by the browser into the attribute
*value*, where it is an ordinary character and can never terminate the
attribute. When the reflection analysis proves the delimiter is encoded, the
shape is **not planned at all** (dropped, not merely deprioritized) — sending it
would only produce a request that cannot break out. Every other canonical
template keeps `survives`' existing behaviour, unchanged.

Gating and default behaviour: the shape is added only for `LocationRawQuery`,
which is itself opt-in and off by default (`-raw-query-injection`), so a default
named-parameter plan is byte-identical. `TestURLAttributeBreakoutDefaultCandidateSetUnchanged`
freezes both sides: the named-parameter plan is exactly what it was, and the
raw-query plan is that same frozen set plus this one shape. Real-browser proof:
`TestURLHrefBreakoutConfirmsAfterOneClick` (raw delimiters → Confirmed, one
dispatched click, injected pair in the rendered DOM) and
`TestURLHrefBreakoutEncodedDelimiterStaysRejected` (HTML-encoded quotes → the
shape is not planned, and forced through the verifier it stays Rejected with the
marker still reflected). `TestDoubleQuoteBreakoutNeedsOnlyTheDoubleQuote` pins
the mirror's invariant against served bytes: a double-quoted `href` that
HTML-encodes `'` still gets the click-class candidate, and that candidate
contains no single quote.

## Ordering and deduplication

Candidates are deduplicated by `category + value`, keeping the highest-priority
instance (ties → earliest site, then lowest offset). The final list is sorted by
**priority desc, then category, then value** — a total order over distinct
candidates, which is what makes the output deterministic.

## Execution

The planner itself sends nothing — it is a pure function from a classified
reflection report to an ordered candidate list. The scan **executor** acts on
that list (`internal/scan/candidate.go`): the reflection job enqueues one child
`JobTest` per candidate (job priority = candidate priority, so the queue drains
them in plan order; the plan's dedup means one request per unique candidate).
Each child sends its single breakout into the injection point — other parameters
unchanged — through the scope-enforcing engine, re-runs reflection + context
analysis on the response, and records reflected/not_reflected plus evidence. It
does not re-plan (no recursion), makes no verdict, and does no browser
verification. See [`scan-orchestration.md`](scan-orchestration.md).

## Boundaries

No verdict, no exploit generation, no LLM. Candidate values embed a benign
marker and are sent only to in-scope targets; state-changing methods require
the operator opt-in. Browser verification only observes the same navigation a
candidate step already made (GET, or POST+form — see `scan-orchestration.md`
and `AGENTS.md` §3); it never simulates clicks/hovers. Obfuscation/evasion
variants exist only behind the explicit `EnableEvasion` opt-in described
above — never in the default candidate set. See `AGENTS.md` §2–§3.

## Header/Cookie/Path injection points

Candidate planning and execution are location-agnostic — the pipeline
(reflect → context-analyze → candidate-plan → candidate-execute →
browser-verify → finding-correlate) does not care whether the mutated value
came from a query string, a form field, a JSON body field, a request
header, a cookie, or a URL path segment. Discovery registers injection
points for three additional `domain.ParamLocation` values beyond
Query/Form/JSON:

| Location | What gets registered | Baseline behavior | Mutated behavior |
|----------|----------------------|--------------------|-------------------|
| `header` | A small, conservative DEFAULT set — `User-Agent`, `Referer`, `X-Forwarded-For` — on **every** discovered endpoint (`internal/discovery/extra_locations.go`). Not derived from observed traffic. | The baseline request sends whatever header the HTTP engine would normally send; the parameter's header is left completely untouched. | `buildRequest` (`internal/scan/executor.go`) clones the baseline headers and overrides **exactly the one** header this injection point targets — every other header (auth headers, the session cookie header, the engine's default User-Agent for every *other* header candidate) is left alone. |
| `cookie` | Cookie names/values found in the saved session state, excluding names recognized as the session's own authentication cookie (`isSessionCookieName`: liberal matching for `sess`/`sid`/`auth`/`token`/`jwt`/`csrf`/`xsrf`). Cookies retain storage-state domain/path/scheme/expiry metadata; `scopedEngine` applies that scope to every request and redirect. A scan with no saved cookies registers none. | Only saved cookies whose host/domain, path, scheme, and expiry match this URL are sent; unrelated cookies in the state are withheld. | `buildRequest` creates the targeted marker override. It wins over a same-named saved cookie when that cookie's scope applies to the request; it follows redirects only while the stored cookie scope still matches. Other saved cookies remain independently scoped. |
| `path` | Only a URL path **segment** that looks like a variable value — purely numeric, UUID-shaped, or an opaque alphanumeric slug containing a digit (`internal/discovery/path_segments.go`'s `QualifyingPathSegments`) — never a literal route keyword (`api`, `v1`, `admin`, `login`, …; see `routeKeywordSegments`). An endpoint whose path has no qualifying segment registers zero Path injection points. The `Parameter.Name` encodes the segment's position (`path[N]`) so `buildRequest` recomputes the identical split from the endpoint's own URL. | The baseline URL already has the right segment value (it came from the URL itself) — nothing to add. | `buildRequest` rewrites exactly that one path segment with the candidate value; the mutated URL carries the marker directly, the same way a Query candidate does. |

Browser verification carries the SAME override into the verifying browser
context, before navigation: `verification.Input.ExtraHeaders` /
`ExtraCookies` (set by `internal/scan/verify.go` from the candidate's
`Location`) flow into `browser.ContextOptions.ExtraHeaders` (merged into the
context at creation, Playwright's own `ExtraHttpHeaders`) and
`browser.Context.SetCookies` respectively — both applied before `Navigate`.
Path needs no special verification handling: the marker is already literally
part of the navigated URL, exactly like Query.

Everything else about these locations is identical to Query/Form/JSON: the
same candidate templates, the same profile bounding, the same Confirmed/
Rejected/Inconclusive verdict lattice, the same Finding correlation. Multi-
parameter/combined injection (mutating more than one location at once) is
now implemented for a bounded, deterministic subset — see below. Standalone
PoC generation (reusing this same location data) is implemented too — see
"Standalone PoC generation" below.

`internal/detection/evasion.go` is a second, separate template generator,
called by the planner ONLY when `PlanOptions.EnableEvasion` is true — itself
only ever set when the operator turns on `ScanConfig.EnableEvasion` (CLI
`scan create -enable-evasion`; API `enable_evasion`) for that scan. Default:
off, and the canonical set (above) is completely unaffected either way — these
candidates are planned *in addition to*, never instead of, the canonical ones.

Rationale: a WAF/filter bypass is itself a valid, often-rewarded bug bounty
finding. Indago's canonical candidates intentionally try only the literal,
unobfuscated breakout shape; that alone cannot find a bypass a naive filter
happens to miss. This generator closes that one specific, scoped gap — nothing
else changes (same scope enforcement, same rate/concurrency limits, same
benign-marker-only rule, same lack of exploit generation).

Current techniques (`Candidate.Technique`, same `candTemplate`/`Candidate`
shape as the canonical set). They are load-triggered except where stated — an
evasion variant of an interaction-only shape would be just as unconfirmable as
the canonical one already is:

| Technique | Idea | Reliability |
|-----------|------|--------------|
| `case_variation` | `<SvG OnLoad=M>` — mixed-case tag/attribute name | bypasses a case-sensitive literal-string filter |
| `alt_separator` | `<svg/onload=M>` / a tab instead of a space before the attribute | valid HTML5 (the tokenizer treats `/` and tab as attribute-boundary whitespace here); bypasses a filter expecting a literal space |
| `double_url_encoding` | the breakout pre-encoded (`%3Csvg...%3E`), which the transport encodes again on the wire | opportunistic only — works solely against a target that decodes twice (e.g. a WAF that decodes once to inspect, then an app that decodes once more); a single-decode target will reflect the literal percent-string, which is the correct, honest outcome, not a false negative |
| `allowlisted_tag_event` | `<body onresize=M>` — the exact tag+event pair a body/onresize allow-list admits | a real bypass of that filter class, but the resize event is never produced by a passive page load. Tagged `interaction`: the verifier records the candidate as **Rejected** (never Confirmed by accident) and the finding is flagged for manual review. The lab's own exploit supplies the resize from an attacker-controlled iframe, which a candidate value cannot carry; the local fixture proves the handler throws the marker `ReferenceError` the moment a genuine viewport resize happens |
| `custom_element_focus` | `<x-M autofocus tabindex=1 onfocus=M></x-M>` — a custom element (the only tag class an "all standard tags blocked" filter admits) plus a focus trigger | fires on load: `tabindex` makes the custom element focusable, `autofocus` focuses it during parsing, and `onfocus` evaluates the bare marker. If the page already has an earlier `autofocus` element, that one consumes the trigger; the lab's `#x`-fragment delivery is a human-payload alternative a reflected candidate value cannot express |
| `svg_smil_begin` | `<svg><animatetransform onbegin=M attributeName=transform></svg>` — an SVG SMIL element whose `begin` event fires when the animation starts | fires on load (SMIL's default `begin="0s"`); covers an allow-list that admits `animatetransform` while blocking both `<svg onload>` and `<animate>` |


`escaped_quote_prefix` (a leading backslash that absorbs a naive quote-escaping
pass, the classic `addslashes()` bypass) remains an evasion-only technique for
**double-quoted** JS strings. Its single-quoted form is now a *canonical*
candidate — a server that backslash-escapes the quote is an ordinary reader,
not a filter, so every scan tries that shape without an opt-in. See
"Reflected JavaScript string contexts (measured)" below.

Explicitly NOT in scope here, and not planned: request-fingerprint spoofing,
TLS fingerprint randomization, IP/proxy rotation, timing jitter, CAPTCHA
handling. That class of evasion depends on infrastructure a single local
scanner process does not have — adding it would be a materially different,
larger change and needs its own explicit decision, not a quiet extension of
this generator.

### Filter-allow-list shapes

The rewriting techniques above assume the filter is trying to *recognize* a
breakout and can be confused. A different, common class does not pattern-match
at all: it allows only a tiny, fixed set of tag names and event-handler
attributes, rejecting everything else. Reshaping `<svg onload=M>` cannot help
there — the **tag** is blocked — so the only possible bypass is the exact
construct the allow-list was written to keep. `internal/detection/evasion.go`
therefore adds three bounded, deterministic shapes of that class (HTML-text
context only, priorities 44/42/40, never a generated payload library):

| Allow-list (documented lab) | Surviving construct | Trigger |
|---|---|---|
| most tags/attributes blocked; `body` + `onresize` survive | `<body onresize=M>` | resize event — **not** supplied by a passive load; stays Rejected and flagged for manual review |
| all standard tags blocked except custom/unknown ones | `<x-M autofocus tabindex=1 onfocus=M></x-M>` | `autofocus` + `tabindex` focus the custom element on load → `onfocus` |
| most tags blocked; some SVG markup (`animatetransform`) survives | `<svg><animatetransform onbegin=M attributeName=transform></svg>` | SMIL `begin` fires when the animation starts (default `0s`) |

All three embed only the benign marker; nothing runs until the browser
dispatches the named event, and the handler body is the bare marker
(a `ReferenceError`, never `alert`/cookie/exfiltration).

**Why `allowlisted_tag_event` is tagged `interaction`.** `onresize` is a
genuine event, not a user gesture, but a page load does not resize the
viewport: the lab's published exploit delivers the payload inside an iframe
and changes *that iframe's* width. Indago's verifier navigates once and
deliberately never synthesizes a resize or any other activation, so it records
this candidate **Rejected** ("no passive execution signal") and the finding
carries the manual-review reason — the bypass is real and worth reporting, but
a human must supply the trigger. Labelling it `load` would be false and would
let the `minimal` profile send it as confirm-capable. A local fixture proves
the handler is real: with a genuine viewport resize (`Page.SetViewportSize`,
not a synthetic event) the page throws
`Uncaught ReferenceError: <marker> is not defined`; without the resize it
throws nothing.

**Profiles.** These are planned *in addition to* the six canonical HTML-text
candidates, the nine pre-existing evasion shapes, and the two variation-pack
values that are not already canonical — 17 candidates for an HTML-text site
with the opt-in on (see "Variation packs (opt-in)" below; the same operator flag
gates both). The default `standard` profile caps at 8 per injection point and
canonical candidates sort first, so it sends the six canonical shapes plus the
two variation-pack values and none of the evasion shapes. For a filter-allow-list
engagement use `-candidate-profile thorough` (cap 16) or `-max-candidates`,
exactly as for the existing evasion set — this slice does not change profile
semantics.

**Fixture proof (`internal/detection/evasion_filter_test.go`).** Each lab is
reproduced as an allow-list over tag names and `on*` attributes, driven through
a real HTML tokenizer:

- every canonical payload for the site is **rejected** by each fixture (so the
  fixture reproduces a filter, not a no-op);
- an independently executable control (`<svg onload=M>`, which confirms on the
  unfiltered control page) is **rejected by every fixture** — a permissive
  matcher would wrongly admit it;
- exactly the shape a technique claims is **admitted**, and the other labs'
  shapes are rejected (the three allow-lists are disjoint);
- a golden test freezes the entire default (evasion-off) plan — 20 candidates
  across every category, values, priorities, triggers — so the default
  candidate set cannot change silently.

**Live validation** against the loopback-only lab
(`/home/udalah/Documents/Developments/indago_lab/ps-filter-evasion/lab.py`,
which returns 403 for a value containing a tag/event outside its allow-list;
the 403 body never echoes the value). Real binary, real Chromium, one scan
(`01420756-b077-4616-a8cf-5c5d31f7163e`) with `-enable-evasion
-candidate-profile thorough` over four seeds:

| Seed | Filter admits | Verified outcome |
|---|---|---|
| `/lab1` | `body` + `onresize` only | the body/onresize candidate reflects and is **Rejected** (needs the external resize); no canonical shape reflects |
| `/lab2` | custom tags + `onfocus` | only `<x-… autofocus tabindex=1 onfocus=…>` is **Confirmed** (marker-specific `ReferenceError`) |
| `/lab3` | `svg` + `animatetransform`, `onbegin` only | only `<svg><animatetransform onbegin=…>` is **Confirmed**; `<svg onload>` and `<svg><animate onbegin>` are refused with 403 and produce no finding |
| `/open` | no filter (control) | canonical `<svg onload>` and the rest are **Confirmed**, including the new custom/SVG shapes; `<body onresize>` still Rejected (no resize) |

The three 403-refusals surface as the engine's existing "possible block/filter"
diagnostic (inconclusive, informational), never as an XSS verdict — the filter
is not mistaken for a negative, and a blocked vector is never Confirmed.

`TestEvasionCandidatesAreOffByDefault`, `TestEvasionCandidatesAreAdditive`
and `TestEvasionCandidatesAreBenignMarkers` (`internal/detection/
evasion_test.go`) enforce exactly these properties: off unless asked for,
additive never destructive, and still benign-marker-only — the same
guarantee `TestPlanCandidatesAreBenignMarkers` holds for the canonical set.

## Variation packs (opt-in)

The canonical set answers "what is the most likely breakout at this site?".
That is one answer per context, so one filter, one rewritten character, or one
browser-specific "not this shape here" hides the injection point completely.
The variation packs add a small, ordered set of **mechanism-distinct** fallbacks
per reflection context — image-error vs SVG-load vs toggle vs handler-free
script vs `</script>` breakout — so a single blocked vector is not the end of
the test. They are not a fuzzer: the packs are literal tables, at most five
variants per context, with fixed priorities and no mutation.

Implementation: `internal/detection/variation.go`; `Candidate.Variation` names
the mechanism, `Candidate.Technique` stays empty (a variation is an alternative
mechanism, not a filter-bypass technique).

### Gate and default behaviour

Nothing is planned unless `PlanOptions.EnableVariationPacks` is set, **or** the
scan already opted into evasion (`PlanOptions.EnableEvasion`) — the operator
flag that already exists end to end (`scan create -enable-evasion` / API
`enable_evasion`). The named field exists so a direct planner caller, or a
future dedicated flag, can ask for the packs alone; a dedicated CLI/API flag
would touch files outside this slice and is not added here.

The default plan is byte-identical to before the packs existed:
`TestVariationPacksOffByDefault` (no `Variation` tag, `VariationCapped == 0`,
6/6 candidates for an HTML-text site) and the frozen golden
`TestEvasionDefaultCandidateSetUnchanged` (20/20 candidates across six contexts,
values, priorities and triggers unchanged) both enforce it.

### The packs

Marker = `M`. `q` is the site's own attribute delimiter (`"`, `'`, or empty for
an unquoted value). "Canonical dup" means the pack deliberately repeats a shape
the canonical set already plans, at the same value, so each pack is a complete
ordered answer for its context; deduplication collapses it onto the canonical
candidate (the canonical instance wins, so `Variation` stays empty there).

| Context (analyzer) | Variant | Mechanism | Trigger |
|---|---|---|---|
| `html_text` (element/body content) | `<svg onload=M>` | `svg_load` (canonical dup) | load |
| | `<img src=x onerror=M>` | `img_error` (canonical dup) | load |
| | `<script>M</script>` | `inline_script` — parser-executed element, **no event handler** | load |
| | `<details open ontoggle=M>` | `details_toggle` (canonical dup) | load |
| | `<svg><script>M</script></svg>` | `svg_script` — foreign-content script element | load |
| `html_attr_value` (quoted + unquoted) | `q"><svg onload=M>` | `tag_breakout_svg` (canonical dup) | load |
| | `q autofocus onfocus=M x=q` | `in_tag_focus` (canonical dup; no `<`/`>` needed) | load |
| | `q"><script>M</script>` | `tag_breakout_script` | load |
| | `q"><img src=x onerror=M>` | `tag_breakout_img` | load |
| | `q"><details open ontoggle=M>` | `tag_breakout_details` | load |
| `js_string` (single/double quoted) | `';M//` / `";M//` | `quote_breakout` (canonical dup) | load |
| | `</script><script>M</script>` | `script_restart` (canonical dup single; new for double) | load |
| | `</script><svg onload=M>` | `script_close_svg` | load |
| | `</script><img src=x onerror=M>` | `script_close_img` | load |
| | `</script><details open ontoggle=M>` | `script_close_details` | load |
| `js_string:template_literal` | `${M}` | `interpolation` (canonical dup) | load |
| | `` `;M// `` | `literal_close` | load |
| | `</script><script>M</script>` | `script_restart` | load |
| | `</script><svg onload=M>` | `script_close_svg` | load |
| | `</script><img src=x onerror=M>` | `script_close_img` | load |
| `script_block` (inert data block, or a JS code position) | `</script><svg onload=M>` | `script_close_svg` | load |
| | `</script><script>M</script>` | `script_restart` | load |
| | `</script><img src=x onerror=M>` | `script_close_img` | load |
| | `</script><details open ontoggle=M>` | `script_close_details` | load |
| `url` at a scheme position | `javascript:M` | `scheme_injection` (canonical dup) | interaction |
| | `javascript&colon;M` | `entity_colon` — decoded before URL parsing | interaction |
| | `\tjavascript:M` | `leading_whitespace` — URL parser strips it | interaction |
| | `data:text/html,<script>M</script>` | `data_uri` | interaction |

`script_block` maps to the analyzer's `unknown:script_data_block` (a
`<script type="text/plain">`-style body a browser never executes, so the direct
marker is inert and **only** a literal `</script>` leaves it) and to
`js_code` positions, where the same shapes are a fallback if direct code is not
the route the page offers.

Every variant is a benign-marker probe: the handler/script body is the bare
marker, so execution raises `ReferenceError: <marker> is not defined`. No
`alert`, cookie access, network call, or DOM exfiltration is generated
(`TestVariationCandidatesAreBenignMarkers`).

**Interaction-only variants.** The four `url` shapes need the link to be
activated, which the passive verifier deliberately never simulates
(AGENTS.md §3), so they are tagged `interaction` — the same trigger class the
evasion allow-list work introduced. They stay **Rejected** and the finding
carries the manual-review reason. Every other pack leads with `load` variants.

**`needs` handling.** A variation whose required canary characters the site
provably neutralizes is **not planned at all** (the packs are opt-in extra
requests; an impossible shape would only add noise). Canonical candidates keep
their older deprioritize-never-drop rule. Example: HTML-text reflection with
`<`/`>` entity-encoded gets no `<>`-dependent variation, and a JS string whose
quote came back backslash-escaped still gets the script-element routes but not
the quote breakout.

### Bounded arithmetic

- Pack size: at most **5** variants per context (`maxVariantsPerContext`).
- Six contexts × 5 = **30** template entries is the theoretical ceiling for a
  response reflecting into every context, but one reflection site has exactly
  one innermost context, so a site contributes at most 5.
- Deduplication collapses identical `category + value` entries: 3 HTML-text,
  2 attribute, 2 JS-string, 1 template-literal and 1 URL pack entry are
  canonical duplicates, and the `</script>` family is shared across the JS
  contexts. A single-context HTML-text site with the opt-in on is therefore
  6 canonical + 2 new variation values = **8** planned candidates.
- The whole plan additionally caps distinct variation candidates at
  `MaxVariationCandidatesPerInjectionPoint` = **10** after sorting by priority;
  the overflow is reported as `CandidatePlan.VariationCapped`, never silently
  lost. Worst realistic case (one site in each of html, attribute, js_string,
  url, script_block) is 14 distinct pack values → 10 kept, 4 reported capped.
- Requests sent are still bounded by the candidate profile: `minimal` 3,
  `standard` 8, `thorough` 16, operator override ≤ hard ceiling **32**. The
  packs never bypass that selection.

### Validation: first variant blocked, a later one still confirms

Pure half (`internal/detection/variation_filter_test.go`) — for each of the six
contexts, a realistic server-side filter rewrites the value so the **first**
pack variant is neutralised while the claimed later variant passes through
byte-identical, and the planner still plans that survivor from the filtered
canary response:

| Context | Filter | First variant (blocked) | Survivor |
|---|---|---|---|
| html | strips `on*=` attributes and `<svg` openings | `<svg onload=M>` | `<script>M</script>` |
| attribute | same | `"><svg onload=M>` | `"><script>M</script>` |
| js_string | backslash-escapes quotes, disables `<script` openings | `';M//` | `</script><svg onload=M>` |
| js_template_literal | `\uXXXX`-escapes `$`, `{`, `}`, backtick, quotes and backslash; disables `<script` openings | `${M}` | `</script><svg onload=M>` |
| script_block | disables `<svg` | `</script><svg onload=M>` | `</script><script>M</script>` |
| url | removes the literal `javascript:` | `javascript:M` | `javascript&colon;M` |

Real-Chromium half (`internal/scan/payload_variation_integration_test.go`, build
tag `browser_integration`): one loopback lab serves a raw and a filtered route
per context; one scan with the evasion opt-in (which also enables the packs)
must produce a **Confirmed** finding at every filtered route, with the
confirmed candidate equal to the surviving later variant. The URL route is the
honest exception: the entity-encoded colon reflects (the filter is bypassed) but
a `javascript:` URL needs activation, so the verdict is Rejected and the finding
is flagged for manual review — never Confirmed by a passive load.

Measured outcomes are recorded in the run handoff
(`ps-payload-variation/HANDOFF.md`); this section describes the contract the
tests enforce, not a claim about an unrun target.

Measured on the loopback lab (real Chromium, one scan with the opt-in, standard
profile), marker `M` per injection point: the filtered route confirmed with
exactly the surviving variant — `<script>M</script>` (html), `"><script>M</script>`
(attribute), `</script><svg onload=M>` (js_string and js_template) and
`</script><script>M</script>` (script_block) — while the unmodified shapes were
rejected or stripped. On the raw html/attribute/js_string/script_block routes
the variation shapes confirmed alongside the canonical ones. Two honest
exceptions: the canonical `${M}` stays **Inconclusive** (the documented
template-literal provenance limit) and the pack's `</script><svg onload=M>` is
what turns that site into a **Confirmed** finding; and the `url` route stays
**Rejected** because none of its variants can fire without activation.

## Combined (multi-parameter) candidates

Every candidate described above mutates exactly ONE parameter per request.
A real class of reflected XSS needs TWO parameters controlled
simultaneously in the SAME request to break out — the classic case: one
parameter's value sits inside a partially-defended HTML attribute and alone
can't both close the attribute AND add a new one, but a SECOND parameter,
reflecting afterward in the same response, can supply the rest. This
section is a small, BOUNDED, deterministic fallback probe for exactly that
class — never an open-ended combinatorial fuzzer.

### Scope (deliberately narrow)

- **Pair only, never a triple+.** Exactly two parameter slots per combined
  candidate.
- **Same classified context only.** Both parameters must have individually
  REFLECTED during single-parameter candidate testing (reusing the existing
  per-parameter reflection/context analysis — this never re-detects
  reflection) AND landed in the SAME classified `Context`: `html_attr_value`
  or `js_string`. Cross-context pairs (e.g. one `html_attr_value`, one
  `js_string`) are out of scope — too speculative to reason about safely.
- **Fallback only, never parallel/always-on.** Combined pairing runs for an
  endpoint ONLY when that endpoint's single-parameter candidate testing
  already ran and did NOT produce a `Confirmed` finding there (see
  `endpointHasConfirmed`, `internal/scan/combined.go`). It never doubles a
  scan's request volume on an endpoint single-parameter testing already
  cracked.
- **Hard ceiling.** At most `maxCombinedPairsPerEndpoint` = **5** pairs are
  ever tested per endpoint, picked deterministically (sorted by parameter
  name, then injection point ID — never randomly, never by discovery
  timestamp order this layer doesn't see). This mirrors the candidate-profile
  ceiling pattern (`minimal`/`standard`/`thorough`, ceiling 32) as precedent
  for "bounded by design, not unlimited".
- **Two context categories only.** `internal/detection/combined.go`'s
  `PlanCombinedCandidate` returns real templates for exactly `html_attr_value`
  and `js_string` — every other context returns `(nil, false)`, never a
  generic/unknown combined template.

### The two templates (each a split of an EXISTING single-parameter template)

| Context | First ("closer") half | Second ("breakout") half | Same idea as |
|---|---|---|---|
| `html_attr_value` | its own quote (if any) + `">"` — closes the attribute AND the tag; carries NO executable reference | `<svg onload=M>` — a brand-new element with an onload handler referencing the marker; needs `<`/`>` but no quote of its own | the single-parameter onload template `q+"><svg onload=M>"` (`htmlAttrTemplates`), split at the point where the attribute/tag close ends and the new element begins |
| `js_string` | its own quote + `;` — closes the JS string and terminates the statement; carries NO executable reference | `M//` — a bare marker reference plus a line comment swallowing whatever static text follows; needs no quote of its own | the single-parameter string-escape template `";M//` / `';M//` (`jsTemplates`), split at the point where the string closes and the breakout code begins |

Both templates are a *natural decomposition* of the matching single-param
template, not an unrelated new payload shape — see `combinedHTMLAttr`/
`combinedJSString` in `internal/detection/combined.go` for the exact
character-level reasoning (which half needs which canary metacharacter).
`js_string`'s `template_literal` sub-kind has no closing-quote character to
split on, so it returns `(nil, false)` — only `double_quoted`/`single_quoted`
are supported.

A realistic "genuinely needs two parameters" site: a WAF/sanitizer blocks
the recognizable `"`+`<` (or `"`+space) signature at the FIRST parameter
(defeating its own onload/autofocus/onmouseover templates, which all need a
quote plus one of those) while leaving a bare quote+`">` through untouched
(exactly what the combined closer needs and nothing more); a DIFFERENT,
more lenient filter at the SECOND parameter always strips quotes
unconditionally (defeating its own templates, which also need a quote) but
leaves `<`/`>` untouched (exactly what the combined breakout needs and
nothing more). Neither parameter's own complete single-parameter template
can get past its own site's filter, but the pair completes the identical
breakout because neither half needs what the OTHER half's filter blocks.
`indago-combined-lab.py` (workspace-local, disposable) implements exactly
this scenario and live-validates it end to end with a real Confirmed
finding.

### Request building, identity, and presentation

One real HTTP request carries BOTH overrides — the executor's `injection`
struct (`internal/scan/reflection.go`) gained an optional `paramB`/`valueB`
pair, and `buildRequest` (`executor.go`) applies whichever of `param`/
`paramB` matches each parameter, exactly like the single-override path.
Browser verification is the SAME navigation/request mechanism, unchanged —
confirmed live, not assumed (see below): `verifyExecutor.run` resolves the
second parameter from the already-loaded endpoint parameter list (by the
name+location the combined candidate itself carries) and threads both
overrides into the one request/navigation, including both
`ExtraHeaders`/`ExtraCookies` when either half is a Header/Cookie location.

A combined candidate is carried as an ordinary `detection.Candidate` with
new optional fields — `Combined bool`, `ParameterB`/`LocationB`/
`InjectionPointBID`/`ValueB` for the second half — rather than a new type,
so every existing piece of machinery that already knows how to persist,
serialize, and replay a `Candidate` keeps working unchanged. The planner's
`enqueueCombinedCandidates` (`internal/scan/combined.go`) is a one-time,
scan-wide pass triggered the FIRST time a scan's ordinary job queue goes
quiet (`execution.go`'s `combinedPassDone`/`evaluate`) — any jobs it
enqueues (there may be none) must themselves drain before the scan is
allowed to complete, exactly like any other job.

A confirmed combined-pair finding is **NOT** the same `Finding` as either
single-parameter finding: `findingDedupKey` (`internal/scan/finding.go`)
keys a combined finding on BOTH injection point IDs plus a `"combined"` tag
plus category+context, so it can never collide with — or absorb into —
either single-parameter finding, nor with a DIFFERENT combined pair sharing
one parameter but pairing it with a different second parameter. Its Title
says so explicitly: `Reflected XSS candidate in parameters "a" + "b"
(combined, html_attr_value) at GET /path` (and, once confirmed, `Reflected
XSS in parameters …` — `confirmedTitle`'s existing string replace keeps
working unchanged since the combined title still starts with the same
literal substring). This threads through all five presentation surfaces:
`report.FindingView`/`CandidateView` (`Combined`/`ParamNameB`/`ParameterB`/
`ValueB`), markdown and HTML report generators (an explicit "⚠ Combined
(multi-parameter) finding" line), the web API (`findingListItem`/
`findingView`'s `combined`/`parameter_b_name` JSON fields), the CLI
(`finding list`'s title already shows it; `finding show` prints a dedicated
`Combined` line and both candidate values), and the web UI
(`internal/web/assets/scans.js`: a warning note in the detail view, the
parameter column showing `a + b`, and the candidates list rendering both
halves) — so an operator sees "this is not a single-parameter bug" on every
surface, not just in the JSON.

### Tests and live validation

`internal/detection/combined_test.go`: the two templates' exact character
splits, the two-category boundary (every other context returns `false`),
dedup-key disjointness from the single-parameter planner, determinism (20
runs byte-identical), and benign-marker-only. `internal/scan/combined_test.go`:
same-context pairing, cross-context/triple/self-pairing rejection, ceiling
enforcement, determinism regardless of input order, the "only when
single-param already failed" gate (`endpointHasConfirmed`), combined
request building (`buildRequest` with both overrides mutating the SAME
request), and finding dedup/title/detail correlation.

Live-validated against `indago-combined-lab.py`, a disposable one-route
Python lab with the asymmetric-filter scenario described above: single-
parameter candidate testing on the route produces only `Rejected` findings
for each of the two parameters individually, while the scan's one-time
combined pass produces a genuine `Confirmed` finding — real browser
execution (`Uncaught ReferenceError: <marker> is not defined`), not just
green unit tests.

## Standalone PoC generation

Every other presentation surface describes a `Confirmed` finding in prose;
nothing generated a clickable, standalone artifact a bug-bounty triager
could open to reproduce the bug themselves — busywork the scan already has
every byte of data needed to automate. `internal/scan/poc.go`'s
`GeneratePoC(ctx, store, findingID)` closes that gap. It is presentation over
persisted scan data and reuses `buildRequest` to reconstruct the confirmed
candidate, but it no longer treats captured auth/CSRF material as replayable:
it checks the scan's session metadata without opening the state file, detects
non-focus token-like parameters with the same `isDynamicTokenName` heuristic
used by refresh logic, and replaces their observed values with fresh-token
placeholders. It performs no target I/O. The focused candidate payload remains
intact so the confirmed XSS input is still visible.

**Evidence integrity (AGENTS.md §2.6) is a hard gate, not a convention**:
`GeneratePoC` refuses (`ErrPoCNotConfirmed`) for anything whose STORED
Verdict is not `Confirmed` — a PoC claiming to reproduce an unconfirmed,
rejected, or inconclusive candidate would fabricate evidence of a
vulnerability that was never actually observed executing.

### One-click vs. "no one-click PoC is possible"

A generated `PoC.HTML` is either a true one-click reproduction or an inert
request template/manual request. One-click is permitted only when every
carrier constraint passes AND the scan had no non-anonymous auth session AND
no non-focus request parameter matches the existing `isDynamicTokenName`
heuristic (`token`, `csrf`, `xsrf`, or `nonce`, case-insensitive).

| Conditions | Artifact | Mechanism / operator work |
|---|---|---|
| Query and/or Path only (method GET/HEAD), no auth/refresh dependency | **True one-click link.** `<meta http-equiv="refresh">` navigates to the confirmed URL; a plain `<a>` is the manual fallback. | Candidate override is in the URL; no captured auth or dynamic-token dependency is present. |
| Form (method POST), no auth/refresh dependency | **True one-click auto-submit form**, mirroring `browser.Page.NavigateForm`'s `formHTML` (hidden inputs with attribute-value escaping and `onload="…submit()"`). | Hidden fields carry the exact static form body confirmed by the scan. |
| Query/Path/Form combined, no auth/refresh dependency | **Still one-click** only if all combined locations pass the carrier constraints. | `allLinkable` requires EVERY location to be carryable. |
| Any non-anonymous auth session OR any non-focus dynamic-looking token parameter | **Not one-click and not an exact runnable request.** The HTML is inert and says “request template—replace fresh CSRF/session placeholders.” Saved session cookies/state paths are never embedded; the curl command uses `-b "$INDAGO_COOKIE_JAR"` for an operator-supplied jar on authenticated scans. | Values of non-focus token-like parameters are replaced in URL/form/JSON/header/cookie renderings with `FRESH_<name>_VALUE` (escaped for that context). Candidate payload(s) remain intact. The operator must use their own authorized authenticated session, obtain current CSRF token(s) from the token-issuing page, and replace placeholders manually. PoC generation does not contact the target or automatically refresh tokens. |
| Header, Cookie, or JSON involved (either half, for a combined finding), absent auth/refresh dependency | **No one-click artifact.** It gives an explicit explanation plus the exact request details and curl command, but deliberately does not auto-navigate/auto-submit. | A browser link/form cannot carry arbitrary headers, target-origin cookies, or an `application/json` body. |

The Header/Cookie/JSON row is not a missing feature to “fix later” — it is
the structurally correct answer. Precision over polish: an artifact that
silently failed to carry a header/cookie override while LOOKING like a
working PoC would be worse than no PoC at all. For public static requests,
the displayed details/curl are exact; if auth or refresh dependencies exist,
the heading changes to “Request template” and the stale values are redacted.

A POST+JSON override can now reach `GeneratePoC` after deterministic browser
verification, but it still cannot produce a one-click HTML PoC: an HTML form
cannot carry `application/json`. The artifact therefore gives an explicit
explanation and curl fallback rather than pretending it can submit the exact
request. Auth/session and dynamic-token constraints still apply as above.

### Reachable from all three surfaces

- **CLI**: `indago finding poc -scan <scan-id|prefix> -out <file.html>
  <finding-id|prefix>` (`cmd/indago/cli.go`'s `findingPoC`).
- **API**: `GET /api/scans/{id}/findings/{fid}/poc`
  (`internal/web/findings.go`'s `handleGetFindingPoC`) — `409` for a
  non-Confirmed finding, `404` for an unknown scan/finding, `200` with
  `Content-Disposition: attachment` otherwise. Always forced as a download
  (never served inline): the whole point is for the artifact to
  navigate/auto-submit when opened on its own, independent of Indago's own
  origin — the sandboxing CSP the Evidence/Report content endpoints apply
  would defeat that.
- **Web UI**: a "⬇ Download PoC (standalone HTML)" link inside a
  Confirmed finding's "Verified candidate" hero block
  (`internal/web/assets/scans.js`'s `findingDetailEl`) — only ever rendered
  when `verified_candidate` is present, i.e. only for a Confirmed finding.

### Tests and live validation

`internal/scan/poc_test.go`: the refuse-if-not-`Confirmed` guard (Pending/
Rejected/Inconclusive), public static one-click Query/Path/POST+Form cases,
not-one-click Header/Cookie constraints, combined cases, authenticated
session redaction/cookie-jar guidance, dynamic CSRF placeholder redaction,
focus-payload preservation, and no auto-submit for dynamic-token POST forms.
`cmd/indago/finding_poc_test.go` and `internal/web/findings_poc_test.go`
also verify the authenticated CLI artifact and the downloaded API template,
including that stale token/session values do not appear at those surfaces.

Live-validated against a disposable one-route Python lab
(`indago-poc-lab.py`) reflecting `q` unescaped into `html_text`: a real
scan produced a genuine `Confirmed` finding, `indago finding poc` generated
a standalone HTML file from it via the real CLI command, and opening that
file completely independently of Indago's own process (a separate static
file server, a fresh browser tab with no Indago code involved) reproduced
the identical execution signal the scan itself observed —
`Uncaught ReferenceError: <marker> is not defined` — proving the generated
artifact is a faithful, independently-reproducible PoC, not just a file
with plausible-looking content.

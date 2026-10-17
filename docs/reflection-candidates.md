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
| `javascript` | JS string / template / code / comment / regex | quote-aware string escape `";M//`, template `${M}`, direct code `M` |
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
| `cookie` | Only cookies actually present in the scan's own session context — the SAME cookie jar `scopedEngine.WithSessionCookies` attaches to every request (loaded from the scan's auth session material; see `internal/auth`) — EXCLUDING whatever looks like the session's own authentication/session cookie (`isSessionCookieName`: a liberal name-based heuristic matching `sess`/`sid`/`auth`/`token`/`jwt`/`csrf`/`xsrf`, mirroring `dynamic_params.go`'s `isDynamicTokenName`). A scan with no session (or no cookies in it) registers none — never fabricated. | Session cookies are already attached to every request by `scopedEngine`; the baseline adds nothing extra. | `buildRequest` appends the injected cookie's marker value as its own `Cookie`, never replacing or removing any other cookie the request carries. |
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
shape as the canonical set, `Trigger: TriggerLoad` only — an evasion variant
of an interaction-only shape would be just as unconfirmable as the canonical
one already is):

| Technique | Idea | Reliability |
|-----------|------|--------------|
| `case_variation` | `<SvG OnLoad=M>` — mixed-case tag/attribute name | bypasses a case-sensitive literal-string filter |
| `alt_separator` | `<svg/onload=M>` / a tab instead of a space before the attribute | valid HTML5 (the tokenizer treats `/` and tab as attribute-boundary whitespace here); bypasses a filter expecting a literal space |
| `double_url_encoding` | the breakout pre-encoded (`%3Csvg...%3E`), which the transport encodes again on the wire | opportunistic only — works solely against a target that decodes twice (e.g. a WAF that decodes once to inspect, then an app that decodes once more); a single-decode target will reflect the literal percent-string, which is the correct, honest outcome, not a false negative |

Explicitly NOT in scope here, and not planned: request-fingerprint spoofing,
TLS fingerprint randomization, IP/proxy rotation, timing jitter, CAPTCHA
handling. That class of evasion depends on infrastructure a single local
scanner process does not have — adding it would be a materially different,
larger change and needs its own explicit decision, not a quiet extension of
this generator.

`TestEvasionCandidatesAreOffByDefault`, `TestEvasionCandidatesAreAdditive`
and `TestEvasionCandidatesAreBenignMarkers` (`internal/detection/
evasion_test.go`) enforce exactly these properties: off unless asked for,
additive never destructive, and still benign-marker-only — the same
guarantee `TestPlanCandidatesAreBenignMarkers` holds for the canonical set.

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
`GeneratePoC(ctx, store, findingID)` closes that gap. It is purely
presentation over data the scan already produced: it reuses the EXACT
`buildRequest` call the candidate step and browser verification themselves
used (never a re-derivation that could silently drift from what was
actually confirmed), and for a POST+form-encoded finding the SAME
auto-submitting-hidden-`<form>` technique `browser.Page.NavigateForm`
itself uses for POST verification (see `docs/browser-verification.md`).

**Evidence integrity (AGENTS.md §2.6) is a hard gate, not a convention**:
`GeneratePoC` refuses (`ErrPoCNotConfirmed`) for anything whose STORED
Verdict is not `Confirmed` — a PoC claiming to reproduce an unconfirmed,
rejected, or inconclusive candidate would fabricate evidence of a
vulnerability that was never actually observed executing.

### One-click vs. "no one-click PoC is possible"

A generated `PoC.HTML` is one of two honest shapes — never a third,
silently-wrong one that looks like it works but doesn't:

| Location(s) involved | Artifact | Mechanism |
|---|---|---|
| Query and/or Path only (method GET/HEAD) | **True one-click link.** `<meta http-equiv="refresh">` auto-navigates to the exact confirmed URL; a plain `<a>` link is the manual fallback. No JavaScript needed at all. | the override is already part of the URL, exactly like a Query candidate's own verified-attempt URL |
| Form (method POST) | **True one-click auto-submit form**, mirroring `browser.Page.NavigateForm`'s own `formHTML` (same hidden-input, attribute-value-escaped, `onload="…submit()"` shape) — a real top-level POST navigation, not a payload. | hidden `<input>` fields carry the exact form body the confirmed request sent |
| Combined, both halves Query/Path/Form | **Still one-click** — both overrides are carried together (both baked into the URL, or the Form half as hidden inputs plus the Query/Path half baked into the form's own `action` URL). | `allLinkable` requires EVERY location involved to be carryable, not just one |
| Header, Cookie, or JSON involved (either half, for a combined finding) | **No one-click artifact at all** — the page renders an explicit "⚠ No one-click PoC is possible for this finding" explanation (which specific location and why) plus the exact HTTP request and a runnable `curl` command. It deliberately does NOT auto-navigate/auto-submit. | a plain navigation/form submission cannot set an arbitrary request header (browsers only allow a small fixed set on cross-context requests); a static page on an unrelated origin cannot set a cookie for the TARGET's origin (same-origin policy); no HTML form can carry an `application/json` body |

The Header/Cookie/JSON row is not a missing feature to "fix later" — it is
the structurally correct answer. Precision over polish: an artifact that
silently failed to carry a header/cookie override while LOOKING like a
working PoC would be worse than no PoC at all. Every generated artifact
(one-click or not) also always includes the exact HTTP request and a
`curl` command, so the header/cookie/JSON case still gives the triager
everything needed to reproduce the bug by hand.

A POST+JSON override can never actually reach `GeneratePoC` on a real
Confirmed finding in the first place — see AGENTS.md §3 and
`docs/browser-verification.md`: browser navigation carries no request
body, so a POST+JSON candidate can never be browser-verified and so can
never be `Confirmed`. `GeneratePoC` still handles it defensively (treated
the same as Header/Cookie: no one-click artifact, explicit explanation,
curl fallback) rather than assuming the limitation holds instead of
checking.

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
Rejected/Inconclusive), one-click Query, one-click Path, one-click
POST+Form (asserts the auto-submit `<form>`/hidden-input shape), not-
one-click Header (asserts the curl `-H` flag and the explicit explanation),
not-one-click Cookie (asserts curl `-b` and the same-origin-policy
explanation), a combined finding with both halves Query (still one-click,
both overrides present in the URL), and a combined finding with one Query
half and one Header half (correctly NOT one-click, even though one half
alone would have been). `cmd/indago/finding_poc_test.go` and
`internal/web/findings_poc_test.go` exercise the CLI and API surfaces
end to end against the real HTTP handler.

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

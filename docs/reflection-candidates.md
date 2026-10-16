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
parameter/combined injection (mutating more than one location at once) and
PoC generation remain out of scope, unchanged by this.

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

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
| `html_text` | element text, comment, RCDATA/RAWTEXT | `<svg onload=M>`, `<Mx>` — prefixed with the construct's closer (`-->`, `</title>`, …) where needed |
| `html_attribute` | attribute value / name, tag name | quote-aware `"><svg onload=M>` and an in-tag `onmouseover=M` handler (which needs only the delimiter, not `<`/`>`) |
| `javascript` | JS string / template / code / comment / regex | quote-aware string escape `";M//`, template `${M}`, direct code `M` |
| `url` | URL attribute | `javascript:M` only at a scheme position (`start`, `relative_first_segment`); `data:` where plausible; nothing in a query/path/host |
| `css` | `<style>` body | `</style><svg onload=M>` (a `style=""` attribute can't break into markup, so nothing) |
| `unknown_mixed` | unclassifiable / ambiguous | generic low-priority markup probes |

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

No verdict, no browser verification, no exploit generation, no obfuscation/
evasion variants, no LLM. Candidate values embed a benign marker and are sent
only to in-scope targets; state-changing methods require the operator opt-in.
See `AGENTS.md` §2–§3.

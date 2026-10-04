# Indago — Finding Correlation & Reporting

Two things happen after a candidate reflects: it is turned into a `Finding`
(the record an operator reads), and — once verified — that record is updated
without ever being duplicated or having its evidence thrown away. Code:
`internal/scan/finding.go` (correlation) and `internal/report` (JSON/Markdown
output).

## Why correlate at all

A single injection point can reflect into several sites, and the candidate
planner deliberately proposes more than one candidate per site (see
[`reflection-candidates.md`](reflection-candidates.md)). Without correlation,
every one of those that happens to reflect would mint its own near-identical
`Finding` — the same underlying vulnerability reported three or four times.
Correlation collapses that back to one `Finding` per *meaningfully distinct*
site, while keeping every contributing candidate and TestCase as raw evidence
inside it — "deduplicated" never means "evidence discarded."

## The correlation key

```go
func findingDedupKey(injectionPointID domain.ID, cand detection.Candidate) string
```

Two candidates correlate into the same `Finding` only when they share **all
three**: the injection point (scan + endpoint + parameter — already one
identity via `domain.InjectionPoint`), the candidate's `Category`, and its
`Context` (e.g. `html_text` vs `js_string` — the detection context, not just
the coarser category). That is deliberately narrow:

- A different **parameter** → a different injection point → never correlates.
- A different **endpoint or method** → `InjectionPointID` already encodes
  both (an `Endpoint` is one URL+method pair) → never correlates.
- A different **context** at the *same* injection point (the parameter
  reflects into both page text and a script block, say) → a genuinely
  different vulnerability manifestation → never correlates.

`upsertPendingFinding` looks up the scan's existing findings for this key; a
match absorbs the new candidate (bumping an occurrence count and recording the
candidate + its TestCase ID, deduplicated by candidate value so a retried
attempt doesn't bloat the list) instead of creating a new row.

## Verdict: monotonic, never an LLM's call

A `Finding`'s `Verdict` only ever moves up one lattice:

```
Pending  <  Inconclusive  <  Rejected  <  Confirmed
```

`correlateVerification` applies a single rule: a new result is written only
when it outranks what the `Finding` already holds. In practice that means:

- **Confirmed is sticky.** Once browser verification has deterministically
  observed execution, no later result at a correlated site — even a flat
  `Rejected` from a *different* candidate that didn't execute — can undo it.
- **Pending/Inconclusive/Rejected can still be upgraded.** A second candidate
  at the same site that *does* execute promotes the finding to Confirmed.
- **Evidence is unioned on every attempt, regardless of rank.** A
  non-promoting result's evidence is not thrown away — see below.

This is the only place `domain.Verdict` changes for Reflected XSS, and it is a
pure function of `verification.Result` (itself a deterministic function of a
browser signal — see [`browser-verification.md`](browser-verification.md)).
Nothing here, or anywhere upstream of it, is an LLM call.

## Provenance and evidence, end to end

Every `Finding` carries the full chain the requirements ask for:

| Link | Field |
|---|---|
| scan | `ScanID` |
| endpoint | `EndpointID` |
| parameter | `ParameterID`, and `Location` |
| injection point | `InjectionPointID` |
| discovery source | `Provenance.DiscoverySource` (copied from the `Endpoint` that was discovered) |
| candidate(s) | `Detail.Candidates` — every distinct candidate (with its `Source`: `builtin` or a future `llm`) that correlated in |
| verification | `Provenance.VerifiedAt`, plus the verification `Report` in the backing TestCase's `Detail` |
| evidence | `EvidenceIDs` |

`EvidenceIDs` is deliberately a union, not the latest attempt's set: each
verification attempt contributes **both** the original candidate's HTTP
request/response evidence **and** that attempt's own screenshot/rendered-DOM/
browser-log evidence (fetched via the candidate TestCase ID carried in the
`JobVerify` payload). Re-running `correlateVerification` for the same or a
different correlated candidate only ever adds IDs, never removes them.

## Guarding against false confirmation

`decide()` in `internal/verification/browser.go` already requires the browser's
own uncaught-exception/console-error channel to name the *exact* marker token —
an unrelated error on a noisy page cannot match it (see
[`browser-verification.md`](browser-verification.md)). On top of that,
`BrowserVerifier.Verify` baselines each observation channel immediately after
opening the page and **before navigating**, and only considers what was
observed *after* that point: nothing a page did before this navigation began
can be attributed to this candidate's signal. Both are enforced, not assumed —
see `TestIntegrationVerifyUnrelatedPageErrorDoesNotConfirm`.

## Reporting (`internal/report`)

`JSONGenerator` and `MarkdownGenerator` both render the same `Data` (project,
scan, findings, a computed `Summary`) and both are pure serialization —
neither imports `internal/detection` or `internal/verification`, and neither
makes or recomputes a verdict; they only echo `Finding.Verdict`. A `Finding`'s
`Detail` is read back through a small, report-local, read-only shape
(`markdownDetail`), never by depending on the packages that produced it. Output
is deterministic: findings are ordered by `(CreatedAt, ID)` and every
map-keyed breakdown (`ByVerdict`, `BySeverity`, `ByVulnClass`) is rendered in
sorted key order, so the same `Data` always serializes to byte-identical
output — required because Go map iteration order is randomized.

## Boundaries

No LLM verdict (correlation only ever relays `verification.Result`, never
invents or scores one), no DOM/Stored XSS, no new payload types — correlation
only groups candidates the planner already proposed and the candidate step
already sent. See `AGENTS.md` §2–§3.

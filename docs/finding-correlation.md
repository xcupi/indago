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

A Finding is created **regardless of HTTP method**: a POST/JSON candidate
reflecting is just as real as a GET one. Supported GET/HEAD, POST/form, and
bounded POST/JSON requests can reach browser verification; unsupported
body-carrying methods still remain `Pending` — see
`docs/scan-orchestration.md`. Only the browser-verify job's enqueue is gated
on the method/body capability, not the correlation itself.

This lookup-then-write is not atomic at the store layer, so `executor` and
`verifyExecutor` share one `*sync.Mutex` (constructed once per scan in
`defaultHandlers`) around it and around `correlateVerification`'s own
Get-mutate-Update — without it, two candidates reflecting into the same site
on different workers could each see "no match" and create a duplicate
Finding, and two concurrent verify completions for the same Finding could
lose one's evidence to the other's `Update`. See `docs/e2e-validation.md`.

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
- **Every attempt keeps its own result.** `Detail.Attempts` records each
  verification attempt — the candidate it replayed, that attempt's own
  verdict/confidence/notes, and the evidence it produced (its browser
  evidence plus the candidate's HTTP request/response) — once per verify
  TestCase. The Finding's `Verdict` is the ratcheted maximum across them, so
  a confirmed finding with a later rejected attempt shows *both*: Confirmed
  overall, with the rejected attempt still visible beside the confirming one.

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

### Where evidence lives (and the Evidence-tab bug it caused)

Evidence rows are written by the executors (`putEvidenceBlob`) **before** any
Finding exists, so they never carry a `finding_id`; the link from a Finding to
its evidence is `Finding.EvidenceIDs` and nothing else. The web API originally
resolved a finding's evidence with `Evidence().ListByFinding` (a
`finding_id = ?` query), which therefore returned nothing for every real
finding — the Evidence tab and finding detail were empty even for confirmed
findings with 7–12 evidence items each. `findingEvidence`
(`internal/web/findings.go`) now resolves `EvidenceIDs` (unioned with any
`finding_id`-linked rows), skips IDs that no longer resolve or belong to a
different scan, and orders the result by `(CreatedAt, ID)`.
`GET /api/scans/{id}/evidence` returns every finding's evidence metadata in
one request, grouped by finding. Web tests seed evidence the way the
executors do (no `finding_id`), so this cannot silently regress.

### Opening evidence safely

Evidence content is the target's own bytes — a rendered DOM includes the
target's scripts and the reflected candidate. Served inline from the control
plane's origin it would run with the operator UI's privileges (same-origin
script can send `X-Indago-Client` and drive the API). Every evidence and
report content response therefore carries
`Content-Security-Policy: sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'`
(no `allow-scripts`: unique opaque origin, scripts/forms/fetches disabled),
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and
`Referrer-Policy: no-referrer`. HTTP-message evidence (`message/http`) is
served as `text/plain`. When the server requires its API token, the console
cannot send that header on a plain navigation, so it fetches the content with
the token and shows HTML/SVG/XML in a full-window frame with `sandbox=""` (no
scripts, no same-origin access) rather than as text. `TestUIFindingsSelectionReportModesAndEvidence`
opens a captured DOM containing a title-changing script in real Chromium and
asserts the script did not run (it does, without these headers).

## Duplicate-looking findings: what they were

Investigated against the corpus with real Chromium. The dedup key behaved
correctly: candidates at one injection point and context collapsed into one
finding (`occurrences`/`candidates` > 1) and `/multi`'s two contexts stayed
two findings. What *looked* like duplicates were distinct findings that the
operator could not tell apart:

- **Titles named the candidate category, not the context or endpoint.**
  Every `html_text` reflection of `q` — on `/confirmed`, `/submit`, `/noisy`,
  `/encoded`, … — read `Reflected XSS candidate (html_text) in parameter "q"`,
  and `js_string`/`js_code` (both category `javascript`) collided too. Titles
  now name parameter, **context**, and endpoint (method, path, and the sorted
  query-parameter *names* that key an endpoint in discovery), e.g.
  `Reflected XSS candidate in parameter "q" (js_string) at GET /multi?q`.
  Titles are set at creation, so findings created before this change keep
  their old titles.
- **The findings table had no endpoint column**, and two endpoints that
  differ only in their parameter set (`/search?q` vs `/search?page&q`) are
  distinct endpoints and injection points in discovery. They stay separate
  findings — merging distinct injection points would lose which request
  shape is vulnerable — but the list API now includes `endpoint_method`/
  `endpoint_url` and the UI shows an Endpoint column.

Regression tests: `TestCorrelateVerificationPreservesEveryAttemptResult`,
`TestAppendAttemptDedupsByVerifyTestCase`,
`TestDistinctInjectionPointsStaySeparateWithDistinguishableTitles`,
`TestDistinctContextsSharingCategoryHaveDistinctTitles`, alongside the
existing sticky-confirmed, distinct-context/parameter, and concurrent
no-duplicate tests.

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

**Selection.** A report covers one of three explicit selections
(`domain.ReportSelection`): `all` findings, `confirmed` only (filtered on the
stored verdict — never inferred or upgraded; with none confirmed the report
is honestly empty), or `selected` (an explicit `finding_ids` list, validated
against the scan). `POST /api/scans/{id}/reports` takes `mode`; an omitted
mode keeps the original contract (`selected` if IDs are given, else `all`),
and IDs combined with `all`/`confirmed` are rejected rather than silently
ignored. `GET /api/scans/{id}/reports/preview?mode=…&finding_id=…` runs the
same selection without writing anything, so the UI shows the exact count and
verdict breakdown before generating. The summary persisted on the report
records `selection` and `scan_findings` (findings in the scan at generation
time), and every format states its scope (e.g. "confirmed findings only (2 of
8 findings in the scan)"). Output stays deterministic: the same selection in
any ID order produces identical content (`TestReportSelectionDeterministic`).
The CLI exposes the same modes (`indago report create -mode …`).

## Boundaries

No LLM verdict (correlation only ever relays `verification.Result`, never
invents or scores one), no DOM/Stored XSS, no new payload types — correlation
only groups candidates the planner already proposed and the candidate step
already sent. See `AGENTS.md` §2–§3.

## Logical findings, attempts, and presentation

A `Finding` is a **vulnerability location** (scan + injection point + vuln class
+ candidate category + execution context), not a candidate attempt. Each
verification attempt (candidate value, verdict, evidence IDs) is a child entry in
`Detail.Attempts`; a rejected attempt at a location that is already a finding
never creates a separate vulnerability row. The finding's verdict is the
strongest of its attempts (pending < inconclusive < rejected < confirmed;
confirmed is never downgraded).

- The default Findings view (UI, `indago finding list`) lists **confirmed**
  findings only; rejected/inconclusive/pending are reachable via "Needs review" /
  "Diagnostics" or `-verdict`, and the default view states how many are hidden.
  `indago finding list -json` is the exception: with no `-verdict` it returns
  **every** finding, so scripts consuming the JSON never silently lose rows
  (JSON output has nowhere to carry the "hidden" hint).
- A confirmed finding prominently shows the **verified candidate** — the attempt
  whose browser verification succeeded. Baseline values (e.g. `hello`) are
  labelled as baseline evidence and never presented as payloads; the verifier
  path refuses any candidate that does not embed the scan's marker.
- Reports (JSON/Markdown/HTML) are sectioned confirmed / needs review /
  diagnostic, lead with the verified payload and role-ordered evidence, and take
  an explicit selection mode (`all`, `confirmed`, `selected`); the UI defaults to
  confirmed only.
- Layout: the app shell is `min-height:100vh` with the footer in normal flow, and
  long values wrap (`overflow-wrap:anywhere`); covered by real-browser tests in
  `internal/web/ui_layout_test.go`.

# Reports: formats, templates, PDF

Reports are generated from a scan's findings, never from raw tool output. Every
format states the selection (which findings were included) and the scan's
coverage completeness, so a report from a canceled or partially covered scan can
never read as "the target is clean".

## Formats

| Format | Content | Use |
| --- | --- | --- |
| `json` | findings + presentation (verified candidate, attempts, role-labelled evidence, CWE/CVSS classification, curl PoC) | machine consumers, re-processing |
| `markdown` | the selected template as text | tickets, wikis, PRs |
| `html` | the selected template as one self-contained page | viewing in a browser |
| `sarif` | SARIF 2.1.0 log: one rule per vulnerability class (CWE + CVSS baseline) and one result per confirmed/needs-review finding | security dashboards (GitHub code scanning, Azure DevOps) |
| `pdf` | the `html` page printed by headless Chromium | client delivery, bounty submissions |

## Layout

`pentest` and `bug_bounty` share one print stylesheet (inline, no remote
assets) and render the same way in the browser and in the PDF:

- a cover with the report kind, the subject, four KPI cards (confirmed count,
  high/critical count, coverage, in-scope seeds) and the metadata grid;
- a numbered contents page;
- numbered sections with a single accent colour, severity/verdict cells as
  coloured pills, evidence as small tables, monospace only for identifiers and
  URLs;
- A4 page rules with a running footer (`INDAGO · CONFIDENTIAL`, page N / total);
  only the appendices start a new page, and short tables are kept whole so no
  page ends up with a single stranded row.

Page numbers in the contents list are deliberately absent: the print engine
has no `target-counter()`, and a wrong number is worse than none.

Set `template` on `POST /api/scans/{id}/reports`. JSON and SARIF ignore it;
markdown, html and pdf honour it.

- `technical` (default when the field is empty) — the evidence-first layout the
  engine has always produced: summary, verdict/severity/class breakdown, then
  confirmed / needs-review / diagnostics sections with candidates and evidence.
- `pentest` — the client deliverable, following the conventional penetration
  test report structure: statement of confidentiality,
  engagement & scope, executive summary, approach & methodology, summary of
  findings, technical findings (CWE, impact, remediation, references, verified
  request, evidence), a short/medium/long remediation roadmap, and appendices
  for severity definitions, evidence inventory and coverage.
- `bug_bounty` — one submission-shaped block per finding: asset, severity,
  confidence, CWE, description, steps to reproduce, the exact verified URL and
  candidate, impact, remediation, references, evidence. No CVSS is invented:
  the line says CVSS is not scored and severity is the engine's verdict.

`pdf` defaults to `pentest` when no template is given. Rejected diagnostics are
excluded from `pentest` and `bug_bounty` bodies and counted instead — they are
not vulnerabilities.

The layout that produced a file is stored on the report row (`template` in the
API response) and shown in the UI's report table, so a list of reports states
which template each one used instead of leaving it to be guessed from the
content. Reports created before this field existed show "—" (unknown); `json`
and `sarif` reports are machine formats and carry no template.

Class context (CWE, impact wording, remediation, references) is a fixed mapping
per vulnerability class in `internal/report/templates.go`. The finding's own
verdict, severity, confidence and evidence remain authoritative; the templates
add framing, not new claims.

## CWE/CVSS and reproducible curl PoC (technical layout)

The technical `json`, `markdown` and `html` layouts carry two extra fields per
finding, both derived from data the scan already stored:

- **`classification`** — `{class, cwe{id,name}, cvss{vector,base_score,severity}, note}`
  from `report.Classify(finding.VulnClass)`. The base score is COMPUTED from the
  vector (CVSS v3.1 Roundup), never hand-typed, so the number and the vector
  cannot disagree. It is a class-level BASELINE, not a measurement of this
  target's impact: `note` says so and ships with every classification. A class
  the table does not know renders as "not classified" — no weakness or score is
  invented.
- **`class_intel`** — `{name, impact, remediation, references}`, the class-level
  context from the same table the deliverable templates use. The technical
  markdown/html layouts render it as "Class", "Typical impact", "Remediation"
  and "References", so a reader of the evidence-first report gets the same
  context a client deliverable carries. A class with no table entry has no
  `class_intel` and is reported as unclassified; no wording or score is
  invented for it.
- **`curl_poc`** — `{evidence_id, curl, note}`, one runnable command reproduced
  from the finding's own stored HTTP request evidence (`message/http`). The
  verified attempt's request is preferred, then any other attempt's, then the
  finding's remaining request evidence. **Baseline evidence is never used**: it
  is the unmodified request and could not reproduce the finding. When no request
  blob is available the field is absent — a PoC is never synthesized from a
  response or a candidate value.

Credentials are redacted by default: `Authorization`/`Cookie`/API-key header
values become shell variables (`-H "Authorization: Bearer $INDAGO_TOKEN"`,
`-b "$INDAGO_COOKIE"`), and the command carries a leading comment saying to
export them. A report is a document people forward, so no literal secret is
written into it. The origin-form stored request target is resolved against the
finding's own recorded URL scheme, so a plain-HTTP lab target gets an `http://`
command rather than a `https://` one that cannot connect.

The server reads at most 200 request blobs of at most 512 KiB each per report;
a blob that cannot be read or is oversized simply omits that finding's PoC.

## SARIF

`sarif` is a machine export, not a template. It emits a SARIF 2.1.0 log with:

- one rule per vulnerability class reported (`indago/<vuln_class>`) carrying the
  same CWE/CVSS baseline as `classification`, the CWE page as `helpUri`, and
  impact/remediation in `help`;
- one result per confirmed or needs-review finding, with the in-scope endpoint
  URL as its artifact location, the CWE/vector/score in the result properties,
  and a deterministic partial fingerprint for de-duplication;
- rejected diagnostics excluded from `results` and counted in
  `runs[0].properties.diagnosticsExcluded` — they are not vulnerabilities.

Result levels follow the finding: a confirmed critical/high finding is `error`,
medium is `warning`, and low/info is `note`. A finding still awaiting review is
`kind: review` at note level, never an error. A class with no classification
still gets a rule and result, but no invented CWE or score.

## PDF requirements

PDF export needs a Chromium/Chrome executable. Resolution order:

1. `-chromium PATH` on `indago serve`
2. `INDAGO_CHROMIUM_PATH`
3. `google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` on `PATH`

Without one, `format: "pdf"` answers 503 naming the missing dependency and every
other format keeps working. The print uses `--no-sandbox` only when the server
itself was started with `-browser-no-sandbox`; the generated HTML is written to a
private temp dir (0600) and removed after conversion.

## Example

```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Indago-Client: ui' \
  -d '{"format":"pdf","template":"pentest","mode":"confirmed"}' \
  http://127.0.0.1:8750/api/scans/<scan-id>/reports

curl -s -OJ http://127.0.0.1:8750/api/reports/<report-id>/content?download
```

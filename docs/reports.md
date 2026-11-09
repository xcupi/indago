# Reports: formats, templates, PDF

Reports are generated from a scan's findings, never from raw tool output. Every
format states the selection (which findings were included) and the scan's
coverage completeness, so a report from a canceled or partially covered scan can
never read as "the target is clean".

## Formats

| Format | Content | Use |
| --- | --- | --- |
| `json` | findings + presentation (verified candidate, attempts, role-labelled evidence) | machine consumers, re-processing |
| `markdown` | the selected template as text | tickets, wikis, PRs |
| `html` | the selected template as one self-contained page | viewing in a browser |
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

Set `template` on `POST /api/scans/{id}/reports`. JSON ignores it; markdown,
html and pdf honour it.

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
reports are machine format and carry no template.

Class context (CWE, impact wording, remediation, references) is a fixed mapping
per vulnerability class in `internal/report/templates.go`. The finding's own
verdict, severity, confidence and evidence remain authoritative; the templates
add framing, not new claims.

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

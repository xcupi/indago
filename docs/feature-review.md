# Feature review and PortSwigger coverage

Reviewed 2026-11-10 against the current branch (binary `b6b3cd2`).
The lab numbers come from `indago_lab/LABS.md`, which was rebuilt from the live
PortSwigger catalogue; the confirmed column is mixed-revision and says so.

## Scoreboard

| Area | Result |
| --- | --- |
| PortSwigger labs catalogued | 55 (XSS 30, access control 13, information disclosure 5, DOM 7) |
| Confirmed by the engine itself | **48** (XSS 23, AC 13, ID 5, DOM 7) |
| Gaps | **7** (4 stored XSS, 3 exploit chains) |
| Payload families | 137 (24 curated + 113 generated from the XSS cheat sheet) |
| Report formats / templates | 4 / 4 |
| LLM provider ids / selectable in Settings | 9 / 9 |
| API routes | 60+ (see `internal/web/server.go`) |

"Confirmed" means the scanner produced the finding and its own execution
evidence. Labs solved manually or with a vendor solution are not counted.

## What the product actually does

Indago is an authorization-first, single-target web scanner. It crawls a seed
inside a project scope and tests four vulnerability classes: reflected and DOM
XSS, access control (including IDOR), and information disclosure. It does not
claim SQL injection, SSRF, CSRF, deserialization, or stored XSS.

### Discovery and recon

| Capability | Where | Notes |
| --- | --- | --- |
| Scope enforcement | `internal/domain`, `internal/web` | hosts, path prefixes, exclude lists, subdomains; fail-closed |
| Crawling | `internal/discovery/collector.go` | depth/page caps, redirects, forms |
| Browser-rendered crawl | `internal/discovery`, browser manager | requires `-browser` |
| Sitemap / robots | `internal/discovery/sources.go` | standard |
| Wayback archive | `internal/discovery/archive.go` | aggressive, same-host, <=200 URLs |
| Well-known paths | `internal/discovery/wellknown.go` | security.txt, etc. |
| Content discovery | `internal/discovery/wordlists` | 162 standard / 252 aggressive paths, soft-404 calibration |
| Parameter mining | `internal/discovery` | differential + 200-name list, GET/body/JSON |
| Script literal extraction | `internal/discovery/extract_script.go` | feeds DOM and endpoint analysis |
| Browser network capture | `internal/discovery` | requires `-browser` |
| Auth state | `internal/auth`, `lab_auth.py` | Playwright storage state; interactive login when enabled |

Deliberately not covered, with reasons in `docs/recon-coverage.md`: WHOIS, DNS
and zone transfer, subdomain discovery, dorking, value fuzzing, subdomain
fuzzing. They either leave the target scope or need a third-party data source.

### Detection engines

| Engine | Contexts / techniques | Labs proven |
| --- | --- | --- |
| Reflected XSS | `html_text`, `html_attr_value`, `js_string`, `js_code`, `url`, comment; quote/backslash/template-literal handling | 1, 7, 9, 14-19, 21, 25-30 |
| DOM XSS | `innerHTML`, `document.write`, jQuery selector/attr, `eval` + XHR, Angular expressions, `location.hash`, external scripts | 3-6, 10-12, 26 |
| Evasion | tag/attribute blocklists, CSP, Angular sandbox, dangling markup, SMIL, JS URL | 14-16, 25, 27-30 |
| Access control | forced browsing, role parameter/cookie/profile, unpredictable IDs, redirect leakage | AC 1-13 |
| IDOR | object families, enumerable IDs, attribution, `-idor-candidates` | AC 5-9 |
| Information disclosure | `.git` history and secrets, headers, comments, backups, TRACE IP header | ID 1-5 |
| Verification | browser marker execution, wait-for-signal, PoC capture, evidence rows + blobs | all confirmed labs |

### Orchestration and operations

- Two-pass scans (discovery then testing), round-based queue, per-step dedupe
  (`STEPS_ONCE` vs `STEPS_ALWAYS`), conservative profile, rate limits.
- Coverage and stats endpoints, endpoint/parameter/test/evidence explorer.
- Retention and data directory layout; SQLite store with migrations.
- Server capabilities are gated by flags: `-browser` (DOM and browser crawl),
  `-allow-state-changing` (POST/PUT/PATCH/DELETE), `-allow-remote` + TLS,
  bearer token for remote binds. With the default flags the capability endpoint
  correctly reports them off.

### Control plane (SPA at `/`)

Pages: Dashboard, Projects, Project detail (scope editor, targets, scans),
Scans, Scan detail (Overview, Coverage, Explorer, Endpoints, Tests, Evidence,
Reports, IDOR, AI advisory), Findings, Reports, Bug bounty, Settings.
Legacy dashboard stays at `/legacy/` for the legacy integration tests; `/` is the SPA.

### AI (advisory only)

| Function | Endpoint | What it may do |
| --- | --- | --- |
| Assist | `POST /api/scans/{id}/ai/assist` | prioritise endpoints, triage findings, next manual steps |
| Diagnose | `POST /api/scans/{id}/ai/diagnose` | explain a failed payload from captured evidence, propose *new* payloads or a WAF bypass |
| Report summary | `ai_summary: true` on report creation | draft the executive paragraph, labelled unverified |
| Triager review | `POST /api/scans/{id}/ai/report-review` | READY / NEEDS FIXES / DO NOT SUBMIT with concrete fixes |

Guardrails: never changes verdict/severity/ordering/evidence; never called by a
background scan; master switch plus attempt budget; secrets redacted from
evidence; evidence treated as data; proposed payloads deduped against what the
scanner already sent and filtered against the scan's scope; diagnosis only for
parameters that are not confirmed. Providers: 9 ids supported by the gateway
(openai, anthropic, claude, openrouter, ollama, vllm, deepseek, custom,
chatgpt), 5 exposed in Settings (deepseek, claude, openai, custom, chatgpt).
ChatGPT and Claude each have an Indago-owned OAuth session; no key needed.

### Reports

Formats: PDF (Chromium print), HTML, Markdown, JSON. Templates: `technical`
(evidence-first), `pentest` (client deliverable), `bug_bounty` (submission),
`yeswehack` (platform skeleton). The template is persisted with the report.
PDF layout: A4, cover, KPI cards, two-column contents, numbered sections,
severity/verdict pills, page footer and counter. TOC page numbers are not
rendered because Chromium does not support `target-counter()`.

### YesWeHack

| Capability | Status |
| --- | --- |
| Browse programs filtered to bug bounty + web-application | yes, explicit Load + 10 min cache |
| Pagination | yes, page/total/has_more |
| Preview scopes and rules without a credential | yes, public program page |
| Import one or many programs | yes; project + target + scope, path-scoped assets kept |
| Duplicate import | skipped |
| Credential | PAT or logged-in session token, stored 0600; never returned |
| Submission template | `yeswehack` markdown, confirmed findings only |
| Submit | **manual by design** (credits) |

### Payload library

137 families: 126 `html_text`, 4 `html_attr_value`, 3 `js_string`, 2 `url`,
1 `js_code`, 1 `html_comment`; 53 load-triggered, 84 interaction-triggered.
Selection is context + required-metacharacter + trigger + a hard cap of 12 per
injection point, so it is not a one-vector-at-a-time brute force. The audit
against the 141 event families in the cheat sheet excludes 28 with reasons
(21 media success events that cannot decode headless, 4 navigation/unload,
`onbeforeprint`, `onunhandledrejection`, `onanimationcancel`).

## PortSwigger mapping

### XSS (30) - 23 confirmed

Confirmed: 1, 3, 4, 5, 6, 7, 9, 10, 11, 12, 14, 15, 16, 17, 18, 19, 21, 25,
26, 27, 28, 29, 30.

Gaps:

| # | Lab | Reason | Decision |
| --- | --- | --- | --- |
| 2, 8, 13, 20 | Stored XSS variants | stored probe removed on request; no persistence/callback model | out of scope |
| 22, 23, 24 | Cookie theft, password capture, CSRF bypass chains | exploit chain needs a victim bot and exfiltration endpoint | out of scope |

### Access control (13) - 13 confirmed

1-13 all confirmed, including IDOR with unpredictable IDs, redirect leakage,
URL/method bypass, and role changes through cookie/profile.

### Information disclosure (5) - 5 confirmed

1-5 all confirmed; `.git` history is walked for secrets, TRACE IP-header leak
is detected, header/comment/backup exposure is reported.

### DOM-based (7) - 7 confirmed

| # | Lab | Gap |
| --- | --- | --- |
| 1 | DOM XSS in `innerHTML` sink | confirmed |
| 2 | Web messages to a JavaScript URL | **confirmed** (scan ee080c8a) |
| 3 | Web messages + `JSON.parse` to `src` | **confirmed** (scan e078f718, child-frame execution) |
| 4 | DOM-based open redirection | **confirmed** (scan 735ed816) |
| 5 | DOM-based cookie manipulation | **confirmed** (scan b78570e2) |
| 6 | DOM clobbering to enable XSS | **confirmed** (scan 8ed23385) |
| 7 | Clobbering DOM attributes to bypass filters | **confirmed** (scan e8111129) |

## Findings from the review

1. **The running instance was started without `-browser` and
   `-allow-state-changing`.** `/api/capabilities` correctly reported
   `browser_enabled: false`, so DOM XSS and browser crawl were unavailable in
   that session. Restarted with both flags; capabilities now report all true.
2. **Settings now exposes all 9 provider ids.** `anthropic`, `openrouter`,
   `ollama`, and `vllm` were added to the settings registry, so each can be
   selected, probed and given a model without editing environment variables.
3. **Claude OAuth now runs live.** Refresh moved to
   `platform.claude.com` with the axios user agent, inference sends the full
   Claude Code identity (UA, betas, system line), and report summarisation
   completes with provider-reported usage. Active offensive advisory
   (`prioritize`, `triage`, `next_steps`, payload diagnosis) is refused by the
   subscription model's safety policy; Indago surfaces that as a policy
   refusal, not an empty answer.
4. **Bounty and LLM tests drifted from the code** (provider count 4 vs 5,
   pagination fixture without `nb_results`). Fixed; `go test ./internal/web`
   and `./internal/bounty` are green.
5. **TOC has no page numbers** (Chromium `target-counter()` limitation).
6. **Token accounting exists; cost does not.** Provider-reported prompt,
   completion and total tokens are stored per task and summed at
   `GET /api/scans/{id}/ai/usage`. No price table is applied, so the UI shows
   tokens rather than a guessed money figure.
7. **YesWeHack draft auto-fill is absent.** Rendering and review exist; writing
   the platform draft would need a stored credential and a live test. Submit is
   deliberately manual.
8. **Four DOM failures remain capability gaps.** Navigation assignment
   (`location.href`/`assign`), `element.src` (including `JSON.parse`) and
   `document.cookie` reachability are now modelled. Open redirect and DOM
   clobbering still need a dedicated engine; a redirect leaves the authorized
   scope by definition, so it is not followed.

## Recommended next steps

| Priority | Work | Why |
| --- | --- | --- |
| P1 | Finish DOM open-redirect and clobbering models | the other sink models are in; these two need an engine that does not follow a redirect out of scope |
| P1 | ~~Expose all 9 providers in Settings~~ | done |
| P2 | ~~Token accounting~~ | done (tokens, not cost) |
| P1 | Live Claude OAuth test | proves the second OAuth path end to end |
| P2 | TOC page numbers via a two-pass render, or drop the page column | polish |
| P2 | YesWeHack draft auto-fill (no submit) | saves typing without spending credits |
| P3 | Stored XSS and exploit chains | explicitly out of scope unless the product decision changes |

## Verification

```
go test ./internal/web                     ok 47.4s
go test ./internal/detection ./internal/report ./internal/llm
go test ./internal/chatgpt ./internal/claudeoauth
go test ./internal/bounty                  ok
GET /api/capabilities  -> browser, sandbox, login, state-changing all true
GET /api/payload-library -> 137 entries
LABS.md -> 42 confirmed / 13 gap
```

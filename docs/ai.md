# AI advisory (optional)

Indago works with no model configured. When one is configured, a model can do
run the operations supported by its provider:

1. **Answer an explicit question about an existing scan** (`POST /api/scans/{id}/ai/assist`):
   prioritise endpoints, triage findings, propose next manual checks.
2. **Diagnose a payload that did not work, or propose a bypass**
   (`POST /api/scans/{id}/ai/diagnose`): the model reads the request/response,
   DOM and browser-log evidence already captured for a finding and explains the
   failure (filter, encoding, WAF, wrong sink) and returns new candidates.
3. **Draft the executive-summary paragraph of a report** (`ai_summary: true` on
   report creation), labeled as an unverified draft.
4. **Review a submission before it is sent** (`POST /api/scans/{id}/ai/report-review`):
   a triager pass over the report Indago itself renders, returning
   `READY` / `NEEDS FIXES` / `DO NOT SUBMIT` with concrete fixes.

Everything else is unchanged by design: the scanner decides what is tested and
what is confirmed, and the model's answer is stored as an advisory `AITask` —
prose, never a finding, verdict, severity or evidence. A scan running in the
background makes no model call on its own.

## Providers and credentials

Resolution order for one advisory call:

1. `ai_provider` on the request (assist body, or report body).
2. The provider saved in Settings (`/api/llm/config`).
3. `deepseek` by default.

Settings keeps each saved provider's key, model, and base URL when you switch
the default provider. Saved values take priority. Provider-specific environment
variables fill missing settings, and the API reads environment keys at request
time without copying them into saved settings:

```bash
INDAGO_LLM_KEY_OPENAI=sk-...            INDAGO_LLM_MODEL_OPENAI=gpt-4o-mini
INDAGO_LLM_KEY_DEEPSEEK=sk-...          INDAGO_LLM_MODEL_DEEPSEEK=deepseek-chat   # direct api.deepseek.com only
INDAGO_LLM_KEY_CUSTOM=...               INDAGO_LLM_BASE_URL_CUSTOM=https://gateway.example/v1
```

`GET /api/llm/providers` reports which providers are usable and where the
credential came from (`settings` or `environment`); it never returns a key.
Settings offers `deepseek`, `claude`, `openai`, `openrouter`, and `google`.
Installations can configure additional gateway providers by environment.
Discover filters the catalog using reported capabilities and known specialized
model IDs. Test checks that the selected model accepts Indago's text request.

## Token accounting

Every successful advisory call stores the provider-reported usage on its
`AITask` (`prompt_tokens`, `completion_tokens`, `total_tokens`). A provider
that reports nothing leaves zeros; Indago never estimates. `GET
/api/scans/{id}/ai/usage` returns the per-scan totals plus the last 50 calls,
and the AI panel prints them.

The gateway deployment used for Indago runs the **custom** provider with
`ds/deepseek-v4.1-flash` and does not fall back to `deepseek-chat`: every
advisory call — assist, payload diagnosis, report narration — uses the same
model. Because it is a reasoning model, its hidden reasoning counts against the
output ceiling, so OpenAI-compatible calls send `max_tokens: 8192`; without a
ceiling a gateway default can be spent entirely on reasoning and return an
empty answer. Diagnosis calls are allowed 180 s for the same reason.

### Claude and OpenAI

In Settings, select `claude` or `openai`, enter the provider's API key, then
save. Use **Discover** for the API model catalog and **Test** to check the
selected model. Environment-managed installations can set
`INDAGO_LLM_KEY_CLAUDE` or `INDAGO_LLM_KEY_OPENAI` and the corresponding
`INDAGO_LLM_MODEL_<PROVIDER>`.

Both providers can draft executive summaries for reports. The former ChatGPT
setting is shown as OpenAI and requires an OpenAI API key. Claude also requires
an Anthropic API key.

### OpenRouter and Google AI (Gemini)

In Settings, select **OpenRouter** or **Google AI (Gemini)** and save the API
key from the corresponding service. **Discover** lists the provider's models.
Save your preferred default model, then use **Test** to check it. Both
providers can draft executive summaries for reports.

Set `INDAGO_LLM_KEY_OPENROUTER` or `INDAGO_LLM_KEY_GOOGLE` to configure a
provider through the server environment. Use `INDAGO_LLM_MODEL_OPENROUTER` or
`INDAGO_LLM_MODEL_GOOGLE` to override its default model.

## During a scan

The **AI advisory** card on a scan's Overview tab asks the selected provider
one question about the scan's stored state (endpoints, parameters, finding
counts, coverage). It is safe while the scan is running: it reads the store and
never touches the scan controller.

Request shapes:

```bash
curl -s -X POST -H 'Content-Type: application/json' -H 'X-Indago-Client: ui' \
  -d '{"kind":"prioritize","provider":"openai"}' \
  http://127.0.0.1:8750/api/scans/<scan-id>/ai/assist
```

Kinds: `prioritize` (endpoint order + reason), `triage` (which findings matter,
without changing a verdict), `next_steps` (manual checks). The response is
`{task_id, kind, provider, model, advisory:true, text}`; the call is recorded as
an `AITask` (request, response, state, provider, model) for audit.

The context sent to the model is bounded: at most 40 endpoints with up to six
parameter names each, finding counts, confirmed titles, seed URLs and scan
state. No evidence bytes, headers, cookies or request bodies.

## In a report

Set `ai_summary: true` and optionally `ai_provider` / `ai_model` when creating a
report. The paragraph is inserted into the pentest template's Executive Summary
as "AI-assisted draft (unverified, advisory only — the findings below are the
authoritative record)". The response includes `ai_summary_status` when requested,
with an `added`, `failed`, or `skipped` result and a message. The report remains
available if the summary is skipped or fails.

## Failure modes

| Situation | Answer |
| --- | --- |
| no provider configured at all | 503 "AI is not configured" |
| provider known, no key anywhere | 400 naming `INDAGO_LLM_KEY_<PROVIDER>` |
| provider unreachable / returns an error | 502 with the provider's redacted message |
| gateway streams by default | handled: `stream:false` is sent, and an SSE-framed body is decoded |

## Payload diagnosis (`/ai/diagnose`)

`POST /api/scans/{id}/ai/diagnose` answers the question the scanner cannot
answer itself: *why did this candidate not produce a signal?*

```json
{"finding_id": "...", "mode": "why_failed", "provider": "custom", "note": "optional hint"}
```

`mode` is `why_failed` (default), `waf_bypass`, or `suggest`. The response
carries `diagnosis`, `why_failed`, a `waf` assessment, up to 8 `payloads`
(with `encoded`, `context`, `proof`, `class`) and `next_steps`.

Evidence is the finding's own stored artifacts — response first, then request,
DOM and browser log — capped at 12 KB each and 48 KB total. Screenshots are
never sent. Before a byte leaves the process:

- `cookie`, `set-cookie`, `authorization`, `proxy-authorization`, `x-api-key`,
  `x-auth-token` and `x-csrf-token` header values are replaced with
  `[REDACTED]`;
- bearer tokens, `sk-…` keys, JWTs and `password`/`api_key`/`token`/`secret`
  fields in bodies are masked.

Captured evidence is attacker-influenced, so it is fenced as untrusted DATA and
the prompt tells the model to analyse it, never to follow instructions inside
it. The model's answer is prose; nothing is executed.

### Guards that keep the model honest and cheap

1. **Master switch** (`enabled` in Settings, default on). Off means no advisory
   call at all — assist, diagnose and report narration all return without
   contacting a provider.
2. **Confirmed parameters are skipped.** If the finding is confirmed, or any
   other finding on the same endpoint+parameter is confirmed, the endpoint
   replies `{"skipped": true, "skip_reason": ...}` and makes **no** model call.
   There is nothing to diagnose about a payload that already worked.
3. **Per-parameter attempt budget** (`max_attempts`, default 10). Failed
   advisory calls for the same parameter are counted; at the limit the endpoint
   stops asking and says so (`attempts_used` / `attempt_budget`). The scan keeps
   running with Indago's own deterministic tests.
4. **No repeats.** Every candidate value the engine already sent is passed to
   the model with an explicit "do not propose them again" instruction, and any
   returned payload that matches a tried value — after URL-decoding, so
   re-encoding does not sneak past — is dropped (`duplicates_dropped`).
5. **Scope fence.** Suggestions are restricted to the classes the engine can
   verify: `reflected_xss`, `dom_xss`, `idor`, `access_control`,
   `information_disclosure`. Each payload must declare `class`; anything else
   (`sqli`, `rce`, `ssrf`, `xxe`, `ssti`, …) is dropped
   (`out_of_scope_dropped`), even if the evidence hints at it.
6. **No verdict.** The model never marks a finding confirmed. It can say the
   evidence is insufficient, and the engine's own verification remains the only
   thing that can confirm.

The UI exposes both policy controls in Settings ("AI advisory" and "Attempts
per parameter") and the diagnosis itself as **Payload doctor** inside a
finding's dialog.

## Report review (triager)

Inspired by YesWeHack's Claude Kit (`/ywh:triage`), with one difference: it
runs on any configured provider, over the report Indago renders locally.

`POST /api/scans/{id}/ai/report-review {"mode":"confirmed","provider":"claude"}`
renders the YesWeHack template from the stored findings, sends those exact
submission bytes to the model, and asks for:

```json
{"verdict":"READY|NEEDS FIXES|DO NOT SUBMIT",
 "summary":"...",
 "issues":[{"severity":"blocker|major|minor","issue":"...","fix":"..."}],
 "missing_evidence":["..."]}
```

The rubric is the kit's core rule: judge only what the report proves. A
submission is READY only if a triager could reproduce it from the report alone
(endpoint, parameter, payload, observable proof). The model is told not to
invent impact and not to fail the report for the intentionally unscored CVSS
field, but to list it as a field to fill. Output is advisory and stored as an
`AITask`; it never edits the report or a finding.

Because the input is the rendered template, every provider reviews the same
structure: switching from DeepSeek to Claude changes the reviewer, not the
submission layout.

A lab host (for example a `web-security-academy.net` instance) is correctly
reported as out of scope by this pass. That is the intended behaviour: the
reviewer checks the host against the program, not against the scan.

## Audit: what is covered, what is not

Covered: provider settings (DeepSeek, Claude, OpenAI and OpenAI-compatible gateways), a master on/off switch, a
per-parameter attempt budget, payload diagnosis over stored evidence, report
narration, triager review over the rendered YesWeHack template, redaction of
cookies/keys before any evidence leaves the process, prompt-injection fencing of
target-derived text, and advisory-only output stored as `AITask`.

Known gaps, stated rather than hidden:

- **No automatic draft submission.** Indago renders the submission and reviews
  it; writing the draft into the platform (`PUT /programs/{slug}/reports/draft`)
  and spending submission credits is deliberately left to the hunter.
- **No cost/token accounting.** Calls are bounded by timeouts and output
  ceilings, not by a monetary budget per scan.
- **No per-review budget.** The per-parameter budget covers payload diagnosis;
  report review is a one-off action the operator triggers.

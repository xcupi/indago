# AI advisory (optional)

Indago works with no model configured. When one is configured, a model can do
two things — and only two things:

1. **Answer an explicit question about an existing scan** (`POST /api/scans/{id}/ai/assist`):
   prioritise endpoints, triage findings, propose next manual checks.
2. **Draft the executive-summary paragraph of a report** (`ai_summary: true` on
   report creation), labeled as an unverified draft.

Everything else is unchanged by design: the scanner decides what is tested and
what is confirmed, and the model's answer is stored as an advisory `AITask` —
prose, never a finding, verdict, severity or evidence. A scan running in the
background makes no model call on its own.

## Providers and credentials

Resolution order for one advisory call:

1. `ai_provider` on the request (assist body, or report body).
2. The provider saved in Settings (`/api/llm/config`).
3. `deepseek` by default.

A stored configuration supplies its own provider. **Additional providers come
from environment variables**, one key per provider, read at request time:

```bash
INDAGO_LLM_KEY_OPENAI=sk-...            INDAGO_LLM_MODEL_OPENAI=gpt-4o-mini
INDAGO_LLM_KEY_DEEPSEEK=sk-...          INDAGO_LLM_MODEL_DEEPSEEK=deepseek-chat
INDAGO_LLM_KEY_CUSTOM=...               INDAGO_LLM_BASE_URL_CUSTOM=https://gateway.example/v1
```

`GET /api/llm/providers` reports which providers are usable and where the
credential came from (`settings` or `environment`); it never returns a key.

Naming: `<PROVIDER>` is the provider id uppercased, non-alphanumerics replaced
by `_`. Supported: `deepseek`, `openai`, `custom` (any OpenAI-compatible
endpoint), plus the gateway's own `anthropic`/`openrouter`/`ollama`/`vllm`.

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
authoritative record)". If the provider is missing or the call fails, the report
is still generated, just without that paragraph.

## Failure modes

| Situation | Answer |
| --- | --- |
| no provider configured at all | 503 "AI is not configured" |
| provider known, no key anywhere | 400 naming `INDAGO_LLM_KEY_<PROVIDER>` |
| provider unreachable / returns an error | 502 with the provider's redacted message |
| gateway streams by default | handled: `stream:false` is sent, and an SSE-framed body is decoded |

## Verified providers

- **DeepSeek** (via an OpenAI-compatible gateway): connect probe, scan assist and
  report narrative all verified against a live endpoint.
- **OpenAI**: the same code path is exercised by tests against a stub endpoint;
  a live check needs an `INDAGO_LLM_KEY_OPENAI` key. Until one is set the API
  answers 400 with that exact instruction.

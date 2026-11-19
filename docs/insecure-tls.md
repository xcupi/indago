# Opt-in insecure TLS for lab and staging targets

`domain.ScanConfig.AllowInsecureTLS` (JSON `allow_insecure_tls`) disables TLS
certificate verification for **one scan's target-facing traffic**. It exists so
an authorized operator can test an HTTPS lab or staging system whose certificate
is self-signed or issued for a different hostname — the ordinary case for a VM
snapshot, a container behind an internal CA, or a staging host reached by IP.

It is **off by default**. With the zero value, Go's HTTP transport and Chromium
keep their normal, strict certificate verification, so a certificate the
toolchain does not trust aborts the connection instead of being silently
accepted.

## What the flag changes — and what it does not

Changes:

- **Raw HTTP engine.** `internal/scan/execution.go` builds a scan-scoped
  `httpengine.Client` with `Config.InsecureSkipVerify` set from this flag. Every
  raw request the scan makes — discovery fetches, reflection and candidate
  probes, the passive engines, redirect hops — uses that client.
- **Browser contexts.** Discovery rendering, reflected-XSS browser verification
  and DOM-XSS probing pass `browser.ContextOptions.IgnoreHTTPSErrors` (Playwright's
  `ignoreHTTPSErrors`), so a real Chromium can load the lab page.
- **Interactive / MFA / password login.** When a scan is created with a login
  mode, the login browser context receives the same flag, so a self-signed login
  page can be reached before a session is captured.

Does **not** change:

- **Scope.** The scope check still runs before every request and every redirect
  hop, in the same scope-enforcing engine. `AllowInsecureTLS` changes how the
  transport authenticates a server the scan was already authorized to talk to;
  it can never widen which hosts, paths, schemes or ports are targeted.
- **Rate and concurrency limits.** The scan's profile and shared limiter are
  unchanged.
- **Verdicts.** No engine uses certificate trust as evidence. In particular
  `internal/scan/methodtls.go` still records the presented certificate
  (`self_signed: true`, issuer, validity window) and reports only real transport
  weaknesses: an expired certificate, a negotiated protocol below TLS 1.2, or a
  weak/export cipher. A self-signed certificate by itself is **recorded, never
  reported as a finding** — accepting the lab's trust model is the operator's
  choice, not a vulnerability the report should repeat.
- **Evidence integrity.** A request or browser navigation that still fails (for
  example, a server that refuses TLS 1.2 or serves an expired certificate that a
  configured client rejects) is recorded as a failure/inconclusive attempt, never
  as a confirmation.

## Usage

CLI:

```
indago scan create -project PROJECT -target TARGET -allow-insecure-tls
```

The flag defaults to false and is only sent when set.

HTTP API, at scan creation:

```json
POST /api/scans
{
  "project_id": "...",
  "target_id": "...",
  "allow_insecure_tls": true
}
```

For a draft (`created`) scan, the same value can be set through
`PUT /api/scans/{id}/capabilities`:

```json
{ "allow_insecure_tls": true }
```

Like the other capability switches, it is fixed once execution starts; a scan
already running must be recreated to change it.

## Observability

Every scan that starts (or resumes) with `AllowInsecureTLS` enabled logs a WARN:

```
scan started with TLS certificate verification DISABLED (allow_insecure_tls):
self-signed and hostname-mismatched HTTPS certificates will be accepted by every
raw request and browser context of this scan — authorized lab/staging targets
only, never a production system
```

The warning names the scan ID and the target base URL. It is deliberately not
suppressible: an operator reading the server log must be able to see that a run
did not verify certificates.

## Safety boundary

This option is intended for authorized testing of lab and staging systems, not
for the open internet. Disabling verification removes the identity guarantee TLS
provides: the scan cannot distinguish the intended lab host from anything else
that can answer on that address and port. The flag does not bypass any other
AGENTS.md guardrail — explicit scope, conservative pacing, benign-marker payloads,
browser process sandboxing and deterministic verification all still apply.

See also `docs/browser-sandbox.md`, `docs/randomized-tls-validation.md`, and
`docs/reflection-candidates.md`.

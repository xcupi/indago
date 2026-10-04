# AGENTS.md

Operating guide for humans and AI agents working in the **Indago** repository.
Read this before making changes.

---

## 1. What Indago is

Indago is a **local-first, single-user web application security hunting
platform**. It helps an authorized operator discover and *verify* web
vulnerabilities against targets **they are explicitly permitted to test**.

- **Phase 1 scope (product):** Reflected XSS detection and verification.
- **Current phase (code):** Reflected XSS — baseline & **reflection detection** (no verdict yet).
- **Future (designed for, not built):** Stored XSS, DOM XSS, additional engines.

The architecture is deliberately generic (not XSS-specific) so new engines plug
in without reshaping the domain model.

---

## 2. Authorized-use & ethics guardrails

Indago is a defensive/authorized-testing tool. These rules are non-negotiable
and must be preserved by every change:

1. **Explicit scope is mandatory.** Nothing is ever tested until an operator has
   defined and the system has validated a `Scope`. Scope enforcement lives in
   the domain/scan layers and must fail closed.
2. **No anti-bot / WAF / detection evasion.** Do not add payload obfuscation for
   evasion, request-fingerprint spoofing, CAPTCHA solving, or similar. (Context-
   aware payload *encoding* required purely for correctness is not evasion.)
3. **Conservative by default.** Default profiles use low concurrency and request
   rates. Aggressive behavior is opt-in and operator-configured.
4. **No DoS / high-volume abuse.** Rate and concurrency controls exist to protect
   targets, not to maximize throughput against them.
5. **AI is advisory only.** An LLM may assist (triage, prioritization, context
   interpretation, report drafting). It is **never** the final authority for
   scope, vulnerability confirmation, evidence, or any security verdict. The tool
   must fully function with AI disabled.
6. **Evidence integrity.** Findings must be reproducible and backed by stored
   request/response/context/payload/browser evidence. Never fabricate evidence.

If a change would weaken any of the above, stop and raise it instead.

---

## 3. Current boundary — DO NOT IMPLEMENT YET

The platform is built incrementally. The following are explicitly **out of scope
right now** and must remain stubs/interfaces (job handlers are no-ops):

- ❌ XSS verdict / declaring a vulnerability (reflection is recorded, not judged)
- ❌ Exploit payload generation / payload libraries (the reflection step injects a
  fixed, non-executable detection canary — never scripts, handlers, or schemes)
- ❌ Context-aware candidate testing, automated exploitation
- ❌ Verification of findings

Implemented so far (infrastructure and **discovery**):

- ✅ Domain models (generic, not XSS-specific)
- ✅ Persistence layer (SQLite + in-memory), migrations
- ✅ Persistent job queue + concurrent worker pool
- ✅ HTTP engine (neutral transport; no scope checks inside it)
- ✅ Browser manager (Chromium/Playwright; neutral automation)
- ✅ Discovery (seeds, crawl, forms, sitemap, robots, wordlists, params,
  network observation) — real requests to **in-scope** targets only
- ✅ Scan controller: wires discovery + queue + workers, pause/resume/cancel,
  completion policy, restart recovery (see `docs/scan-orchestration.md`)
- ✅ Test job executor: runs each `JobTest` through the scope-enforcing engine and
  persists outcome (success/error/timeout/cancelled) + request/response evidence.
  Endpoint-level jobs send a baseline; injection-point jobs run the **Reflected
  XSS reflection step** — baseline + a mutated request carrying a unique,
  deterministic marker in the selected parameter only — and record reflection,
  locations, surrounding context, and the marker's encoding/transformation into
  `TestCase.Detail`. No verdict. State-changing methods need the explicit opt-in.
- ✅ Web UI + CLI (status and scan control)
- ✅ Evidence filesystem store, config, JSON reporting
- ⏳ Stubs: detection engines, verification, non-anonymous auth, AI providers

**The dividing line:** transport, browser, discovery, and orchestration are
implemented; anything that *tests a target for a vulnerability* is an interface
with a stub returning `ErrNotImplemented`.

**Scope is enforced outside the transport modules.** `httpengine` and `browser`
perform no scope checks; the scan controller wraps the HTTP engine in a
scope-enforcing engine (every request and redirect hop) and the discovery
collector re-checks every result. The browser aborts out-of-scope requests
itself (`AllowRequest`). Never hand an unwrapped engine to code that
follows attacker-influenced URLs.

---

## 4. Repository layout

```
cmd/indago/            CLI entrypoint (stdlib flag subcommands)
internal/
  domain/              Core domain models, enums, state machines (no deps)
  store/               Persistence interfaces
    memory/            In-memory store (tests, default dev)
    sqlite/            SQLite store + migrations (modernc.org/sqlite, pure Go)
  queue/               Persistent job queue interface + in-memory impl
  worker/              Concurrent worker pool
  httpengine/          HTTP engine abstraction (STUB in Phase 0)
  browser/             Browser service abstraction (STUB in Phase 0)
  discovery/           Discovery source abstraction + registry (STUBS)
  detection/           Detection engine interface + registry (no logic)
  verification/        Verification interface (STUB)
  auth/                Authentication abstraction (anonymous works; rest STUB)
  scan/                Scan controller, profiles, lifecycle wiring
  config/              Configuration load/save
  evidence/            Filesystem evidence store (implemented)
  report/              Report generator interface + JSON reporter
  ai/                  AI Gateway abstraction + disabled/noop provider (default)
  web/                 HTTP API + minimal UI skeleton
docs/                  Architecture, domain, state machines, interfaces, testing
```

See `docs/repository-structure.md` for the rationale.

---

## 5. Engineering workflow (every task)

1. **Change only what is necessary.** Keep diffs tight and focused.
2. **Match surrounding style.** Idiomatic Go; `gofmt`; small interfaces.
3. **Add/update tests** for any behavior you touch.
4. **Run the full gate** before reporting done:
   ```bash
   make check      # = gofmt check + go vet + go test ./...
   ```
   or individually:
   ```bash
   gofmt -l .
   go vet ./...
   go test ./...
   ```
5. **Report** changed files and any remaining issues honestly. If tests fail,
   say so and show output.

Keep it simple and local-first. **Do not** introduce Redis/Kafka/Kubernetes or
other heavy infrastructure without a concrete, documented requirement.

---

## 6. Dependencies

Minimal by policy. Current external dependency:

- `modernc.org/sqlite` — pure-Go SQLite driver (no cgo; clean local builds).

Everything else is the standard library (routing via `net/http.ServeMux`, CLI
via `flag`, IDs via `crypto/rand`). Add a dependency only with a clear reason.

---

## 7. Design priorities (in order)

```
Correctness → Reliable verification → Concurrency → Persistence
→ Evidence → Reproducibility → Maintainability
```

When trade-offs arise, prefer the earlier item.

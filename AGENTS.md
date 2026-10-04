# AGENTS.md

Operating guide for humans and AI agents working in the **Indago** repository.
Read this before making changes.

---

## 1. What Indago is

Indago is a **local-first, single-user web application security hunting
platform**. It helps an authorized operator discover and *verify* web
vulnerabilities against targets **they are explicitly permitted to test**.

- **Phase 1 scope (product):** Reflected XSS detection and verification.
- **Current phase (code):** **Phase 0 — architecture + scaffold only.**
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

## 3. Phase 0 boundary — DO NOT IMPLEMENT YET

Phase 0 is **scaffold and architecture only.** The following are explicitly
**out of scope right now** and must remain stubs/interfaces:

- ❌ Vulnerability detection logic
- ❌ Payload generation / payload libraries
- ❌ Automated exploitation
- ❌ Active target testing (no real HTTP/browser traffic *to targets*)
- ❌ Real crawling/spidering of live targets

What Phase 0 **does** build (infrastructure — safe to implement fully):

- ✅ Domain models (generic, not XSS-specific)
- ✅ Persistence layer (SQLite + in-memory), migrations
- ✅ Persistent job queue + concurrent worker pool
- ✅ Service **interfaces/abstractions** for: HTTP engine, browser, discovery,
  detection, verification, auth, AI gateway
- ✅ Scan orchestration/lifecycle wiring (handlers are no-ops in Phase 0)
- ✅ Evidence filesystem store, config, JSON reporting
- ✅ Web UI + CLI skeletons
- ✅ Tests, docs

**The dividing line:** infrastructure is implemented; anything that *performs
security testing against a target* is an interface with a stub returning
`ErrNotImplemented`.

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

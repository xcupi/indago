# Indago — Architecture

Indago is a **local-first, single-user** web application security hunting
platform. This document describes the system architecture established in
**Phase 0** (scaffold) and the shape it is designed to grow into.

> Scope reminder: Phase 0 contains **no** vulnerability detection, payload
> generation, exploitation, or active target testing. Infrastructure is real;
> every target-facing engine is an interface with a `ErrNotImplemented` stub.
> See [`../AGENTS.md`](../AGENTS.md).

---

## 1. Design goals & priorities

In priority order (ties broken toward the earlier item):

```
Correctness → Reliable verification → Concurrency → Persistence
→ Evidence → Reproducibility → Maintainability
```

Principles:

- **Local-first.** One process, one operator, one SQLite database, one evidence
  directory. No external infrastructure (no Redis/Kafka/K8s).
- **Scope fails closed.** Nothing is tested outside an explicit, validated scope.
- **Verification over reflection.** A reflection is only ever a *candidate*;
  confirmation requires browser evidence.
- **Generic domain.** The model is not XSS-specific, so Stored/DOM XSS and other
  engines slot in without reshaping it.
- **AI optional & advisory.** The scanner is fully functional with AI disabled;
  AI never decides scope, confirmation, evidence, or verdicts.

---

## 2. Component map

```
                        ┌─────────────────────────────────────────────┐
                        │                 CLI / Web UI                 │
                        │        cmd/indago        internal/web        │
                        └───────────────┬──────────────────────────────┘
                                        │
                        ┌───────────────▼───────────────┐
                        │        Scan Controller         │   internal/scan
                        │  lifecycle · scope · session   │
                        │  profiles · stop policy        │
                        └───┬───────────┬───────────┬────┘
                            │           │           │
             ┌──────────────▼──┐  ┌─────▼──────┐  ┌─▼───────────────┐
             │ Persistent Queue│  │ Worker Pool│  │  Auth (session) │
             │ internal/queue  │◄─┤internal/   │  │  internal/auth  │
             │ (sqlite|memory) │  │   worker   │  └─────────────────┘
             └──────────┬──────┘  └─────┬──────┘
                        │               │ dispatches by job type
                        │       ┌───────┼────────────┬───────────────┐
                        │       ▼       ▼            ▼               ▼
                        │  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐
                        │  │Discovery│ │HTTP engine│ │ Detection │ │ Verification │
                        │  │ sources │ │           │ │  engines  │ │  (browser)   │
                        │  └─────────┘ └──────────┘ └───────────┘ └──────────────┘
                        │   discovery/   httpengine/  detection/     verification/
                        │                                            browser/
                        ▼
             ┌─────────────────────────────────────────────────────┐
             │                    Persistence                       │
             │  internal/store (interfaces)                         │
             │  ├─ store/sqlite  (durable, modernc.org/sqlite)      │
             │  └─ store/memory  (tests / dev)                      │
             │  internal/evidence (filesystem blobs)                │
             └─────────────────────────────────────────────────────┘

             Cross-cutting:  internal/domain (model + state machines)
                             internal/config (local config)
                             internal/report (JSON reporter)
                             internal/ai     (optional, advisory gateway)
```

---

## 3. Data flow (designed end state)

The spec's pipeline, and where each stage lives:

```
Target / Scope          domain.Target, domain.Scope (scope fails closed)
  → Authentication       auth.Authenticator → domain.Session (established once, reused)
  → Discovery            discovery.Source → emits Endpoints/Parameters (continuous)
  → Endpoint/Param       domain.Endpoint, domain.Parameter, domain.InjectionPoint
      Registry           persisted via store
  → Persistent Queue     queue.Queue (every new injection point → a test job)
  → Concurrent Workers   worker.Pool (discovery/http/browser groups)
      → HTTP Engine      httpengine.Engine
      → Browser Engine   browser.Browser
      → Detection Engine detection.Engine (candidate, never confirmation)
      → Verification     verification.Verifier (confirmed/rejected/inconclusive)
  → Finding / Evidence   domain.Finding + domain.Evidence (blobs on disk)
  → Reporting            report.Generator (JSON in Phase 0)
  → AI Gateway           ai.Gateway (advisory only, optional)
```

**Key behavior — discovery and testing run in parallel.** Discovery does not
block testing: as each injection point is discovered it is persisted and a test
job is enqueued immediately. Workers consume the queue continuously.

---

## 4. Concurrency model

- **Independent worker groups.** The pool runs three named groups — `discovery`,
  `http`, `browser` — each serving one job type with its **own worker count**.
  Sizes map from `domain.ScanConfig` (DiscoveryConcurrency / HTTPConcurrency /
  BrowserConcurrency).
- **Runtime tunable.** Group sizes and the request rate can change while a scan
  runs (`Controller.Reconfigure` → `Pool.Resize` / `Pool.SetRate`).
- **Typed, scan-scoped leasing.** `Queue.Lease` filters by scan ID and job
  types, so each scan's pool draws only its own work and pause/cancel are
  per-scan.
- **Rate limiting.** A dependency-free limiter spaces target-facing (`http`)
  requests to honor `RequestsPerSecond`. Conservative defaults.
- **Multicore.** Work is naturally parallel across goroutines; SQLite access is
  serialized (single writer) for correctness on a local single-user DB.

See [`state-machines.md`](state-machines.md) for job/scan/session lifecycles.

---

## 5. Persistence & recovery

- **SQLite** (`modernc.org/sqlite`, pure Go, no cgo) is the durable store, with
  WAL journaling and a small, indexed schema (one table per aggregate). An
  **in-memory** store with identical behavior backs tests.
- **Evidence** blobs (responses, screenshots, HARs) live on the **filesystem**,
  content-addressed by SHA-256; only metadata is stored in SQLite.
- **Restart recovery.** On startup the controller requeues jobs left `leased`/
  `running` by a previous process (`Queue.Recover`). At runtime, jobs whose
  worker died (expired lease) are reaped (`Queue.ReapExpired`).
- **Pause / resume / cancel.** The queue persists across all three; pause/resume
  stop and restart leasing without losing queued work; cancel marks a scan's
  non-terminal jobs canceled.

---

## 6. Authentication model

One session is established **once per scan** and reused throughout. The scanner
never silently re-authenticates. On expiry the scan transitions to
`awaiting_auth` and the operator is asked to re-authenticate. Phase 0 implements
the **anonymous** mode; password, interactive-browser, MFA, and existing-session
modes are stubbed.

---

## 7. AI gateway

Optional and **disabled by default**. When enabled it is advisory only — it may
assist prioritization, triage, context interpretation, payload suggestions, JS
analysis, and report drafting, but **never** decides scope, confirmation,
evidence, or any security verdict. The invariant is reinforced in code: the
method is `Advise` (not `Decide`) and every response is flagged `Advisory`.

---

## 8. Technology choices

| Concern            | Choice                           | Why |
|--------------------|----------------------------------|-----|
| Language           | Go 1.26+                         | Concurrency, single static binary, strong stdlib |
| Database           | SQLite via `modernc.org/sqlite`  | Local-first, embedded, **no cgo** → clean builds |
| HTTP routing       | stdlib `net/http.ServeMux`       | Method+path patterns (Go 1.22+); no framework dep |
| CLI                | stdlib `flag`                    | No dependency; simple subcommands |
| Browser (Phase 1)  | Chromium via Playwright          | Real runtime for verification |
| IDs                | UUIDv4 (`crypto/rand`)           | No dependency |

**Dependency policy:** minimal. The only external module today is
`modernc.org/sqlite`. Everything else is the standard library.

---

## 9. Phase roadmap

| Phase | Adds |
|-------|------|
| **0** (now) | Architecture, domain model, persistence, queue, workers, service interfaces, UI/CLI shells, tests |
| **1** | Reflected XSS: real discovery, HTTP engine, detection pipeline, browser verification, evidence capture, auth modes |
| Later | Stored XSS, DOM XSS, additional engines, richer reporting (Markdown/HTML), AI providers |

The Phase 0 interfaces are the seams along which Phase 1+ attach — no domain
reshaping required.

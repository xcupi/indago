# Indago — Repository Structure

Rationale for the layout. The guiding ideas: a **leaf domain** everyone shares,
**interfaces at every seam**, and a crisp line between implemented infrastructure
and deferred security logic.

```
indago/
├── AGENTS.md                 Operating guide + scope boundary + ethics rules
├── README.md                 Overview, quick start
├── LICENSE                   MIT
├── Makefile                  build / test / vet / fmt gate
├── go.mod                    Module (Go 1.26+; single external dep)
│
├── cmd/
│   └── indago/
│       └── main.go           CLI: version | db init | serve
│
├── internal/                 All application code (not importable externally)
│   ├── domain/               ★ Leaf: entities, enums, state machines (stdlib only)
│   │   ├── ids.go            UUIDv4 IDs
│   │   ├── enums.go          Value enums (VulnClass, Severity, …) + IsValid
│   │   ├── state.go          Lifecycle enums + transition tables
│   │   ├── core.go           Project, Target, Scope(+Permits), Scan(+config types)
│   │   ├── discovery.go      Endpoint, Parameter, InjectionPoint
│   │   ├── jobs.go           TestJob, TestCase
│   │   ├── findings.go       Finding, Evidence, Provenance
│   │   ├── session.go        Session, AuthMode
│   │   ├── report.go         Report, ReportSummary
│   │   └── ai.go             AITask
│   │
│   ├── store/                Persistence interfaces
│   │   ├── store.go          Store + 14 repo interfaces, ErrNotFound/ErrConflict
│   │   ├── memory/           In-memory impl (generic table, deep-copy)
│   │   ├── sqlite/           SQLite impl + embedded migrations
│   │   │   ├── sqlite.go     Open/pragmas/helpers
│   │   │   ├── migrate.go    Embedded migration runner
│   │   │   ├── repos.go      14 repos (SQL)
│   │   │   └── migrations/   *.sql (embedded via go:embed)
│   │   └── storetest/        Shared conformance suite (runs against both)
│   │
│   ├── queue/                Persistent job queue
│   │   ├── queue.go          Queue interface, Stats, backoff
│   │   ├── memory.go         In-memory queue
│   │   └── sqlite.go         SQLite queue (atomic guarded leasing)
│   │
│   ├── worker/               Concurrent worker pool
│   │   ├── pool.go           Groups, resize, pause/resume, heartbeat
│   │   └── rate.go           Dependency-free rate limiter
│   │
│   ├── auth/                 Authentication (Anonymous ✅; others stub)
│   ├── discovery/            Source interface + Sink + registry (stubs)
│   ├── httpengine/           HTTP engine interface (stub)
│   ├── browser/              Browser interface (stub)
│   ├── detection/            Detection engine interface + registry (stubs)
│   ├── verification/         Verifier interface (stub)
│   │
│   ├── scan/                 Orchestration
│   │   ├── controller.go     Lifecycle, scope enforcement, session, pool wiring
│   │   ├── profiles.go       Profile presets + EvaluateStop
│   │   └── handlers.go       Phase 0 no-op job handlers
│   │
│   ├── config/               Local config (data dir, server, AI settings)
│   ├── evidence/             Filesystem evidence store (✅)
│   ├── report/               Report generator (JSON ✅)
│   ├── ai/                   AI gateway + providers (disabled by default)
│   │
│   └── web/                  HTTP API + minimal UI
│       ├── server.go         Routes, handlers, graceful serve
│       └── assets/           Embedded static dashboard (go:embed)
│
├── docs/                     This documentation set
└── data/                     Runtime state (gitignored): indago.db, evidence/, config.json
```

★ = leaf package (no internal dependencies).

---

## Conventions

- **`internal/`** for everything: nothing is a public API surface yet.
- **One aggregate per domain file**, one concern per infra file.
- **Interfaces live with their consumer's expectations**, implementations in
  subpackages (`store` → `store/sqlite`, `store/memory`).
- **Tests sit beside code** (`*_test.go`); cross-implementation behavior is
  verified by shared suites (`store/storetest`, the queue's `runEach`).
- **Stubs are explicit**: a deferred capability is an interface plus a `Stub`
  whose methods return `ErrNotImplemented` — never a silent no-op that could be
  mistaken for real behavior. (The one deliberate exception is the scan
  controller's Phase 0 handlers, which are documented no-ops used only to
  exercise the pipeline.)

---

## Why `internal/domain` is a leaf

Keeping the model free of dependencies means:

- It can't accidentally couple to SQLite, HTTP, or any engine.
- State-machine rules live in one place and are imported everywhere.
- Tests for the model are pure and fast.

Everything else depends inward toward `domain`; `domain` depends on nothing but
the standard library.

---

## Data directory (`data/`)

Local-first: all runtime state is under one directory (default `./data`,
gitignored):

```
data/
├── indago.db       SQLite (projects, scans, jobs, findings, evidence metadata…)
├── evidence/       Content-addressed blobs: <scan>/<kind>/<sha256><ext>
└── config.json     Persisted configuration
```

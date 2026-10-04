# Indago

**Local-first, single-user web application security hunting platform.**

Indago helps an authorized operator **discover** and **verify** web
vulnerabilities against targets they are explicitly permitted to test. It
emphasizes *verified* findings (not mere reflections), reproducible evidence,
and conservative, operator-controlled behavior.

> ⚠️ **Authorized use only.** Only run Indago against systems you own or have
> explicit written permission to test. Indago enforces explicit target scope
> before any testing and does **not** implement anti-bot/WAF evasion.

---

## Status

| Phase | Scope | State |
|-------|-------|-------|
| **Phase 0** | Architecture + repository scaffold | **current** |
| Phase 1 | Reflected XSS detection & verification | planned |
| Later | Stored XSS, DOM XSS, more engines | designed-for |

**Phase 0 contains no vulnerability detection, payload generation, exploitation,
or active target testing.** It is the skeleton: domain models, persistence,
job queue, worker pool, service interfaces, and UI/CLI shells. See
[`AGENTS.md`](AGENTS.md) for the exact scope boundary.

---

## Architecture at a glance

```
Target / Scope
  → Authentication
  → Discovery  ──┐ (continuous, parallel with testing)
  → Endpoint / Parameter Registry
  → Persistent Job Queue  ⇄  Concurrent Workers
        → HTTP Engine
        → Browser Engine
        → Detection Engine
        → Verification
  → Finding / Evidence
  → Reporting
  → AI Gateway (optional, advisory only)
```

Full design docs live in [`docs/`](docs/):

- [`architecture.md`](docs/architecture.md) — components & data flow
- [`domain-model.md`](docs/domain-model.md) — entities & relationships
- [`state-machines.md`](docs/state-machines.md) — scan / job / session / finding lifecycles
- [`interfaces.md`](docs/interfaces.md) — service boundaries & contracts
- [`repository-structure.md`](docs/repository-structure.md) — layout rationale
- [`testing-strategy.md`](docs/testing-strategy.md) — how we test

---

## Requirements

- **Go 1.26+** (production target). The repo's `go.mod` is currently pinned to
  `1.22` to match the installed dev toolchain; the code is compatible with both.
- SQLite is embedded via the pure-Go `modernc.org/sqlite` driver (no cgo).
- Chromium/Playwright will be required for browser verification in **Phase 1**
  (not needed for Phase 0).

---

## Quick start

```bash
# Build
make build

# Initialize the local database (creates ./data by default)
./bin/indago db init

# Start the web UI + API (default http://127.0.0.1:8750)
./bin/indago serve

# Show version
./bin/indago version
```

Run the quality gate:

```bash
make check     # gofmt + go vet + go test ./...
```

---

## Configuration & data

Local-first: all state lives under a single data directory (default `./data`):

```
data/
  indago.db            SQLite database (projects, scans, jobs, findings, …)
  evidence/            Large evidence blobs (responses, screenshots) on disk
  config.json          Persisted configuration
```

Nothing is sent anywhere by default. The optional AI Gateway is **disabled**
unless you explicitly configure a provider; even then it is advisory only and
never decides scope or confirms a vulnerability.

---

## License

See [`LICENSE`](LICENSE).

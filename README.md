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
| Scaffold | Domain, persistence, queue, workers, interfaces | done |
| Transport | HTTP engine, browser manager | done |
| Discovery | Crawl, forms, sitemap/robots, wordlists, params; scan controller integration | **current** |
| Phase 1 | Reflected XSS detection & verification | next |
| Later | Stored XSS, DOM XSS, more engines | designed-for |

**There is no vulnerability detection, payload generation, or exploitation yet.**
A scan currently performs scope-enforced *discovery* (real requests to in-scope
targets only) and drains its test jobs through no-op handlers. See
[`AGENTS.md`](AGENTS.md) for the exact boundary and
[`docs/scan-orchestration.md`](docs/scan-orchestration.md) for how a scan runs.

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

Drive a scan from another terminal (the CLI talks to the running server; the web
UI at http://127.0.0.1:8750 shows the same state):

```bash
./bin/indago project create "my project"                       # → project ID
./bin/indago scope set  -project <PID> -include app.example.com   # scope is mandatory
./bin/indago target add -project <PID> -name app -url https://app.example.com/
./bin/indago scan create -project <PID> -target <TID> -profile conservative
./bin/indago scan start  <scan-id>        # IDs may be a unique prefix
./bin/indago scan status <scan-id>        # discovery progress, jobs, provenance
./bin/indago scan pause|resume|cancel <scan-id>
```

Only scan systems you own or have written permission to test. Nothing is
requested outside the scope you set — including redirect targets.

After a crash or restart, interrupted scans come back **paused**; nothing is sent
until you run `indago scan resume`.

Each discovered endpoint is then requested once as a **baseline** (observed
values, no payloads) and the result plus request/response evidence is stored
under `data/evidence/`. POST/PUT/PATCH/DELETE endpoints are skipped unless you
start the server with `-allow-state-changing`. `indago serve -browser` adds
browser network discovery (needs Chromium; out-of-scope requests are blocked in
the browser).

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

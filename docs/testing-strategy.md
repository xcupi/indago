# Indago — Testing Strategy

Testing follows the project's priority order: **correctness** and **reliable
verification** first, then concurrency, persistence, evidence, reproducibility.

---

## 1. Principles

- **Test behavior through interfaces**, not implementation details. The same
  suite runs against multiple implementations where they must agree.
- **Fast and deterministic by default.** Use the in-memory store/queue for logic;
  use real SQLite (temp files) for persistence-specific tests.
- **Control time, don't sleep on it.** Queue/retry/lease logic uses an injectable
  clock (`SetClock`) so backoff and expiry are tested deterministically.
- **Race-clean.** Concurrency code is tested under `-race`.
- **No network, no targets.** Phase 0 tests never touch a target (there is no
  target-facing code yet); stubs assert `ErrNotImplemented`.

---

## 2. Test layers

### Unit — domain
`internal/domain` — ID generation/format/uniqueness, enum validation, state-
machine transitions (legal and illegal), and the safety-critical
`Scope.Permits` (fail-closed, exclusions win, subdomain rules, bad input).

### Conformance — persistence
`internal/store/storetest` is a single suite exercised by **both** the memory and
SQLite stores (`store/memory`, `store/sqlite`). It covers CRUD, not-found,
list-filter isolation, update semantics, and **deep-copy isolation** (mutating a
returned entity must not corrupt stored state). SQLite adds:
- **Migration idempotency** (migrate repeatedly → one applied record).
- **Persistence across reopen** (write, close, reopen, read).

### Behavioral — queue
`internal/queue` runs one suite against both implementations (`runEach`):
enqueue/lease/complete, priority ordering, `ErrNoJobs`, retry backoff → dead
(fake clock), fail-no-retry, cancel/cancel-scan, recover, reap-expired, stats,
and **scan-isolation** leasing. SQLite additionally has a **concurrency test**
(16 goroutines hammering `Lease`) asserting **no double-lease**.

### Behavioral — workers
`internal/worker` (under `-race`): jobs processed to completion, pause stops
progress / resume drains, permanent failure → dead, missing handler → dead,
runtime resize up/down, and typed groups only handling their own job types.

### Behavioral — orchestration
`internal/scan` (under `-race`): scope enforcement at creation
(`ErrScopeRequired` / `ErrScopeEmpty` / `ErrOutOfScope`), full lifecycle
(create → start → session active → job processed → pause → resume → reconfigure →
cancel), illegal-transition rejection, and the pure `EvaluateStop` stop-policy
table.

### Component — web
`internal/web` via `httptest`: health, version, project create/list/get (+404,
+validation), static UI served, and graceful serve/shutdown.

### Contract — abstractions
`auth`, `discovery`, `detection`, `ai`: the working default (anonymous auth,
disabled gateway) behaves, registries enumerate correctly, and every stub returns
`ErrNotImplemented`. `report`/`config`/`evidence`: JSON report validity +
summary math, config round-trip/defaults/derived paths, evidence content-
addressing + idempotency + path-traversal rejection.

### Real Chromium
`internal/browser/playwright_integration_test.go` drives a real Chromium (render,
context isolation, cancellation, and that the scope gate stops out-of-scope
requests from leaving the browser). `internal/verification/browser_integration_test.go`
drives the same real Chromium through `BrowserVerifier` directly: a reflected-
but-non-executable candidate is rejected, an executable one (HTML text/attribute,
JS string) is confirmed via the uncaught-exception signal, a merely-reflected
`javascript:` URL is rejected (not activated by passive load), an authenticated
session's cookie reaches the server, out-of-scope subresources and navigation
are blocked, and timeout/cancellation are observed. Both run by default and skip
when no Chromium is found (`$INDAGO_CHROMIUM_PATH` or
`~/.cache/ms-playwright/chromium-*`; skipped in `-short`). Chromium is launched
by explicit path, so the Playwright driver and the installed revision need not
match.

### Test job executor
`internal/scan/executor_test.go` (request construction, resolution, each outcome
and its retry/permanent mapping, evidence content, scope, evidence-write failure,
and — through the worker pool — job states, concurrency limit, pause/resume) and
`executor_integration_test.go` (a full scan's persisted results, the
state-changing opt-in, cancel recording `cancelled`, crash recovery of running
test cases).

### Candidate execution and browser verification
`internal/scan/candidate_test.go` (sending one candidate per job, parameter
preservation, enqueue/dedup/ordering, concurrency) and `verify_test.go`
(enqueueing a Pending Finding + `JobVerify` from a reflected candidate against a
FAKE `verification.Verifier` — fast and deterministic: outcome mapping for
confirmed/rejected/inconclusive/timeout/cancelled/skipped, the state-changing
and GET/HEAD-only guards, scope/session pass-through into `verification.Input`,
and evidence/Finding persistence). The signal itself and real-browser behavior
are covered by the Real Chromium tests above, not re-verified here.

### End-to-end — binary smoke
The built binary is exercised manually/CI: `db init` creates the schema; `serve`
brings up the stack; the API persists a project that **survives a restart**.

---

## 3. The quality gate

Every change must pass, before being reported done:

```bash
make check     # gofmt -l (clean) + go vet ./... + go test ./...
```

Equivalent to:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...     # add -race for concurrency work: make test
```

`make cover` produces a coverage summary.

---

## 4. Conventions

- Table-driven tests for enumerable cases (transitions, stop policy, scope).
- `t.TempDir()` for SQLite/evidence file tests (auto-cleaned).
- Quiet loggers (`slog` → `io.Discard`) in tests.
- Poll-with-timeout helpers (`waitFor`) for async assertions — never a bare
  `time.Sleep` to "wait for" work.
- Shared suites (`storetest`, queue `runEach`) prevent implementations from
  drifting apart.

---

## 5. What Phase 1 testing will add

- Golden-file tests for the reflection/context analysis on captured responses.
- A local, intentionally-vulnerable test app (served on `127.0.0.1`) for
  end-to-end detection+verification — exercised only against that local target.
- Browser-verification tests (headless Chromium) asserting that **reflection
  without execution ⇒ not confirmed**, and execution ⇒ confirmed with evidence.
- Evidence completeness assertions (request/response/context/screenshot present
  and hash-verified for every confirmed finding).

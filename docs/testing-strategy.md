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

### Fuzz — context classifier
`internal/detection/fuzz_test.go` (`FuzzClassifyAt`): the hand-written HTML/
JS/CSS/URL tokenizers in `context_*.go` parse bytes straight from a scanned
target's HTTP response — untrusted input, since the whole point of the tool is
testing applications that may themselves be buggy or hostile. Unlike
`golang.org/x/net/html` (not used, per the project's minimal-dependency
policy), these tokenizers are project-local, so they get their own fuzz target
rather than relying on an upstream library's hardening. The only requirement
is "never panics or hangs" — any `ContextAnalysis` is an acceptable answer for
garbage input. `go test ./internal/detection/... -fuzz FuzzClassifyAt` for a
real fuzzing run (regular `go test` only replays the seed corpus).

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
and evidence/Finding persistence). The signal itself, real-browser behavior,
and unrelated/pre-existing page errors correctly NOT confirming are covered by
the Real Chromium tests above, not re-verified here.

### Finding correlation and reporting
`internal/scan/finding_test.go`: the dedup key (same site vs. distinct
parameter/distinct context), `upsertPendingFinding` (new finding creation with
full provenance, correlating a duplicate candidate without losing it as raw
evidence, an exact retry not re-adding the same candidate twice), and
`correlateVerification` (confirmed/rejected/inconclusive, evidence linkage
across BOTH the candidate's HTTP evidence and the verification's browser
evidence, the monotonic confirm-is-sticky rule, and the allowed
inconclusive/rejected→confirmed upgrade) — all against the in-memory store, no
browser needed. `internal/report/markdown_test.go` and `report_test.go`:
Markdown/JSON validity and, since `Summarize`'s breakdowns are Go maps,
deterministic byte-identical output across repeated `Generate` calls.
`storetest/suite.go`'s finding/evidence conformance test round-trips the new
`ParameterID`/`Detail` fields through both the memory and SQLite backends.

### End-to-end — full pipeline against a local corpus
`internal/scan/e2e_corpus_test.go` drives a real `Controller` + real Chromium
over a one-server corpus covering every scenario the pipeline needs to get
right (reflected-but-safe, encoded, HTML-attribute, JavaScript, multiple
reflection sites, confirmed, a page with an unrelated/pre-existing browser
error, an authenticated endpoint, an out-of-scope resource, and GET/POST-
form/POST-JSON) — asserting the correct verdict lands on each, evidence
resolves, and JSON/Markdown reports are reproducible.
`e2e_recovery_test.go` crashes a scan mid-`JobVerify` navigation and restarts
with a fresh `browser.Manager`, asserting recovery (no duplicate findings, no
orphaned work). `e2e_hardening_test.go` covers concurrent scans sharing one
browser pool, a goroutine-leak check across a scan's lifecycle, malformed/
oversized responses, a larger crawl, and throughput/memory measurements
(logged for inspection, not gated on exact numbers). See
[`e2e-validation.md`](e2e-validation.md) for what this found and fixed. All of
these skip (quickly) when no Chromium is found, like the other real-browser
suites.

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

**`make test` runs `go test -race -p 1 ./...`, deliberately serialized.**
Several packages (`internal/browser`, `internal/scan`, `internal/verification`)
launch real Chromium instances under test. `go test`'s default parallelism runs
different packages' test binaries concurrently, which lets their Chromium
processes compete for CPU at the same time — under `-race`'s overhead, that can
push a real-browser test's own internal timeout past its deadline on a loaded
machine (observed in `TestE2E_RestartRecoversInterruptedVerification`: fails
intermittently with full default parallelism, passes reliably both in
isolation and under `-p 1`, confirming the cause is scheduling contention
rather than a product race). `-p 1` costs wall-clock time but removes that
contention entirely; prefer it over chasing a flake that `-race` would
otherwise make look like a real bug. A single package's tests still run their
own subtests/goroutines concurrently as normal — only cross-package
parallelism is removed.

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

# Indago — Interfaces & Boundaries

The system is organized around small interfaces so behavior can be swapped,
stubbed, and tested in isolation. This document catalogs the key contracts and
their **Phase 0 status**.

Legend: ✅ implemented · 🔌 interface + stub (returns `ErrNotImplemented`) ·
🧩 interface + working default.

---

## 1. Persistence — `internal/store`

```go
type Store interface {
    Projects() ProjectRepo
    Targets() TargetRepo
    Scopes() ScopeRepo
    Scans() ScanRepo
    Endpoints() EndpointRepo
    Parameters() ParameterRepo
    InjectionPoints() InjectionPointRepo
    Jobs() JobRepo
    TestCases() TestCaseRepo
    Findings() FindingRepo
    Evidence() EvidenceRepo
    Sessions() SessionRepo
    Reports() ReportRepo
    AITasks() AITaskRepo

    Migrate(ctx) error
    Ping(ctx) error
    Close() error
}
```

- Each repo is minimal CRUD plus a few domain list filters (e.g.
  `ScanRepo.ListByProject`, `JobRepo.ListByState`).
- Errors: `store.ErrNotFound`, `store.ErrConflict`.
- Implementations: ✅ `store/sqlite` (durable), ✅ `store/memory` (tests/dev).
- Both pass the **same conformance suite** (`store/storetest`), guaranteeing
  identical behavior.

**Boundary:** the rest of the system depends on these interfaces, never on
SQLite directly (except the queue, which deliberately shares the `jobs` table via
`*sql.DB`).

---

## 2. Persistent queue — `internal/queue`

```go
type Queue interface {
    Enqueue(ctx, *domain.TestJob) error
    Lease(ctx, workerID string, scanID domain.ID, types []domain.JobType, leaseFor time.Duration) (*domain.TestJob, error)
    Heartbeat(ctx, jobID domain.ID, leaseFor time.Duration) error
    Complete(ctx, jobID domain.ID) error
    Fail(ctx, jobID domain.ID, cause string, retry bool) error
    Cancel(ctx, jobID domain.ID) error
    CancelScan(ctx, scanID domain.ID) (int, error)
    Recover(ctx) (int, error)                 // startup: requeue all active
    ReapExpired(ctx, now time.Time) (int, error) // runtime: requeue expired leases
    Stats(ctx, scanID domain.ID) (Stats, error)
}
```

- Implementations: 🧩 `queue.NewMemory()` (tests/dev), ✅ `queue.NewSQLite(db)`
  (persistent, atomic guarded leasing).
- `Lease` filters by **scan** and **job type** → per-scan, per-group draw.
- Retry backoff is capped-exponential; `ErrNoJobs` when nothing is available.

---

## 3. Worker pool — `internal/worker`

```go
type Handler interface { Handle(ctx, *domain.TestJob) error }
type HandlerFunc func(ctx, *domain.TestJob) error

type Pool struct { /* ... */ }
func New(q queue.Queue, handlers map[domain.JobType]Handler, cfg Config, log) *Pool
func (p *Pool) Start(ctx) error
func (p *Pool) Pause(); func (p *Pool) Resume()
func (p *Pool) Resize(group string, n int) error
func (p *Pool) SetRate(rps float64)
func (p *Pool) Stop()
```

- ✅ implemented. Named groups (`discovery`/`http`/`browser`), runtime resize,
  pause/resume, lease heartbeating, optional rate limiting.
- `ErrPermanent` marks a non-retryable handler failure; any other error is
  retried subject to the job's `MaxAttempts`.
- **Handlers are supplied by the caller.** Phase 0 wires no-op handlers.

---

## 4. Authentication — `internal/auth`

```go
type Authenticator interface {
    Mode() domain.AuthMode
    Establish(ctx, Input) (*domain.Session, error)
    Validate(ctx, *domain.Session) (bool, error)
}
func For(mode domain.AuthMode) (Authenticator, error)
```

- ✅ `Anonymous` (no credentials; immediately active; never expires).
- 🔌 `password`, `interactive`, `mfa`, `existing` (stubs).
- Secrets are never logged; interactive/MFA login and credential handling arrive
  in Phase 1.

---

## 5. Discovery — `internal/discovery`

```go
type Sink interface {
    AddEndpoint(ctx, domain.Endpoint) error
    AddParameter(ctx, domain.Parameter) error
}
type Source interface {
    Name() domain.DiscoverySource
    Run(ctx, Input, Sink) error   // streams results; does not block testing
}
type Registry struct { /* register/get/names by source */ }
```

- 🔌 All sources are stubs (`DefaultRegistry` registers one per planned method:
  user-provided, crawler, form, browser-network, sitemap, robots, content, param).
- The `Sink` streaming contract is what lets **discovery and testing run in
  parallel** — a source emits endpoints/parameters as it finds them.

---

## 6. HTTP engine — `internal/httpengine`

```go
type Engine interface { Do(ctx, *Request) (*Response, error) }
```

- 🔌 `Stub` returns `ErrNotImplemented` — **no target traffic in Phase 0**.
- The real engine (connection reuse, timeouts, session cookies, rate
  integration) is Phase 1.

---

## 7. Browser — `internal/browser`

```go
type Browser interface {
    Render(ctx, url string, RenderOptions) (*RenderResult, error)
    Close() error
}
```

- 🔌 `Stub`. `RenderResult` exposes generic runtime signals (executed markers,
  dialogs, console logs/errors, screenshot) that verification consumes.
- Real implementation: Chromium via Playwright (Phase 1).

---

## 8. Detection — `internal/detection`

```go
type Engine interface {
    Name() string
    VulnClass() domain.VulnClass
    Detect(ctx, Input) (*Outcome, error)   // proposes a CANDIDATE, never confirms
}
type Registry struct { /* by VulnClass */ }
```

- 🔌 `DefaultRegistry` registers a Reflected XSS **stub** only. Stored/DOM XSS are
  intentionally absent until their phases.
- Contract: a detection engine **never confirms** — it proposes candidates for
  verification.

---

## 9. Verification — `internal/verification`

```go
type Verifier interface { Verify(ctx, Input) (*Result, error) }  // → Verdict + evidence
```

- 🔌 `Stub`. This is the authority that turns a candidate into
  `confirmed`/`rejected`/`inconclusive`, backed by browser evidence (Phase 1).

---

## 10. Evidence — `internal/evidence`

```go
type Store interface {
    Put(scanID, kind, ext, data) (Ref, error)   // content-addressed by SHA-256
    Open(relPath) (io.ReadCloser, error)
    AbsPath(relPath) string
}
```

- ✅ `FSStore` (filesystem). Idempotent writes, path-traversal guarded.

---

## 11. Reporting — `internal/report`

```go
type Generator interface { Format() domain.ReportFormat; Generate(w, Data) error }
func For(format) (Generator, error)
func Summarize(scanID, []*Finding) domain.ReportSummary
```

- ✅ `JSONGenerator`. 🔌 Markdown/HTML return `ErrNotImplemented`.

---

## 12. AI gateway — `internal/ai`

```go
type Gateway interface { Enabled() bool; Advise(ctx, Request) (*Response, error) }
type Provider interface { Name() string; Complete(ctx, Request) (*Response, error) }
func New(Settings) (Gateway, error)
```

- 🧩 `Disabled` is the default (scanner works without AI). When enabled, wraps a
  Provider and stamps every response `Advisory`.
- 🔌 Providers (`openai`, `anthropic`, `openrouter`, `ollama`, `vllm`) are stubs.
- **Invariant:** advisory only — never authoritative for scope, confirmation,
  evidence, or verdict. Enforced by naming (`Advise`) and the `Advisory` flag.

---

## 13. Orchestration — `internal/scan`

```go
type Controller struct { /* ... */ }
func (c *Controller) CreateScan(ctx, CreateScanParams) (*domain.Scan, error)
func (c *Controller) Start/Pause/Resume/Cancel(ctx, scanID) error
func (c *Controller) Reconfigure(ctx, scanID, domain.ScanConfig) error
func (c *Controller) Recover(ctx) (int, error)
func (c *Controller) Stats(ctx, scanID) (queue.Stats, error)
```

- ✅ implemented. Enforces scope (fail closed), establishes the reused session,
  builds the per-scan worker pool with no-op handlers, and exposes the full set
  of scan controls. `scan.EvaluateStop` implements the stop policy.

---

## 14. Dependency direction

```
cmd/indago, internal/web
        │ depends on
        ▼
internal/scan ──► internal/{queue,worker,auth,store,config}
        │                 │
        ▼                 ▼
internal/{httpengine,browser,discovery,detection,verification,evidence,report,ai}
        │
        ▼
internal/domain   (leaf — no internal deps)
```

`internal/domain` is the leaf everyone shares. No import cycles. The queue
depends on `*sql.DB` (not on `store/sqlite`) to share the `jobs` table without a
cycle.

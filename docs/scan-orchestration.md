# Indago — Scan Orchestration

How a scan runs: the `internal/scan` controller wires **discovery**, the
**persistent queue**, and the **worker pool** together, and owns pause / resume /
cancel, completion, and restart recovery.

> Boundary: a scan performs scope-enforced **discovery**, runs each test job (a
> baseline; the **Reflected XSS reflection → context → candidate-plan** step for
> an injection point; a **candidate** job that sends one planned benign-marker
> breakout and re-analyzes it; or a **browser-verify** job that confirms/rejects
> a reflected candidate — sections 1b–1c), and records the result. The verdict
> itself (Confirmed/Rejected/Inconclusive) is a deterministic function of a real
> browser signal — **never an LLM**, and verification never performs
> exploitation beyond replaying the exact candidate already sent. Detection
> attaches through `scan.Options.Handlers`.

---

## 1. What starts when a scan enters RUNNING

`Controller.Start` (or `Resume`, for a restored scan) launches one **execution**
per scan:

```
                         ┌──────────────────────── execution ────────────────────────┐
 Scan → RUNNING ───────► │  discovery run ──► Collector ──► store + queue.Enqueue      │
                         │   (sources, concurrent)   │                                 │
                         │                           ▼  every new endpoint/parameter   │
                         │                     TestJob(queued) immediately             │
                         │                           │                                 │
                         │  worker pool (http/browser/discovery groups) ◄── Lease ─────┤
                         │                                                             │
                         │  monitor: stats refresh · stop policy · completion          │
                         └─────────────────────────────────────────────────────────────┘
```

- **Discovery and testing run in parallel.** The collector enqueues a test job
  for each endpoint and each injection point *as it is discovered*; workers lease
  them while discovery is still running. Exactly one job is created per endpoint
  and one per injection point (deduplicated).
- **Seeds**: the scan's `SeedURLs`, or the target base URL when none were given.
  Every seed must be in scope at creation (an out-of-scope seed is rejected, not
  silently dropped).
- **Provenance** (`user_provided`, `crawler`, `form`, `sitemap`, `robots`, …) is
  stored on every endpoint/parameter and surfaced in status.

## 1b. Test job execution

Each `JobTest` is run by the **executor** (`internal/scan/executor.go`) on the
worker pool's `http` group, so HTTP concurrency, the request rate, pause/resume,
and cancel are exactly the pool's.

1. **Resolve** the job's endpoint, the endpoint's parameters, and (for an
   injection-point job) the focused parameter; all must belong to the job's scan.
2. **Build the baseline request**: the endpoint's method and URL with every known
   parameter at its **observed value** — query parameters in the URL, form/JSON
   parameters in the body — in a deterministic order. No mutation, no payloads;
   a later phase attaches by choosing which parameter value to substitute.
3. **Execute** through the scan's scope-enforcing engine with a per-request
   timeout (`ExecutorConfig.RequestTimeout`, default 20s).
4. **Persist** a `TestCase` (one per job attempt) with the result and
   **evidence**: the request and the response (when received) as HTTP/1.1 message
   blobs in the evidence store, with `Evidence` rows (kind, size, SHA-256)
   referenced from `TestCase.EvidenceIDs`.

**Injection-point jobs run the Reflected XSS reflection step** instead of a plain
baseline:

- A **baseline** (all parameters at observed values) is fetched once per endpoint
  and **reused** across that endpoint's injection points (cached by request
  signature); a failed baseline is not cached.
- A **mutated** request carries a unique, deterministic marker
  (`detection.NewProbe`) in the **selected parameter only**; all others keep their
  observed values. Supported for GET query, POST form, and POST JSON.
- The marker is an alphanumeric token bracketed around a fixed canary
  (`<>"'`) by a second sentinel. The analyzer (`detection.AnalyzeReflection`,
  pure) locates the token, counts reflection sites, records surrounding context,
  and classifies how the canary came back (none/html/url/js/stripped/mixed). The
  canary is a detection probe, **not** an exploit payload.
- Each reflection site is then **context-classified** (`detection.ClassifyContexts`,
  pure — see [`reflection-context.md`](reflection-context.md)): where the marker
  sits in the real response markup, with confidence and reason.
- A **candidate plan** is then derived (`detection.PlanCandidates`, pure — see
  [`reflection-candidates.md`](reflection-candidates.md)): per site, an ordered,
  deduplicated set of benign-marker breakout candidates chosen from the context
  and the observed transformation.
- The reflection job then **enqueues one child `JobTest` per planned candidate**
  (before it completes, so completion waits for them). Each child's job priority
  is the candidate's priority, so the queue drains them in the plan's
  deterministic order; the plan's dedup means one request per unique candidate. A
  **candidate job** (`internal/scan/candidate.go`) sends its single breakout into
  the injection point — all other parameters unchanged, GET query / POST form /
  POST JSON — through the scope-enforcing engine, then **re-runs reflection +
  context analysis** on the response. It records reflected/not_reflected and
  evidence, but **does not re-plan** (no recursion). The state-changing opt-in is
  re-checked, so a breakout never reaches a state-changing endpoint unless the
  operator allowed it.
- A candidate that **reflects via GET/HEAD** is **correlated into a `Finding`**
  (`internal/scan/finding.go`'s `upsertPendingFinding` — see
  [`finding-correlation.md`](finding-correlation.md)): the same injection point
  producing the same candidate category+context absorbs into one existing
  `Finding` rather than minting a near-duplicate, with every distinct
  candidate's TestCase ID preserved as raw evidence regardless. A genuinely
  new site creates one at `VerdictPending`. Either way, a **browser-verify
  job** (section 1c) is then enqueued. A POST/body-carrying reflection has no
  browser-navigable form in this phase and stays `pending`.
- The `detection.ReflectionReport` (reflection + context + plan; for a candidate
  job, reflection + context + the executed `candidate`) is stored in `TestCase.Detail`; evidence
  references the shared baseline (request+response) and the mutated
  (request+response), and the report records the response body's offset inside
  the response evidence blob so every site offset resolves to an exact byte.
  **No verdict is made by the executor** — reflection and context are recorded,
  not judged; only browser verification (1c) decides confirmed/rejected/
  inconclusive. `Status.Tests` adds `reflected` / `not_reflected` tallies.

## 1c. Browser verification

Each `JobVerify` job runs on the worker pool's **`browser`** group (its own
concurrency, `BrowserConcurrency`), via `verifyExecutor`
(`internal/scan/verify.go`) calling the real `verification.Verifier`
(`internal/verification/browser.go`) — see
[`browser-verification.md`](browser-verification.md) for the deterministic
signal and the confirmed/rejected/inconclusive decision rule in full.

In orchestration terms: it resolves the job's target exactly like a test job,
re-applies the state-changing safeguard, and — only for a GET/HEAD candidate —
calls the Verifier with the scan's scope (for the browser's `AllowRequest`
gate) and the scan's saved session (`domain.Session.StatePath`, for an
authenticated context). On success it persists the verification report into
`TestCase.Detail`, stores the screenshot/rendered-DOM/browser-log as evidence,
and **correlates** the result into the Finding (`finding.go`'s
`correlateVerification` — see [`finding-correlation.md`](finding-correlation.md)):
the Verdict only ever moves up Pending→Inconclusive/Rejected→Confirmed — a
finding already Confirmed is never downgraded by a later, weaker result at a
correlated site — while every attempt's evidence (this one's AND the
candidate's own request/response) is unioned in regardless, so correlating
never discards raw evidence. `Provenance.VerifiedAt` is stamped on every
completed attempt. A timeout or cancellation leaves the Finding untouched. No
browser configured for the scan → the job is `skipped`, not failed.

| Outcome | Meaning | Job result |
|---------|---------|------------|
| `success` | a response was received (**any** HTTP status — a 404/500 is still a successful execution) | succeeds |
| `error` | could not complete: connection failure, out of scope, invalid request, unresolvable job | transport errors **retry** (queue backoff, up to `MaxAttempts`); out-of-scope/invalid/unresolvable are **permanent** (dead, not retried) |
| `timeout` | exceeded the request timeout | retries |
| `cancelled` | scan cancelled / shutdown interrupted it | context error (jobs are then cancelled or recovered) |
| *(skipped)* | state-changing method and the opt-in is off | succeeds; recorded as status `skipped` |

- **State-changing methods are skipped by default.** POST/PUT/PATCH/DELETE
  endpoints are only executed with `ExecutorConfig.AllowStateChanging`
  (`indago serve -allow-state-changing`), because replaying discovered forms can
  change a live target's state. (A form's `action` is also registered as a GET
  endpoint by discovery; that GET is safe and runs.)
- The `cancelled` result is persisted with a **detached context**, since the job's
  own context is already canceled; `Cancel` therefore returns only after in-flight
  attempts have been recorded.
- If evidence cannot be written the outcome is kept (the request already
  happened; a retry would resend it) and the test case's note says
  `evidence incomplete`.
- On restart, `Recover` marks test cases left `running` by the dead process as
  `cancelled` ("interrupted by restart"); their requeued jobs record fresh attempts.
- Completed-scan status reports `tests` counts (success/error/timeout/cancelled/
  skipped/running), also shown by `indago scan status`.

## 2. Scope is enforced at five points (fail closed)

1. `CreateScan` — project scope must exist, be non-empty, and permit the target
   base URL **and every seed**.
2. `Start` / `Resume` — re-checked (scope may have changed).
3. The discovery **collector** — drops any out-of-scope endpoint/parameter before
   it is persisted or enqueued.
4. Every outbound HTTP request goes through `scopedEngine` — checked *before* it
   is sent. `/robots.txt` outside a path-limited scope is never fetched.
5. **Redirects are followed by the controller, one hop at a time**, re-checking
   scope on each hop, so an in-scope page cannot bounce the crawler out of scope.

The HTTP client passed to the controller **must** be built with
`FollowRedirects=false` (otherwise it would follow redirects itself, bypassing
check 5). `cmd/indago` does this.

The **executor** and discovery share one scope-enforcing engine per scan.

**Browser-network discovery** (`Options.Browser`, `indago serve -browser`) is
scope-gated in two layers: the browser **aborts every out-of-scope request before
it is sent** (page loads, subresources, XHR/fetch, redirect hops — so no
third-party traffic is generated), and the discovery source re-checks each
observation before it reaches the collector, so nothing out of scope is persisted
or enqueued. Aborted requests are reported as `Blocked`, never as observations.
Limitation: WebSocket and service-worker traffic is not intercepted. It is off by
default (it needs Chromium).

## 3. Pause, resume, cancel

All three route to **both** the worker pool and discovery.

| Operation | Worker pool | Discovery | Persisted |
|-----------|-------------|-----------|-----------|
| **Pause** | stops leasing (in-flight jobs finish) | gate closes: no new fetch starts (in-flight fetch finishes and its results are still persisted) | scan `paused` |
| **Resume** | leases again | gate opens | scan `running` |
| **Cancel** | stopped | context canceled — **in-flight requests are interrupted** | queued/active jobs `canceled`; scan `canceled`, discovery `canceled` |

Pause is idempotent. Cancel is idempotent for terminal scans and works on a scan
with no live execution (e.g. one restored after a restart).

## 4. Completion policy

A monitor evaluates each running scan every `PollInterval`:

1. **Refresh** persisted stats (endpoints, parameters, queued/succeeded jobs,
   findings by verdict).
2. **Stop policy** (`continue_all` · `first_confirmed` · `after_n_confirmed` ·
   `pause_and_ask`) is applied to the confirmed-finding count. `pause_and_ask`
   re-asks only when the count *increases*, so resuming does not immediately
   re-pause. Stopping early cancels the scan's remaining jobs.
3. **Complete** when discovery has finished **and** no job is queued, leased, or
   running (`Pending() == 0`). Handlers must enqueue any child jobs *before* the
   parent job completes — that is what makes `Pending() == 0` a reliable
   quiescence test.

A paused or awaiting-auth scan never completes. `COMPLETED` is recorded only
*after* the workers and discovery have fully stopped and (for an early stop) the
remaining jobs are canceled, so a status reader never sees a completed scan with
pending work.

## 5. Persisted scan and discovery state

`Scan.Discovery` is persisted (migration `0002_scan_discovery`):

```
pending ──► running ──► complete          (every source finished)
               └──────► canceled          (scan canceled mid-discovery)
```

`Scan.Stats` is refreshed by the monitor and finalized on completion/cancel.
`Status` (below) reads live from the store, so it is correct at any moment —
including immediately after a restart, before anything is resumed.

## 6. Restart and crash recovery

A restart **never sends traffic on its own.** `indago serve` runs, in order:

1. `Controller.Recover` — jobs left `leased`/`running` by the dead process are
   requeued (no worker can legitimately hold a lease at startup).
2. `Controller.RecoverScans`:
   - `running` scans → **`paused`** ("interrupted by restart"),
   - `canceling` scans → the cancel is completed,
   - `created`, `paused`, `awaiting_auth`, and terminal scans are left alone.
3. The operator resumes with `indago scan resume <id>` (or the UI).

`Resume` on a restored scan rebuilds its execution. If discovery had **not**
finished it runs again, but the collector first **hydrates** its dedup state from
the store, so nothing is re-registered and no duplicate jobs are enqueued; it
simply continues discovering. If discovery had already completed it is **not**
re-run — only the remaining jobs are processed.

Hydration also **reconciles** registrations the interrupted run left half-done.
Registering a target is several separate writes (endpoint → its job → its query
parameters → parameter → injection point → its job), and a shutdown or crash
can land between any two. Hydrate completes each one it finds incomplete: an
endpoint without its endpoint-level job, an endpoint missing any of its own
URL's query parameters, a parameter without an injection point, or an injection
point without a test job (checked against `Queue.Jobs`). Without this, the
resumed crawl would rediscover such an endpoint, hit the dedup check, and never
register or test what was missing, and the scan would still **complete**.
That was the root cause of the intermittent
`TestE2E_RestartRecoversInterruptedVerification` failure. See
`TestRestartTestsInjectionPointWhoseJobWasLostToShutdown` and the
`TestCollectorHydrate*` tests.

Job execution is **at-least-once**: a job interrupted mid-handler is re-run
from the start after `Recover`, so its side effects can repeat. For a
reflection job, that means re-enqueueing its candidate children. Finding
correlation absorbs the repeats into the same `Finding` (no duplicate rows),
but `Finding.Detail.occurrences` counts every correlated attempt, and a crash-
interrupted attempt still counts against the job's `MaxAttempts`.

`Controller.Shutdown` (graceful stop) cancels and joins every goroutine but
leaves persisted state untouched, so a graceful stop is recovered exactly like a
crash.

## 7. Status

`Controller.Status` backs the web UI, the CLI, and `GET /api/scans/{id}/status`,
so all three always agree:

```jsonc
{
  "scan":      { "state": "running", "discovery": "running", ... },
  "running":   true,                       // a live execution exists in this process
  "discovery": { "state": "running", "endpoints": 13, "parameters": 4,
                 "injection_points": 4,
                 "endpoints_by_source": { "crawler": 8, "form": 3, "robots": 1, "user_provided": 1 } },
  "jobs":      { "Queued": 6, "Running": 4, "Succeeded": 3, ... },
  "findings":  { "confirmed": 0, "rejected": 0, "inconclusive": 0, "pending": 0 }
}
```

## 8. Web API and CLI

| Action | HTTP | CLI |
|--------|------|-----|
| create project | `POST /api/projects` | `indago project create NAME` |
| add target | `POST /api/projects/{id}/targets` | `indago target add -project ID -name N -url URL` |
| set scope | `PUT /api/projects/{id}/scope` | `indago scope set -project ID -include a,b …` |
| create scan | `POST /api/scans` | `indago scan create -project ID -target ID …` |
| … with an existing session | `POST /api/scans` + `"auth_mode":"existing","auth_state_path":"/abs/state.json"` | `indago scan create … -auth-state FILE` (`-auth existing` implied; a relative path is made absolute by the CLI) |
| start / pause / resume / cancel | `POST /api/scans/{id}/{action}` | `indago scan start\|pause\|resume\|cancel ID` |
| status | `GET /api/scans/{id}/status` | `indago scan status ID [-json]` |

The CLI is a thin client over the running server's API (so only the server opens
the SQLite file); scan IDs may be given as a unique prefix.

### Protecting the control plane

The API can start scans, so it is guarded against a malicious web page the
operator visits:

- **CSRF**: every state-changing request needs the `X-Indago-Client` header
  (browsers cannot send a custom header cross-origin without a CORS preflight,
  which the server never approves), and an `Origin` header, if present, must match
  the `Host`. The bundled UI and the CLI send it.
- **DNS rebinding**: when bound to a specific address, the `Host` header must be
  loopback or the bound host.
- The API has **no authentication** (single local user). `indago serve` warns when
  bound to a non-loopback address; restrict network access in that case.

## 9. Locking rules (for maintainers)

- `Controller.mu` guards the running-execution map and the closed flag. It is
  **never held while waiting for a goroutine** — `Cancel`/`Shutdown` take the
  execution out of the map, release the lock, then wait. This is what stops the
  completion monitor (which also takes `mu`) from deadlocking against them.
- `Controller.scanMu` serializes read-modify-write of scan rows (`mutate`), so the
  monitor's stats refresh can never overwrite a concurrent state change with stale
  data. Lock order: `mu` → `scanMu`.
- Completion takes ownership (state check + map removal in one critical section)
  before tearing the execution down.

## 10. Known limitations

Reviewed at the Reliability & Release Gate. Three earlier entries were
already fixed in code and have been removed: live discovery concurrency
(`Reconfigure` → `discovery.Manager.SetConcurrency`), per-parameter mutation
(the reflection step), and the in-memory `pause_and_ask` marker (now
`ScanStats.AskedAtConfirmed`, persisted).

- **At-least-once job execution (accepted).** Per-job progress inside a handler
  is not persisted; a crashed job is re-run from the start (§6). Outcomes
  stay correct: findings correlate, evidence is unioned, and verdicts only move
  up. The costs are a few repeated benign requests after a crash, and an
  `occurrences` count that includes repeats.
- **Crash-interrupted attempts count toward `MaxAttempts` (accepted).** A job
  interrupted N times and then failing transiently can go `dead` sooner than
  one that was never interrupted. Its TestCases record the interruptions
  (`cancelled`, "interrupted by restart").
- **WebSocket and service-worker traffic is not intercepted** by browser
  discovery's scope gate (§2). This is deferred, and not a production blocker:
  `-browser` is opt-in, and every observation is still re-checked against scope
  before anything is persisted.

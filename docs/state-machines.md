# Indago — State Machines

Lifecycle states and their legal transitions. The transition tables in
[`internal/domain/state.go`](../internal/domain/state.go) are the single source
of truth; every diagram here mirrors that code. Transitions are validated via
`CanTransitionTo`, so illegal states cannot be persisted.

---

## 1. Scan lifecycle

A scan is one hunting run. Pause/resume/cancel and session-expiry handling are
all modeled here.

```
                 ┌─────────┐
                 │ created │
                 └────┬────┘
                      │ start
                      ▼
      ┌──────────► running ◄───────────┐
      │ resume      │  │  │  resume     │
      │             │  │  └─────────────┤ (re-auth OK)
  ┌───┴────┐ pause  │  │                │
  │ paused │◄───────┘  │ session expiry │
  └───┬────┘           ▼                │
      │          ┌──────────────┐       │
      │          │ awaiting_auth├───────┘
      │          └──────┬───────┘
      │ cancel          │ cancel
      ▼                 ▼
  ┌───────────┐   (also from running/paused/awaiting_auth)
  │ canceling │
  └─────┬─────┘
        ▼
   ┌──────────┐     running ──► completed   (work drained)
   │ canceled │     running/paused/awaiting_auth/canceling ──► failed
   └──────────┘

Terminal: canceled, completed, failed
```

Legal transitions:

| From | To |
|------|----|
| `created` | `running`, `canceled`, `failed` |
| `running` | `paused`, `awaiting_auth`, `canceling`, `completed`, `failed` |
| `paused` | `running`, `canceling`, `canceled`, `failed` |
| `awaiting_auth` | `running`, `paused`, `canceling`, `canceled`, `failed` |
| `canceling` | `canceled`, `failed` |
| `canceled` / `completed` / `failed` | — (terminal) |

Notes:

- **Pause/resume**: `running ⇄ paused`. Queued work is preserved; workers stop
  leasing and resume on `running`.
- **Session expiry**: `running → awaiting_auth`. The scanner does **not**
  silently re-authenticate; after the operator re-auths, `awaiting_auth →
  running`.
- **Cancel** moves through `canceling` (stop workers, cancel jobs) to `canceled`.

---

## 2. Job (TestJob) lifecycle

Jobs live in the persistent queue. This machine encodes leasing, retries, and
**restart/crash recovery**.

```
          enqueue
             │
             ▼
        ┌─────────┐   lease    ┌─────────┐   start*   ┌─────────┐
        │ queued  ├───────────►│ leased  ├───────────►│ running │
        └──┬───▲──┘            └────┬──▲──┘            └───┬──┬──┘
           │   │ retry (backoff)    │  │ recover           │  │
           │   └────────────────────┼──┼───────────────────┘  │ success
           │                        │  │ recover              ▼
    cancel │                        │  │              ┌───────────┐
           │                        │  │              │ succeeded │
           ▼                        │  │              └───────────┘
      ┌──────────┐                  │  │ cancel         fail (transient)
      │ canceled │◄─────────────────┘  │                      │
      └──────────┘                     │                      ▼
                                       │                 ┌─────────┐
                                       └─ cancel ───────►│ failed  │
                                                         └────┬────┘
                                              retry ◄─────────┤
                                            (→ queued)        │ retries exhausted
                                                              ▼
                                                        ┌──────────┐
                                                        │   dead   │
                                                        └──────────┘

Terminal: succeeded, canceled, dead
Active (reclaimed by recovery): leased, running
```

\* In the current queue implementation, `Lease` claims a job directly into
`running` (the `leased` state remains legal for a future reserve-then-start
dispatcher). Both `leased` and `running` are **active** and are requeued by
recovery.

Legal transitions:

| From | To |
|------|----|
| `queued` | `leased`, `canceled` |
| `leased` | `running`, `queued` (recovery), `canceled` |
| `running` | `succeeded`, `failed`, `queued` (recovery), `canceled` |
| `failed` | `queued` (retry), `dead` (retries exhausted) |
| `succeeded` / `canceled` / `dead` | — (terminal) |

Recovery:

- **`Queue.Recover` (startup):** requeue *all* active jobs → `queued`. No worker
  legitimately holds a lease at process start.
- **`Queue.ReapExpired(now)` (runtime):** requeue active jobs whose lease expired
  (dead-worker detection).
- **Retry backoff:** capped exponential (base 2s, cap 5m) on transient `failed`
  → `queued`.

---

## 3. Auth session lifecycle

One session per scan, reused. Expiry pauses the scan for re-auth.

```
         ┌──────┐
         │ none │
         └──┬─┬─┘
   import/  │ └──────────────┐ begin auth
   existing │                ▼
   (active) │        ┌────────────────┐
            │        │ authenticating │
            │        └───────┬──┬─────┘
            │        success │  │ failure
            ▼                ▼  ▼
         ┌────────┐      ┌────────┐
         │ active │◄─────┤ (succ) │
         └───┬──┬─┘      └────────┘
      expiry │  │ failure
             ▼  ▼
        ┌─────────┐  re-auth   ┌────────┐
        │ expired ├───────────►│ (auth) │
        └────┬────┘            └────────┘
             │ refreshed
             ▼
          active

       ┌────────┐ retry auth
       │ failed ├──────────► authenticating
       └────────┘
```

Legal transitions:

| From | To |
|------|----|
| `none` | `authenticating`, `active` (imported/existing material) |
| `authenticating` | `active`, `failed` |
| `active` | `expired`, `failed` |
| `expired` | `authenticating`, `active`, `failed` |
| `failed` | `authenticating` |

Phase 0 implements only the **anonymous** authenticator (goes straight to
`active` and never expires).

---

## 4. Finding verdict

Not a transition table (it is a value enum), but the intended lifecycle:

```
   detection                      verification
   ──────────►  pending  ──────────────────────►  confirmed   (terminal)
   (candidate)      │                         └──►  rejected   (terminal)
                    └─────────────────────────┴──►  inconclusive
                                                      │ re-verify
                                                      ▼
                                              confirmed / rejected
```

- A reflection alone ⇒ `pending`.
- `confirmed` / `rejected` are terminal (`Verdict.IsTerminal()`).
- `inconclusive` may be re-verified later.

---

## 5. Where these are enforced

- **Domain:** `CanTransitionTo` guards (scan/job/session).
- **Queue:** job transitions happen inside guarded SQL updates / locked memory
  ops (no double-lease, atomic claim).
- **Controller:** `setState` validates every scan transition before persisting.

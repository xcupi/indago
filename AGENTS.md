# AGENTS.md

Operating guide for humans and AI agents working in the **Indago** repository.
Read this before making changes.

---

## 1. What Indago is

Indago is a **local-first, single-user web application security hunting
platform**. It helps an authorized operator discover and *verify* web
vulnerabilities against targets **they are explicitly permitted to test**.

- **Phase 1 scope (product):** Reflected XSS detection and verification.
- **Current phase (code):** Reflected XSS — baseline, **reflection detection**, **context analysis**, **candidate planning**, **candidate execution**, **browser verification** (a reflected candidate is confirmed/rejected/inconclusive only by a real, deterministic browser signal — never by an LLM), **finding correlation & reporting** (repeated results at the same site collapse into one `Finding` without discarding evidence; JSON + Markdown output), and **end-to-end validation/hardening** of that whole pipeline against a local test corpus (see `docs/e2e-validation.md`) — no new detection features, only fixes the corpus's real-browser tests actually caught.
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

## 3. Current boundary — DO NOT IMPLEMENT YET

The platform is built incrementally. The following are explicitly **out of scope
right now** and must remain stubs/interfaces (job handlers are no-ops):

- ❌ Any verdict made by an LLM. Verification's Confirmed/Rejected/Inconclusive
  decision is a pure function of a deterministic browser signal
  (`internal/verification/browser.go:decide`) — AI remains advisory-only
  everywhere, per §2.5.
- ❌ DOM XSS. Verification replays the SAME marker/candidate the candidate step
  already sent; it does not crawl the rendered DOM for new sinks or
  client-side-only inputs.
- ❌ Automated exploitation / weaponized payloads. Candidate execution AND
  verification only ever send the small, canonical, benign-marker breakouts the
  planner chose — no payload obfuscation, no evasion variants, no exploit
  payload libraries, no simulated user activation (e.g. clicking a
  `javascript:` link) to force execution. State-changing methods still require
  the explicit opt-in, for both candidate execution and verification.
- ❌ POST/body-carrying candidates are not browser-verified (navigation carries
  no request body); those findings stay Pending. Stored XSS/additional engines
  remain designed-for, not built.

Implemented so far (infrastructure and **discovery**):

- ✅ Domain models (generic, not XSS-specific)
- ✅ Persistence layer (SQLite + in-memory), migrations
- ✅ Persistent job queue + concurrent worker pool
- ✅ HTTP engine (neutral transport; no scope checks inside it)
- ✅ Browser manager (Chromium/Playwright; neutral automation)
- ✅ Discovery (seeds, crawl, forms, sitemap, robots, wordlists, params,
  network observation) — real requests to **in-scope** targets only
- ✅ Scan controller: wires discovery + queue + workers, pause/resume/cancel,
  completion policy, restart recovery (see `docs/scan-orchestration.md`)
- ✅ Test job executor: runs each `JobTest` through the scope-enforcing engine and
  persists outcome (success/error/timeout/cancelled) + request/response evidence.
  Endpoint-level jobs send a baseline; injection-point jobs run the **Reflected
  XSS reflection step** — baseline + a mutated request carrying a unique,
  deterministic marker in the selected parameter only — and record reflection,
  locations, surrounding context, the marker's encoding/transformation, and the
  derived candidate plan into `TestCase.Detail`. The reflection job then enqueues
  one child `JobTest` per planned candidate; each child sends that single
  benign-marker breakout into the same injection point (other parameters
  unchanged), re-runs reflection analysis, and records reflected/not_reflected +
  context + evidence. No verdict. State-changing methods need the explicit opt-in.
- ✅ Context analyzer (`internal/detection/context*.go`): a **pure** classifier that
  labels each reflection site (HTML text/attribute/tag/comment, JS string/code/
  comment/regex, URL, CSS, unknown/mixed) by driving a real HTML tokenizer to the
  site's byte offset, with confidence + reason. No network/browser/LLM/payloads;
  a test enforces its imports stay pure. See `docs/reflection-context.md`.
- ✅ Candidate planner (`internal/detection/candidate.go`): a **pure** layer that
  turns each context-classified site into an ordered, deduplicated set of
  benign-marker breakout *candidates* (per category: HTML text/attribute, JS
  string/code, URL, CSS, unknown/mixed), transformation-aware (deprioritizing —
  never dropping — characters the site encodes/strips), each with provenance,
  rationale, and a dedup key. Data only: nothing is sent and no verdict is made.
  Serializable into `TestCase.Detail` and extensible to future advisory (e.g.
  LLM) sources without touching the domain model. A test enforces its imports
  stay pure. See `docs/reflection-candidates.md`.
- ✅ Candidate executor (`internal/scan/candidate.go`): the reflection job
  enqueues one child `JobTest` per planned candidate (priority = candidate
  priority, so the queue drains them in the plan's deterministic order; dedup is
  inherited from the plan, so one request per unique candidate). Each child sends
  its single benign-marker breakout into the injection point through the
  scope-enforcing engine, keeping all other parameters at their observed values
  (GET query, POST form, POST JSON), re-runs reflection analysis on the response,
  and persists the result (reflected/not_reflected/error/timeout/cancelled) with
  provenance, source (builtin/llm), and baseline+candidate evidence. Candidate
  jobs do not re-plan, so execution never recurses. A candidate that reflects
  via GET/HEAD creates a **Pending `Finding`** and enqueues a `JobVerify` job
  (POST/body-carrying reflections stay Pending — browser navigation has no
  body).
- ✅ Browser verification (`internal/verification/browser.go` +
  `internal/scan/verify.go`): the real `Verifier`. It replays the EXACT
  candidate into its injection point in a real, scope-gated, optionally
  authenticated (`domain.Session.StatePath`) browser context (reusing
  `internal/browser`'s Manager — the same one discovery uses), waits for the
  page's own `load` event (no arbitrary sleeps), and observes whether the
  marker reaches an executable position. The signal is deterministic, not a
  payload: every built-in candidate is, at its target position, nothing but
  the bare marker token used as a JS expression, so a browser that evaluates it
  throws `ReferenceError: <token> is not defined` — observed via the browser's
  own uncaught-exception/console-error channels, never anything the candidate
  or verifier causes to happen (no alert/cookie/network call is ever part of a
  candidate). `Confirmed` only when that signal names the exact marker —
  attributed strictly to THIS navigation (observations are baselined before
  navigating, so no pre-existing/unrelated page activity can be mistaken for
  it); `Rejected` when the candidate reflected but no signal appeared;
  `Inconclusive` when the marker could not even be re-observed. Correlates the
  result into the `Finding` (see next bullet) and persists screenshot/
  rendered-DOM/browser-log evidence. No LLM, no DOM XSS, no simulated
  clicks/activation. See `docs/browser-verification.md`.
- ✅ Finding correlation (`internal/scan/finding.go`): a candidate that
  reflects is correlated into a `Finding` by injection point + candidate
  category + context (`findingDedupKey`) — the same underlying site reflecting
  via several candidates absorbs into ONE finding, never a near-duplicate row,
  while every distinct candidate and contributing TestCase ID is still
  recorded (`Finding.Detail`, an opaque JSON blob mirroring `TestCase.Detail`).
  A verification result only ever moves the Verdict UP the
  pending→inconclusive/rejected→confirmed lattice — once Confirmed, a later,
  weaker result at a correlated site never downgrades it — while evidence
  (this attempt's browser evidence AND the original candidate's own request/
  response evidence) is unioned in every time, so correlating never discards
  raw evidence. Full provenance (scan/endpoint/parameter/injection point/
  discovery source/candidate source) is carried on every `Finding`. See
  `docs/finding-correlation.md`.
- ✅ Reporting (`internal/report`): `JSONGenerator` and `MarkdownGenerator`,
  pure serialization of findings — no detection/verification dependency, no
  LLM, deterministic output (sorted findings, sorted map-keyed breakdowns).
- ✅ End-to-end validation/hardening (see `docs/e2e-validation.md`): a local
  test corpus and real-Chromium tests exercising the full pipeline (discovery
  → … → report), which found and fixed real gaps rather than adding features:
  **session expiration** was fully designed (states, `Authenticator.Validate`,
  `ScanAwaitingAuth`) but never wired into the monitor — it now is, and
  **`auth.Existing`** (importing session material saved by a prior login) is
  implemented so an authenticated scan can be tested at all; the **HTTP-level**
  executor never carried the scan's session cookies (only browser verification
  did) — `scopedEngine` now does too; a candidate reflecting on a **POST/JSON**
  endpoint created no `Finding` at all, contradicting the documented "stays
  pending" behavior — fixed to always correlate one, just never enqueuing a
  (body-less) browser-verify job for it; the browser worker group could be
  sized to **zero**, silently orphaning every `JobVerify` job forever even
  though "no browser configured" is a supported, tested configuration — now
  floored at 1; and **Finding correlation** (`upsertPendingFinding`/
  `correlateVerification`) read-then-wrote without a lock, so concurrent
  candidates at the same site could race into a duplicate `Finding` or a lost
  evidence update — now serialized per scan.
- ✅ Reliability & release gate (see `docs/e2e-validation.md`): no new
  detection features. Discovery's restart hydration now **reconciles**
  half-finished registrations (endpoint/parameter/injection point persisted
  but its job not enqueued), which was the root cause of the
  `TestE2E_RestartRecoversInterruptedVerification` flake, via the new
  `Queue.Jobs`. Two Playwright races are fixed: the library is upgraded to
  `playwright-go v0.6000.0` (driver 1.60.0), and closing a context/browser
  waits for any in-flight creation. `auth.Existing` is wired end to end: CLI
  `-auth-state`, API `auth_state_path`, create-time validation (`ErrAuth` →
  400), session reuse by HTTP + browser discovery + verification, and the
  monitor pausing to `awaiting_auth` when the material disappears. Stress
  tests live in `internal/scan/stress_test.go`. When changing restart, queue,
  or browser lifecycle code, keep `assertScanIntegrity`'s invariants
  passing under `-race -count=20`.
- ⏳ Stubs: detection engines (non-XSS classes), Password/Interactive/MFA auth
  modes, AI providers

**The dividing line:** transport, browser, discovery, orchestration, and the
full Reflected XSS pipeline (reflect → context → plan → execute candidates →
verify) are implemented end to end, with a real verdict (Confirmed/Rejected/
Inconclusive) for Reflected XSS specifically. Every OTHER vulnerability class
(Stored XSS, DOM XSS) is still an interface with a stub returning
`ErrNotImplemented` — Reflected XSS is the one class built all the way through.

**Scope is enforced outside the transport modules.** `httpengine` and `browser`
perform no scope checks; the scan controller wraps the HTTP engine in a
scope-enforcing engine (every request and redirect hop) and the discovery
collector re-checks every result. The browser aborts out-of-scope requests
itself (`AllowRequest`). Never hand an unwrapped engine to code that
follows attacker-influenced URLs.

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
  httpengine/          HTTP engine (implemented)
  browser/             Browser manager — Chromium/Playwright (implemented)
  discovery/           Discovery source abstraction + registry (implemented)
  detection/           Reflected XSS: reflection/context/candidate planner
                       (implemented, pure); other vuln classes are stubs
  verification/        Verification interface + real browser Verifier
                       (implemented for Reflected XSS)
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

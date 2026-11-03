# HANDOFF — IDOR / access-control engine (family A vertical slice)

Run ID: ps-idor-20261107
Base SHA: 72e8aa3e74ec85ed0cd4ab7c05f241f866d133a3
Branch / worktree: fix/ps-idor at `/home/udalah/.hermes/cache/scratch/indago-ps-idor-worktree`
Outcome: **ready_for_qa**

No commit, push, PR or merge was made. AGENTS.md was NOT modified.

---

## 1. Design

### Data flow

```
discovery (authenticated session)
  └─ endpoints + parameters (+ injection points)
        │
        │ controller: one bounded pass when the ordinary queue goes quiet,
        │ after the combined and DOM-XSS passes (execution.go)
        ▼
  enqueueIDORProbes  (only if ScanConfig.EnableIDOR)
        │  one JobIDOR per GET/HEAD query/path object-identifier injection point
        ▼
  idorExecutor.Handle  (HTTP worker group — no special-casing in the worker)
        ├─ 1. identity baseline, once per scan, persisted as a TestCase
        │       GET /my-account | /profile | /account | /me on the endpoint origin
        │       → identity fields + request/response evidence
        ├─ 2. request A: caller's own observed identifier → evidence
        ├─ 3. candidates: supplied → numeric neighbours → observed ids (≤ 5)
        ├─ 4. request B × N (GET/HEAD only) → idor.Decide(...)
        └─ 5. Confirmed → Finding (VulnClass "idor"); otherwise TestCase.Detail only
```

All requests go through the scan's existing `scopedEngine`: fail-closed host/path
scope on every request and redirect hop, the scan's single rate limiter, and the
scan's saved session cookies. No new transport, no new dependency.

### Identity baseline (who am I)

* The operator supplies ONE identity: the scan's saved storage state. No second
  (victim) session is created, imported or guessed.
* The engine establishes the caller from the target itself by fetching a bounded
  set of account paths on the endpoint's own origin (`/my-account`, `/profile`,
  `/account`, `/me`) with the scan's session, and extracting label-based
  identity fields: JSON keys (`username`, `user_name`, `login`, `email`,
  `user_id`, `uid`, `account_id`, …; a bare `id` only inside a
  user/account/profile object), HTML `<input name=… value=…>`, and labelled
  text (`Username:`, `Your username is`, `Email:`, `User ID:`).
* Placeholder values, identities inside arrays (a user listing is not the page's
  principal) and form tokens (`csrf_id`) are ignored.
* The baseline — positive OR negative — is persisted once as a `TestCase`
  (note prefix `idor identity baseline`) with request/response evidence, and is
  read back by later probes, so a restart does not re-probe and every verdict
  chain carries the "who am I" evidence.
* No identity → every probe is SKIPPED with a stated reason. Nothing is ever
  Confirmed without a caller identity to compare against.

### Candidate derivation (bounded, deterministic)

`idor.DeriveCandidates`, order fixed, hard cap `idor.MaxCandidates = 5`:

1. operator-supplied identifiers (`-idor-candidates` / `idor_candidates`), given
   order — the only way to test an opaque identifier or a username lab's named
   victim. Max 10, identifier-shaped, validated at scan creation.
2. numeric neighbours of the caller's own numeric id: +1, −1, +2, −2, +3
   (dropped at ≤ 0).
3. identifier-shaped values already observed in other in-scope parameters by
   this scan's authenticated discovery.

An opaque identifier with no supplied candidate produces ZERO candidates and a
stated skip reason (`…unpredictable, so guessing is not attempted`). No
wordlist, no enumeration, no jitter.

### Verdict table (acceptance bar)

| Fixture shape | Outcome |
|---|---|
| 2xx body names a different principal in a field the caller also carries | **Confirmed** (with the foreign field recorded) |
| 2xx body identifies the caller anywhere (incl. pages also listing others) | Rejected |
| 2xx body has identity fields, none comparable to the caller | Inconclusive |
| 2xx body with no identity fields / plain content | Inconclusive |
| login page (password form, no identity) after a redirect | Inconclusive |
| 401 / 403 | Rejected (object protected) |
| other 4xx / 5xx | Inconclusive |
| empty body | Inconclusive |

Confirmed also requires request A (own object) and request B (foreign object)
to be persisted as evidence, and the identifier to be visibly carried in the
focused request parameter. Status codes, lengths and redirects alone never
Confirm. A Finding is created only for Confirmed; Rejected/Inconclusive/Skipped
stay in `TestCase.Detail` (no report padding, no false "clean" rows).

A page that mentions the caller anywhere is Rejected even if it also lists
another principal (e.g. a comment author), so a listing page cannot produce a
false Confirmed.

### Read-only guarantees

GET and HEAD only. Body-carrying methods are skipped with a stated reason even
when the scan's state-changing opt-in is enabled. Only query/path object-id
parameters are probed; form/JSON identifiers are out of this slice. No writes,
no exploitation, no exfiltration, no LLM input anywhere.

---

## 2. Changes

New:
* `internal/idor/idor.go` — pure core: identity extraction, candidate
  derivation, decision rules (`Decide`), object-id parameter predicate.
* `internal/idor/idor_test.go` — pure fixtures incl. all negative controls.
* `internal/scan/idor.go` — `idorExecutor` (JobIDOR handler), identity baseline,
  evidence persistence, Finding correlation, `enqueueIDORProbes`.
* `internal/scan/idor_test.go` — real-httptest differential, negative controls,
  evidence assertions, probe-pass selection, opt-in gate, worker routing.
* `docs/idor.md` — capability + limits record.

Wiring (minimal):
* `internal/domain/enums.go` — `VulnIDOR = "idor"`.
* `internal/domain/state.go` — `JobIDOR = "idor"`.
* `internal/domain/core.go` — `ScanConfig.EnableIDOR`, `IDORCandidates`.
* `internal/scan/handlers.go` — phase0 no-op entry + real handler; shares
  `findingsMu`.
* `internal/scan/controller.go` — `poolConfig` routes JobIDOR to the HTTP
  group; `CreateScanParams`/`CreateScan` carry + validate the opt-in and the
  candidate list; anonymous + `enable_idor` is rejected fail-closed; pass
  candidates to the handler.
* `internal/scan/execution.go` — one-time `idorPassDone` step after the DOM
  pass; `defaultHandlers` gains the candidate list.
* `internal/web/scans.go` — `enable_idor` / `idor_candidates` API fields.
* `cmd/indago/cli.go` — `-idor`, `-idor-candidates`.
* Two DOM-XSS test call sites updated for the widened `defaultHandlers`
  signature (no DOM/XSS behavior changed).

---

## 3. RED / GREEN evidence

Logs: `/home/udalah/.hermes/cache/scratch/indago-ps-results/idor/worker/`

| Step | Command | Result | Log |
|---|---|---|---|
| RED 1 (pure) | `go test ./internal/idor` | exit 1 — behavioral assertion failures (stub, compiles) | `red-01-idor-core.log` |
| GREEN 1 | `go test ./internal/idor` | exit 0 | `green-01b-idor-core.log` |
| RED 2 (scan) | `go test ./internal/scan -run 'TestIDOR\|TestEnqueueIDOR'` | exit 1 — no TestCase/jobs produced (behavioral) | `red-02-idor-scan.log` |
| GREEN 2 | same | exit 0 (8 tests) | `green-03-idor-scan.log` |
| GREEN wiring | focused `-run` incl. `TestJobIDORIsWiredToTheHTTPGroup` | exit 0 | `green-04-wiring.log` |
| GREEN packages | `go test -count=1 ./internal/scan ./cmd/indago` | exit 0 (22.6s / 1.0s) | `green-05-scan-cli-full.log` |
| GREEN evidence | focused IDOR tests after evidence linkage | exit 0 | `green-06-evidence.log` |
| Race (intermediate) | `go test -race -p 1 -count=1 ./internal/idor ./internal/scan` | exit 0 | `race-01-idor-scan.log` |
| **Race (final)** | `go test -race -p 1 -count=1 ./internal/idor ./internal/scan` | **exit 0** (idor 1.0s, scan 45.1s) | `race-02-final.log` |
| gofmt | `gofmt -l .` | no output outside third_party | — |
| vet | `go vet ./...` | exit 0 | — |
| full suite | `go test -count=1 ./...` | all packages pass except `internal/browser` `TestIntegrationDefaultConfigRendererIsSandboxed` | `green-07-all-packages.log` |
| browser env gate | `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -count=1 ./internal/browser` | exit 0 (191s). The bundled headless shell cannot use Chromium's sandbox on this host; the documented system-Chrome path works. The base commit passes the same test with the system Chrome, and this slice does not touch `internal/browser`. | — |

Dependency packages also green: `./internal/domain`, `./internal/web` (31.7s),
`./internal/report`.

---

## 4. Remaining gates / not done

1. **AGENTS.md is unchanged and still says additional engines are not built.**
   The product boundary must be raised to the operator before this ships as an
   approved capability. Exact wording to raise is in §5.
2. **No live lab run was performed** (per the brief, the coordinator validates
   the PortSwigger access-control labs). Unit/httptest behavior only.
3. **No browser-tagged test roots were added** — the engine is raw HTTP only,
   so `scripts/ci-browser-check.py` and `deploy/ci_runtime_test.go` needed no
   new root. (They must be updated only if a browser-tagged IDOR test is added
   later.)
4. Full hosted CI was not run. `make check` was approximated by `gofmt -l .`,
   `go vet ./...`, the focused race gate and the package tests above.
5. Known limits (also in `docs/idor.md`):
   * family B (role/URL/method/Referer/multi-step) not implemented;
   * POST/JSON object identifiers skipped (read-only slice);
   * identity extraction is label-based — a target that exposes no labelled
     identity field yields a stated skip, not a verdict;
   * intermediate 3xx bodies are not analysed (the scope engine follows
     redirects), so a leak visible only in a redirect body is missed;
   * opaque identifiers need operator-supplied candidates.
6. The API field additions mean a web-created scan can enable the engine too;
   no dashboard control was added (explicitly minimal wiring).

---

## 5. AGENTS.md wording the coordinator must raise to the operator

Do not edit AGENTS.md in this worktree. Raise these exact passages:

**(a) The "additional engines" line (line 29):**
> `- **Future (designed for, not built):** Stored XSS, additional engines.`

**(b) The §3 summary line (line 138):**
> `  Stored XSS/additional engines remain designed-for, not built.`

**(c) The §3 stub bullet (lines 348–350):**
> `- ⏳ Stubs: detection engines for non-Reflected-XSS, non-DOM-XSS vulnerability`
> `  classes (Stored XSS), and every DOM-XSS source/sink combination beyond the`
> `  Phase-2 first slice.`

**(d) The §3 "dividing line" paragraph (lines 352–357), which currently names
only Reflected XSS and DOM XSS as implemented engines:**
> `**The dividing line:** transport, browser, discovery, orchestration, and the`
> `full Reflected XSS pipeline (reflect → context → plan → execute candidates →`
> `verify) are implemented end to end, with a real verdict (Confirmed/Rejected/`
> `Inconclusive) for Reflected XSS specifically. DOM XSS has a real seven-source,`
> `bounded HTML-sink engine with deterministic browser verification. P2.3 authorizes …`

Proposed operator-approved replacement (for the coordinator to apply, not this
worker): add an implemented bullet for a bounded **IDOR / object-level
authorization engine (family A only)** under §3 "Implemented so far", state
that family B (function/role-level) and BFLA are NOT implemented, and note the
read-only slice (GET/HEAD, bounded candidate set, operator-supplied identifiers
for opaque values, no victim session). The line-29 "additional engines" and
line-138 "designed-for, not built" wording must then exclude IDOR explicitly.

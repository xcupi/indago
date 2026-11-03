# IDOR / broken object-level authorization engine

Status: **first slice implemented, pending operator approval of the product-boundary
change in AGENTS.md.** Family A only (object-level). Function/role-level access
control (family B) is not implemented.

This document is the truthful capability and limit record for the engine. It
does not itself change AGENTS.md, which is the protected product-boundary file.

---

## 1. What the engine does

For an authenticated scan that explicitly opts in, Indago tests whether an
object identifier in a request can be changed to select **another principal's
object**. It:

1. establishes **who the caller is** from the target itself (the account page
   served with the scan's own session) and records that as a baseline fact with
   request/response evidence;
2. for each discovered GET/HEAD parameter that plausibly selects an object,
   sends request **A** with the caller's own observed identifier;
3. sends a small, hard-capped set of request **B**\ s with other identifiers;
4. compares the **identity fields** in each response against the caller's
   identity and confirms only on a positive mismatch.

Everything goes through the scan's existing scope-enforcing engine
(`internal/scan/scoped.go`): scope is re-checked on every request and redirect
hop, the scan's single rate limiter paces every request, and the scan's saved
session cookies are carried exactly as for every other engine. It is dispatched
to the ordinary **HTTP worker group** — no special case in the worker.

## 2. Data flow

```
discovery (authenticated)                      controller, once per execution,
  └─ endpoints + parameters                     after the XSS/DOM-XSS passes
        │                                              │
        │  opt-in: ScanConfig.EnableIDOR               │ enqueueIDORProbes
        ▼                                              ▼
   JobIDOR (one per object-identifier injection point)
        │
        ├─ identity baseline (once per scan, persisted as a TestCase)
        │     GET /my-account | /profile | /account | /me  on the endpoint origin
        │     → extracted identity fields + request/response evidence
        │
        ├─ request A: own identifier, observed value   → evidence (baseline)
        │
        ├─ candidate derivation (bounded, deterministic)
        │     operator-supplied → numeric neighbours → observed identifiers
        │
        ├─ request B × N (N ≤ 5): each → idor.Decide(...)
        │     → request/response evidence per attempt
        │
        └─ Confirmed → Finding (VulnClass "idor")
              Rejected / Inconclusive / Skipped → TestCase.Detail only
```

### Identity baseline

* One authenticated identity only: the scan's saved storage state. The engine
  never invents or logs into a second (victim) session.
* The caller identity is extracted from the target's own account page, trying a
  bounded set of common paths (`/my-account`, `/profile`, `/account`, `/me`) on
  the origin of the endpoint being tested. No wordlist, no cross-host lookup.
* Extraction is label-based and deterministic: JSON keys (`username`,
  `user_name`, `email`, `user_id`, `uid`, `account_id`, … and a bare `id` only
  inside a user/account/profile object), HTML input `name`/`value` pairs, and
  labelled text (`Username: …`, `Your username is …`, `Email: …`, `User ID: …`).
  Placeholder values, identities inside arrays (a listing of users is not the
  page's own principal) and form tokens are ignored.
* The baseline is persisted once as a `TestCase` (note prefix
  `idor identity baseline`) with its own request/response evidence, because
  "who am I" is a fact the report must be able to show. A negative baseline is
  persisted too, so a restarted scan does not re-probe.
* If no identity can be established, every probe is **skipped** with a stated
  reason. Nothing is Confirmed without a caller identity to compare against.

### Candidate derivation (bounded, never brute force)

`idor.DeriveCandidates`, in this order, capped at `idor.MaxCandidates` (5):

1. **operator-supplied** identifiers (`-idor-candidates` / `idor_candidates`),
   in the given order — the only way to test an opaque identifier. Max 10,
   validated at scan creation. The tool never invents these; the operator names
   them (e.g. the victim username an authorized lab brief states).
2. **numeric neighbours** of the caller's own numeric identifier (`+1`, `−1`,
   `+2`, `−2`, `+3`), dropped at `≤ 0`.
3. **observed identifiers** — identifier-shaped values discovery already saw in
   other in-scope parameters with the authenticated session.

An opaque identifier (UUID, long random slug) with no supplied candidate yields
**no candidates at all** and a stated skip reason. There is no enumeration,
no wordlist and no timing jitter.

### Verdict rules (`idor.Decide`)

Confirmed requires a **positive identity mismatch** in the response body. Status
codes, body lengths and redirects alone are never enough; the identifier must
also visibly be present in the request (the engine sends it in the focused
parameter only).

| Response shape | Outcome | Reason class |
|---|---|---|
| 2xx body identifies a different principal in a field the caller also carries | **Confirmed** | foreign username/email/user-id mismatch |
| 2xx body identifies the caller (any comparable field matches) | Rejected | same principal, including pages that also list other users |
| 2xx body has identity fields but none comparable to the caller | Inconclusive | cannot attribute ownership |
| 2xx body has no identity fields (plain content, error page) | Inconclusive | no identity to compare |
| login page returned (password form, no identity) | Inconclusive | session did not reach the object |
| 401 / 403 | Rejected | object is protected |
| other 4xx/5xx | Inconclusive | no identity data observed |
| empty body | Inconclusive | no identity data observed |

A finding is created **only** for Confirmed. Rejected/Inconclusive/Skipped
outcomes stay in the `TestCase.Detail` so a report is never padded with one
negative row per parameter. A later Confirmed result at the same
(endpoint, parameter) ratchets the existing Finding and unions evidence.

### Evidence

Every Confirmed finding references:

* request A (own object) request + response evidence;
* request B (foreign object) request + response evidence for the confirming
  attempt;
* the identity-baseline TestCase with the account-page request/response.

Evidence blobs are the same `.http` message dumps every other engine writes.

## 3. Current slice boundaries

Deliberately **not** implemented or not performed:

* **Family B** (role parameters, admin paths, URL-prefix bypass, alternate
  methods, multi-step flows, Referer checks) — not authorised by this slice.
* **Writes / state changes.** Only `GET` and `HEAD` are ever sent. A
  body-carrying method (POST/PUT/PATCH/DELETE) is skipped with a stated reason,
  even when the scan's state-changing opt-in is on.
* **POST/form/JSON object identifiers.** The handler accepts query and path
  identifiers only; other locations are skipped with a reason.
* **Victim session.** None is created, imported or guessed.
* **Redirect-body data leakage.** The scope-enforcing engine follows redirects
  and returns the final response; intermediate 3xx bodies are not analysed, so
  a leak that appears only in an intermediate redirect body is not detected.
* **Randomized/opaque identifier enumeration.** Refused by design; supply
  explicit candidates when an authorized brief names the victim's identifier.
* **Function-level authorization and BFLA.**

## 4. Configuration

Scan creation (CLI):

```
indago scan create -project P -target T -auth existing -auth-state state.json \
  -idor -idor-candidates carlos
```

* `-idor` / `enable_idor`: opt-in. Off by default. Rejected at creation time for
  an anonymous scan (there is no caller identity to establish).
* `-idor-candidates` / `idor_candidates`: repeatable, at most 10,
  identifier-shaped values only.

The API (`POST /api/scans`) accepts the same two fields.

## 5. Tests

* `internal/idor/idor_test.go` — pure extraction/derivation/decision fixtures,
  including the mandatory negative controls (same-principal data, no identity
  fields, login pages, opaque identifiers, mixed caller/foreign pages).
* `internal/scan/idor_test.go` — the differential against real `httptest`
  servers: Confirmed on foreign data with both requests as evidence;
  same-principal and no-identity fixtures never Confirmed; login redirect not
  Confirmed; opaque identifier skipped without guessing; POST skipped with no
  request sent; probe-pass selection; opt-in gate; worker-group routing.

## 6. Product-boundary note

AGENTS.md currently lists additional engines as "designed for, not built" and
describes Reflected XSS + DOM XSS as the implemented engines. This slice makes
the IDOR engine real, so AGENTS.md §3 must be raised to the operator for
approval before this can be described as an approved product boundary. The
exact wording is in `HANDOFF.md`.

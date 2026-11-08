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
  └─ endpoints + parameters                     on the same quiet tick as the
        │                                       DOM-XSS pass (neither gates
        │  gate: an authenticated, active        the other)
        ▼                                              │
   JobIDOR (one per object-identifier injection point)
        │
        ├─ identity baseline (once per scan, persisted as a TestCase)
        │     GET /my-account | /profile | /account | /me  on the endpoint origin
        │     → extracted identity fields + request/response evidence
        │
        ├─ request A: own identifier, observed value   → evidence (baseline)
        │
        ├─ candidate derivation (bounded, deterministic, LOCAL — no request)
        │     operator-supplied → numeric neighbours / harvested identifiers
        │     → opt-in bounded enumeration (value±1, 1..N, padded; or the
        │       fixed slug set admin/test/demo/guest)
        │     no candidate at all → one informative skipped TestCase, NO probe
        │
        ├─ request B × N: each → idor.Decide(...)
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

Derivation is **local work**: it reads only data the scan already holds and
performs arithmetic. It therefore happens BEFORE any request, so a parameter
with nothing to try never touches the target (see "Clean conclusion" below).

With the default engine (enumeration off), `idor.DeriveCandidatesFromHarvest`,
in this order, capped at `idor.MaxCandidates` (5):

1. **operator-supplied** identifiers (`-idor-candidates` / `idor_candidates`),
   in the given order — the only way to test an opaque identifier. Max 10,
   validated at scan creation. The tool never invents these; the operator names
   them (e.g. the victim username an authorized lab brief states).
2. **numeric neighbours** of the caller's own numeric identifier (`+1`, `−1`,
   `+2`, `−2`, `+3`), dropped at `≤ 0`.
3. **harvested identifiers** — identifier-shaped values mined from the scan's
   own data (see "Harvesting precision").

With `-idor-enumerate` on, the two numeric sources are replaced by the stated
enumeration arithmetic (below), so the probe list is predictable; supplied and
harvested identifiers still come first.

An opaque identifier (UUID, long random slug) with no supplied candidate and no
harvest yields **no candidates at all** and a stated skip reason. There is no
wordlist and no timing jitter.

### Harvesting precision

A value is only ever treated as an object identifier when the POSITION it came
from plausibly is one:

| Position | Accepted when | Example |
|---|---|---|
| query parameter | name is in the identifier vocabulary | `/my-account?user_id=42` |
| JSON field | field name is in the vocabulary (or is an identity attribute) | `{"users":[{"id":17}]}` |
| path segment | it is the segment AFTER a collection noun | `/users/42`, `/orders/99` |

A bare top-level path is never an identifier: `/product` contributes nothing.
A pure word that the same page also links to as an ordinary route is dropped
even when it appears as a form value or in labelled text. The rest of the
existing filter is unchanged: caller identity, session secrets, timestamps,
versions, asset fingerprints, length bounds, and the deterministic
`MaxHarvested` cap all still apply.

The vocabulary (see `internal/idor/vocabulary.go`) is `id`, `uid`, `guid`,
`uuid`, `user`, `account`, `profile`, `member`, `customer`, `employee`,
`patient`, `order`, `invoice`, `item`, `product`, `booking`, `ticket`, `doc`,
`document`, `file`, `attachment`, `download`, `ref`, `reference`, `no`, `num`,
`number`, `post`, `message`, `comment`, `report`, `record`, `object`, `tenant`,
`org`, `group`, `company`, plus their `_id` / camelCase forms and any
`<something>_id` suffix. The same table gates which parameters are probed
(`ObjectIDParameter`), so harvesting and probing cannot disagree.

### Bounded enumeration (opt-in)

`-idor-enumerate` / `idor_enumerate` adds a small, predictable arithmetic step
for the classic `?id=1`, `?id=2` case. It is OFF by default and requires
`-idor`.

| Baseline observed value | Candidates (N = `-idor-enumerate-n`, default 5, ceiling 10) |
|---|---|
| numeric `7` | `6`, `8`, then `1,2,3,4,5` — exactly 7 values |
| zero-padded `007` | `006`, `008`, then `001..005` — padding preserved at the baseline's width, never unpadded |
| short slug `wiener` | `admin`, `test`, `demo`, `guest` — the only slug set, never a wordlist |
| UUID / email / opaque / long hex | none |

The baseline itself is never repeated; `value-1` is dropped when it would be
`≤ 0`. Arithmetic is `strconv.Atoi` on the observed value (1..12 digits) and
`fmt.Sprintf("%0*d", width, v)` when the baseline is padded — see
`internal/idor/enumerate.go`.

**Bounds.** Per injection point: at most `MaxCandidates` (5) derived plus
`MaxEnumerationPerSite` (2 + N ≤ 12) enumerated = **17 foreign-object
requests**. Scan-wide: ONE shared budget of **60** probes
(`maxIDORProbesPerScan`) spent by derived and enumerated candidates alike, so
enumeration can never multiply the pass's request count. Every probe is still a
single scoped GET/HEAD through the same scope-enforcing engine with the same
saved session; `idor.Decide` is unchanged — an enumeration hit that returns the
caller's own data is **Rejected**, never Confirmed.

### Clean conclusion

If no candidate survives harvesting (and enumeration is off, or produces
nothing), the engine sends **no request at all** — not even the own-object
baseline — and records one skipped `TestCase` whose note reads:

> no foreign object identifier available; supply -idor-candidates or enable
> -idor-enumerate

That is a success with no verdict (not an inconclusive): there is no
probability judgement to make about a target the engine never reached.

### Login-page conclusion, once per scan

A candidate response that renders a password form means the session did not
reach the object. The engine states that **once per scan** (later sites say the
login page was already reported), and stops probing that site immediately
instead of spending the rest of the budget on the same page.

### Verdict rules (`idor.Decide`)

Confirmed requires a **positive identity mismatch** in the response body. Status
codes, body lengths and redirects alone are never enough; the identifier must
also visibly be present in the request (the engine sends it in the focused
parameter only), and — when an evidence store is configured — both request A
and request B blobs must actually be stored (a persistence failure downgrades
the outcome to Inconclusive rather than shipping an unreproducible finding).

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
| evidence store configured but either differential pair could not be stored | Inconclusive | not reproducible |

A finding is created **only** for Confirmed. Rejected/Inconclusive/Skipped
outcomes stay in the `TestCase.Detail` so a report is never padded with one
negative row per parameter. A later Confirmed result at the same
(endpoint, parameter) ratchets the existing Finding and unions evidence.

### Identity extraction rules (and the false-negative defect they fix)

The live PortSwigger "User ID controlled by request parameter" lab exposed a
decision-path defect: the page renders the identity as
`<p>Your username is: wiener</p>` and its title is
`User ID controlled by request parameter`. The old labelled-text patterns made
the separator optional, so `username` + `is` matched with `is` as the value and
the title produced `user_id=controlled`. Both responses — the caller's own and
the foreign object — therefore extracted to the SAME bogus identity
(`username=is`, `user_id=controlled`) and every probe was Rejected.

Extraction is now deliberately strict:

* **A separator is required** between a label and its value: `is`, `:` or `=`
  (in any combination, e.g. `is:`). Prose such as `<title>User ID controlled by
  request parameter</title>` has none and yields nothing.
* **Only rendered text is mined.** `<head>`, `<title>`, `<script>`, `<style>`,
  `<template>`, `<noscript>` and HTML comments are removed first, so page
  metadata and script bodies can never supply an identity.
* **A value must end its element.** Each remaining tag becomes an element
  boundary; a captured word followed by more sentence words is rejected
  ("Your user ID is controlled by the request parameter" yields nothing).
* **Grammar words are not identities** ("is", "not", "the", ... are dropped).
* JSON extraction is unchanged: keys are read structurally, arrays are never
  descended into (a user listing is not the page's principal).

These rules only make the extractor more conservative: a page that renders no
labelled identity remains Inconclusive, never Confirmed on a guess.

The differential itself was already correct — `Decide` is fed the CANDIDATE
response body, not the baseline body — and the account endpoint was already
probed as a target (`/my-account?id=…`): both were verified against the live
fixture before changing anything. The defect was entirely in what the two
responses were understood to say.

### Evidence

Every Confirmed finding references:

* request A (own object) request + response evidence;
* request B (foreign object) request + response evidence for the confirming
  attempt;
* the identity-baseline TestCase with the account-page request/response.

Evidence blobs are the same `.http` message dumps every other engine writes.

### Pass scheduling

The IDOR pass is raw HTTP work on the ordinary HTTP worker group, so it is
enqueued on the **same quiet tick as the DOM-XSS pass** rather than after that
pass's jobs drain. The previous ordering let a single slow or stuck browser
job (reproduced with `browser_concurrency=0`, where browser-group work can
stall indefinitely) prevent object-authorization testing from ever starting.
Both passes remain one-time per execution and still start only once the
ordinary candidate/reflection queue is quiet.

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
  The only enumeration is the bounded, opt-in arithmetic above (small numeric
  neighbours and a four-item slug set) — never a wordlist, never a
  UUID/hash search.
* **Function-level authorization and BFLA.**

## 4. Configuration

Scan creation (CLI):

```
indago scan create -project P -target T -auth existing -auth-state state.json \
  -idor-candidates carlos
```

* There is **no** `-idor` / `enable_idor` switch any more. The engine runs
  automatically for any scan that carries a real caller identity — an
  authenticated, active session (`-auth existing|interactive|mfa|password`)
  and at least one object-identifier-shaped parameter. An anonymous scan plans
  nothing, because there is no caller to compare against.
* `-idor-candidates` / `idor_candidates`: repeatable, at most 10,
  identifier-shaped values only.
* `-idor-enumerate` / `idor_enumerate`: opt-in bounded enumeration. Off by
  default. Requires an authenticated session; rejected at creation otherwise.
* `-idor-enumerate-n` / `idor_enumerate_n`: N for `1..N` (default 5, ceiling
  10). Rejected when set without `-idor-enumerate`.

The API (`POST /api/scans`) accepts the same fields (minus `enable_idor`).

## 5. Tests

* `internal/idor/idor_test.go` — pure extraction/derivation/decision fixtures,
  including the mandatory negative controls (same-principal data, no identity
  fields, login pages, opaque identifiers, mixed caller/foreign pages) and the
  live lab page shape (`Your username is: <name>` under a
  "User ID controlled by request parameter" title) in both its confirming and
  same-principal forms.
* `internal/idor/harvest_test.go` — position/vocabulary precision
  (`/product` and other ordinary routes are never identifiers; `/users/42` and
  `?user_id=42` are), route-word values, the `ObjectPathSegments` rule, plus the
  existing rejection/ranking/purity fixtures.
* `internal/idor/enumerate_test.go` — the exact arithmetic: baseline 7 with N=3
  is exactly `6,8,1,2,3`; a zero-padded baseline yields only padded variants;
  `value-1` never becomes 0; slug/opaque baselines; N clamping; determinism;
  and the unchanged legacy numeric set used when enumeration is off.
* `internal/scan/idor_harvest_test.go` — the harvest integration (no extra
  requests, provenance, persistence, shape matching) and the clean no-candidate
  conclusion: **zero** requests when nothing can be tried.
* `internal/scan/idor_test.go` — the differential against real `httptest`
  servers: Confirmed on foreign data with both requests as evidence;
  same-principal and no-identity fixtures never Confirmed; login redirect not
  Confirmed; opaque identifier skipped without guessing; POST skipped with no
  request sent; probe-pass selection; the automatic caller-identity gate; worker-group routing. Plus
  the regressions for this slice:
  * `TestIDORConfirmsLiveLabShape` — the exact live page shape confirms, the
    caller extracts as `username=wiener` (not `is`), and the account endpoint
    is both the identity source and the probed target;
  * `TestIDORConfirmsJSONVariant` — the same differential on JSON bodies;
  * `TestIDORRequiresStoredEvidenceToConfirm` — a failing evidence backend
    downgrades the verdict instead of creating an unreproducible finding;
  * `TestIDORPassRunsWithoutWaitingForDOMWork` — with `browser_concurrency=0`
    the IDOR job is enqueued while DOM-XSS work is still pending.
* `internal/scan/idor_enumerate_test.go` — the engine-level enumeration
  contract: the exact numeric set, confirmation on an enumerated foreign object,
  the shared 60-probe budget (a 3-probe budget sends exactly 3), the
  once-per-scan login-page conclusion (one attempt per site, never repeated),
  enumeration-off preserving the legacy candidate set, a `/product`-link page
  producing zero requests, zero-padded requests, and the scan-creation
  validation gate.

## 6. Product-boundary note

AGENTS.md currently lists additional engines as "designed for, not built" and
describes Reflected XSS + DOM XSS as the implemented engines. This slice makes
the IDOR engine real, so AGENTS.md §3 must be raised to the operator for
approval before this can be described as an approved product boundary. The
exact wording is in `HANDOFF.md`.

## Redirect-body leaks (case 32)

Some applications answer a foreign object with `302 -> /login` and still put the
account page in the BODY of that redirect. Following the redirect turns the only
copy of the evidence into a login page, and the differential used to end
Inconclusive.

The engine now replays the candidate request **once** with
`httpengine.Request.NoRedirects` when the followed response both redirected and
looked like a login page. The 3xx body is what `Decide` classifies, and the
finding says so: *the redirect response (HTTP 302) leaked the object instead of
sending only a Location*.

- `NoRedirects` is honoured by `scopedEngine.Do` before its own redirect loop, so
  no out-of-scope hop is ever taken; the direct `Client` honours it in
  `CheckRedirect`.
- The replay spends one probe permit from the same scan-wide budget; when the
  budget is gone the original response stands.
- A redirect whose body carries no identity data is still Inconclusive — the
  negative control `TestIDORLoginRedirectIsInconclusive` covers it.

The victim identifier is unchanged: username-shaped ids are operator input
(`-idor-candidates`, or harvest when the app exposes them) or bounded
enumeration. This engine never invents usernames.

## Object families (case 34)

Some endpoints never take an identifier — they mint one. The chat page's own
script posts a transcript to `/download-transcript` and the answer is
`302 -> /download-transcript/2.txt`: the caller's own object. The neighbours'
identifiers are then the arithmetic around that number, which the application
itself named.

The slice is opt-in (`-object-family-probe` / `enable_object_family_probe`,
requires an authenticated session) because the first request POSTs a document
the scan authored. It reads the page's own bytes only:

1. inline and linked same-origin scripts are fetched (bounded: 3),
2. the free-text form field name comes from the page's own `FormData` calls,
3. the endpoint literal comes from the page's own quoted paths (never a wordlist),
4. the scan POSTs its own marker, and the redirect target must parse as
   `<base>/<n>[.<ext>]` with the same base it posted to,
5. the scan reads its own object and requires its marker to be there (proof it
   created this object), then probes the bounded set: `n-1`, `n+1`, and the
   family's first object (`1`) when that is not already one of them.

Confirmation is NOT the identity-field differential: a plain text transcript
names nobody. The rule (`idor.ObjectFamilyDecision`) is narrower: the sibling
must answer 200 with a DIFFERENT document, must not contain the scan's marker,
must not be a denial, and must disclose a credential (`password`, `api key`,
`secret`, `access token`). A sibling equal to the caller's own document, or one
with no credential, is Inconclusive — never Confirmed.

Measured live on case 34 (scan 6d80d4d6): the scan's own object
`/download-transcript/5.txt` carried its marker while `/download-transcript/1.txt`
returned a different transcript disclosing a password — confirmed, 8 evidence
blobs.

# Indago — Domain Model

The domain model lives in [`internal/domain`](../internal/domain) and has **no
dependencies outside the standard library**. It is deliberately **generic across
vulnerability classes** — Phase 1 implements Reflected XSS, but the same entities
serve Stored XSS, DOM XSS, and future engines.

---

## 1. Entities & relationships

```
Project 1───* Target
   │              (BaseURL)
   │ 1
   ├──1 Scope                         (explicit in/out-of-scope rules)
   │ 1
   └──* Scan ───1 Session             (one auth session, reused)
          │ 1
          ├──* Endpoint ──* Parameter
          │        └────────*─────────┐
          │                           │
          ├──* InjectionPoint ◄───────┘   (Endpoint × Parameter)
          │
          ├──* TestJob ──* TestCase       (queue work → concrete tests)
          │
          ├──* Finding ──* Evidence       (verdict + substantiating artifacts)
          │
          ├──* Report                      (rendered summary index)
          │
          └──* AITask                      (advisory records; optional)
```

Cardinality notes:

- A **Project** is the top-level container. A **Target** is a web app (base URL)
  under a project. **Scope** is per-project and governs everything.
- A **Scan** is one hunting run of a target using one reused **Session**.
- **Endpoint**, **Parameter**, **InjectionPoint** form the discovery registry,
  scoped to a scan. An **InjectionPoint** couples an endpoint with a parameter
  and is the generic unit of testing.
- A **Parameter** discovered inside an HTML form carries the **form group** it
  came from (`domain.Parameter.FormGroup`, derived by
  `discovery.FormGroupKey`). One page can hold several forms posting to the
  SAME action — bWAPP's `/commandi.php` has three — and their fields are
  separate request shapes, not one interchangeable parameter list. A request
  built for a parameter therefore carries only that parameter's form group
  (`scan.paramsForFocus`), plus the group-less parameters (query, JSON body,
  header, cookie, path) that belong to the endpoint as a whole. Without this,
  every form's submit button was sent together and the target ran the wrong
  handler.
- A **TestJob** is a unit of queue work (`discovery` / `test` / `verify`). A
  **TestCase** is a concrete test produced while exercising an injection point.
- A **Finding** is a candidate or verified vulnerability with a **Verdict**; it
  links to **Evidence** blobs stored on disk.

---

## 2. Identifiers

`domain.ID` is an opaque UUIDv4 string (`domain.NewID()`), generated from
`crypto/rand`. All entities use it as their primary key.

---

## 3. Value enums (classification)

Defined in [`enums.go`](../internal/domain/enums.go). Each has an `IsValid()`
guard.

| Type | Values |
|------|--------|
| `VulnClass` | `reflected_xss` (Phase 1), `stored_xss`, `dom_xss` (designed-for) |
| `Severity` | `info`, `low`, `medium`, `high`, `critical` |
| `Confidence` | `low`, `medium`, `high` (distinct from verdict) |
| `HTTPMethod` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS` |
| `ParamLocation` | `query`, `form`, `json`, `header`, `cookie`, `path` |
| `DiscoverySource` | `user_provided`, `crawler`, `form`, `browser_network`, `sitemap`, `robots`, `content_discovery`, `param_discovery` |
| `EvidenceKind` | `request`, `response`, `context`, `payload`, `screenshot`, `browser_log`, `har`, `other` |
| `Verdict` | `pending`, `confirmed`, `rejected`, `inconclusive` |
| `AuthMode` | `anonymous`, `password`, `interactive`, `mfa`, `existing` |
| `ReportFormat` | `json` (Phase 0), `markdown`, `html` |

> **Reflection ≠ confirmation.** A detected reflection yields at most
> `VerdictPending`; only verification promotes it to `confirmed` (or demotes it
> to `rejected` / `inconclusive`).

Phase 1 requires at minimum `query`, `form`, and `json` parameter locations;
`header`, `cookie`, and `path` are now wired end to end too (see
`docs/reflection-candidates.md` "Header/Cookie/Path injection points").

---

## 4. Lifecycle enums (state)

Defined in [`state.go`](../internal/domain/state.go) with transition tables.
Full diagrams in [`state-machines.md`](state-machines.md).

| Type | States |
|------|--------|
| `ScanState` | `created`, `running`, `paused`, `awaiting_auth`, `canceling`, `canceled`, `completed`, `failed` |
| `JobState` | `queued`, `leased`, `running`, `succeeded`, `failed`, `canceled`, `dead` |
| `SessionState` | `none`, `authenticating`, `active`, `expired`, `failed` |
| `JobType` | `discovery`, `test`, `verify` |
| `TestCaseStatus` | `pending`, `running`, `completed`, `failed`, `skipped` |
| `AITaskKind` | `prioritize`, `triage`, `interpret_context`, `suggest_payloads`, `analyze_js`, `draft_report` |
| `AITaskState` | `pending`, `running`, `succeeded`, `failed`, `skipped` |

Transitions are validated via `CanTransitionTo`; illegal transitions cannot be
persisted (the controller and store check them).

---

## 5. Scan configuration

```go
ScanConfig{ DiscoveryConcurrency, HTTPConcurrency, BrowserConcurrency int; RequestsPerSecond float64 }
StopPolicy{ Mode StopMode; ConfirmedLimit int }
```

- `ProfileName`: `conservative`, `balanced`, `fast`, `custom`. Presets in
  [`internal/scan/profiles.go`](../internal/scan/profiles.go). **Conservative is
  the default for a new scan** (`domain.DefaultProfile`): Discovery 2 / HTTP 4 /
  Browser 1, 2 requests per second. A caller that omits the profile, or names an
  unknown one, gets that preset — never a faster one. Balanced is the medium
  preset (4 / 10 / 2, 10 req/s) and Fast the aggressive one (8 / 25 / 4, 50
  req/s); both must be requested explicitly.
- `StopMode`: `continue_all`, `first_confirmed`, `after_n_confirmed`,
  `pause_and_ask`. Evaluated by `scan.EvaluateStop`.

---

## 6. Scope (safety-critical)

`domain.Scope.Permits(url)` is pure matching logic that **fails closed**:

- Empty scope (no include hosts **and** no subdomain-only hosts) → deny all.
- Exclusions (hosts, path prefixes) always win over inclusions.
- Host must match an included host; subdomains allowed only when
  `AllowSubdomains` is set (or a `.suffix` pattern is used).
- `SubdomainOnlyHosts` is the third shape: a host listed there authorizes its
  **strict subdomains only**, never itself. It is how a bug-bounty wildcard
  asset (`*.example.com`) is imported — the apex is not part of a wildcard, and
  neither a leading-dot include nor an exclusion can express that. A scope that
  lists only wildcard hosts is a real, non-empty scope.
- If include path prefixes are configured, the path must match one.
- Unparseable or hostless URLs → deny.
- `AllowedOrigins`, when non-empty, adds a scheme/port requirement: the URL must
  match an entry's `scheme://host[:port]` (an omitted port is the scheme
  default; `*.example.com` means strict subdomains only). It can only narrow the
  scope. An empty list is the documented **legacy** behaviour (any scheme, any
  port of an in-scope host), which preserves scopes saved before the field
  existed; `AllowAnySchemePorts` records that choice explicitly for a scope
  saved later and never overrides a non-empty origin list. A save never derives
  an origin list: a new scope must state one or explicitly choose
  `AllowAnySchemePorts`.

Scope is enforced at **scan creation** and again at **start** (defense in depth).

The host matcher compares the **hostname** only (not the resolved IP), and path
prefixes are plain string prefixes. Scheme and port are compared only when the
scope declares origins; otherwise they are ignored, exactly as before. See
[scope-semantics.md](scope-semantics.md) for the exact behaviour and its limits.

---

## 7. Provenance & evidence

Every `Finding` carries `Provenance` (engine, discovery source, tool version,
detected/verified timestamps, and an `AIAssisted` flag that is advisory-only).
Evidence records store a relative `BlobPath`, `Size`, and `SHA256` — the blob
itself lives under the evidence root on disk. This supports **reproducibility**:
a finding can always be traced back to the exact stored request/response/context/
screenshot that substantiates it.

---

## 8. Why generic?

Making the model XSS-specific would force a reshape for every new engine. Instead:

- `InjectionPoint` is the universal test unit (any engine can test it).
- `Finding.VulnClass` + `detection.Engine.VulnClass()` route behavior by class.
- `TestJob.Type` + `Payload []byte` (opaque) keep the queue class-agnostic.

Adding Stored XSS later means: register a new `detection.Engine`, add discovery
that records stored sinks, and reuse everything else.

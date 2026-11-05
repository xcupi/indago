# HANDOFF — Lab 19: anonymous response-cookie continuity (page disclosure → panel probe)

Branch: `fix/ac19-cookie-continuity` (worktree), base `de03251`.
Status: implemented, tested, **not committed / not pushed**. No live host was contacted;
every fixture is a local `httptest` server.

**Review-correction status**

| Correction | Status |
|---|---|
| R1 — disclosure fetch must not touch the shared jar | **GREEN** (shared-jar contamination regression passes; observed RED on the rejected candidate) |
| R2 — explicit authenticated cookies must be redacted too | **GREEN** |
| R3-A — authenticated comparison must be `NoJar` | **GREEN** (RED observed first) |
| R3-B — no cookie value in response bodies / TestCase detail / Finding detail | **GREEN** (RED observed first, twice: body leg, then detail leg) |
| R3-C — isolation modes fail closed outside `scopedEngine` | **GREEN** (RED observed first, 9 failing paths) |
| R3-D — final proof | build, focused tests and `-race` pass (see §9) |
| R4 — no short-value exception | **GREEN** (RED observed first: short value persisted in the response body and the finding title; see §6a) |
| R5 — preserve valid structured detail | **GREEN** (RED observed first: detail JSON corrupted by a one-digit cookie value; see §6b) |

---

## 1. Measured failure and the code path that produced it

Live symptom (reproduced by the coordinator): the page-disclosure pass extracted
`/admin-ah82gg` correctly, the immediate panel probe got HTTP 404, and the path
changes on every fresh `/` request. Control: `/` + matching jar → 200; the same
path with no jar → 404.

Traced path:

1. `enqueueAccessControlDisclosureProbes` (`internal/scan/accesscontrol.go`) enqueues
   `JobAccessControl` with payload `{"mode":"page"}` for discovered HTML pages.
2. `accessControlExecutor.run` → `runPageDisclosure` fetches the page. Before this
   slice that was an ordinary request through the scan's `*scopedEngine`, so the
   page's `Set-Cookie` was consumed by the **shared** `*httpengine.Client` jar.
3. `probePanel` sent the anonymous panel probe with `NoCookies = true` (jar nil,
   cookie list nil). The very cookie the same response had just minted was
   deliberately withheld from the disclosed path → 404 → `accesscontrol.Decide`
   → `rejected`.

Path extraction, context and verdict rules were correct. The missing piece was
transporting the anonymous cookie the disclosure response issued to the one
follow-up probe — without turning it into ambient state.

## 2. The fix

### 2.1 Three explicit cookie modes (`internal/httpengine`)

| `Request` mode | transport jar | `Request.Cookies` | scan's explicit saved session | raw/default `Cookie` header |
|---|---|---|---|---|
| default | read + write | sent | sent | sent (unchanged) |
| `NoCookies` | bypassed | suppressed | suppressed | **dropped** |
| `Jarless` | bypassed | sent | suppressed | **dropped** |
| `NoJar` | bypassed | sent | **sent** | **dropped** |

`NoJar` is the primitive the disclosure fetch needs: hide the shared jar in both
directions while still attaching an authenticated scan's explicit saved session
(deliberate request state, not ambient jar content). At the transport level
`NoJar` and `Jarless` behave identically; the difference is made in
`scopedEngine.Do`, where `NoJar` takes the default `cookiesForURL` path (session
cookies included) and `Jarless` takes `jarlessCookiesForURL` (caller-supplied
cookies only).

All three modes are **fail-closed on redirects the Client follows itself**: the
mode's cookies are declared for THIS request, so the next hop carries none of
them. Go's client otherwise copies an explicit `Cookie` header to any same-host
redirect — including a changed port and an HTTPS→HTTP downgrade.

### 2.2 Wiring (`internal/scan`)

- `runPageDisclosure`: the page fetch is `NoJar`; `fetchDisclosingScript` too.
- `carry := continuityCookies(resp.FinalURL, resp.Headers, probeURL)` per
  disclosed path is a plain job-local value handed to `probePanel`.
- `probePanel`: the anonymous probe is `Jarless` with exactly `carry` (or
  `NoCookies` when there is nothing to carry); the authenticated non-admin
  comparison is `NoJar` — it keeps the scan's explicit saved session and neither
  reads ambient jar cookies nor deposits its own `Set-Cookie`.
- `persistPair` is the single evidence boundary: request `Cookie` values and
  response `Set-Cookie` values are always rewritten to `name=<redacted>` /
  `name=<redacted>; attrs`, and the stored bodies are rewritten too.
- Detail/finding persistence is redacted at its own boundary (`finish`,
  `correlate`) from the same job-local redactor.

Nothing changed in `accesscontrol.Decide`, scope checks, the rate limiter,
redirect handling, or the non-admin comparison's decision role.

---

## 3. R1 — the disclosure fetch leaves the shared jar alone — GREEN

The first candidate left `runPageDisclosure` on `e.do(ctx, httpengine.GET(pageURL))`
and only made the later probe jarless; the disclosure page's cookie outlived the
job in the process-wide jar. The mandated behavioural regression is
`TestAccessControlPageDisclosureLeavesTheSharedJarAlone`
(`internal/scan/accesscontrol_page_disclosure_test.go`). It pins **both**
directions: the disclosure fetch does not READ a planted ambient jar cookie, and
after the job an **ordinary scoped engine on the same client** requesting a capture
endpoint does not receive the cookie the disclosure page (or an external
disclosure script) issued.

**Observed RED on the rejected candidate** (write direction):

```
--- FAIL: TestAccessControlPageDisclosureLeavesTheSharedJarAlone (0.03s)
    accesscontrol_page_disclosure_test.go:455: the disclosure pass stored
    "anon-session=anon-secret-1" in the shared HTTP client jar; a request from another
    engine on that client carried it: "anon-session=anon-secret-1; script-session=script-secret"
```

**Observed RED, read direction** (re-observed by temporarily removing only the page
fetch's `NoJar`, then restoring it):

```
--- FAIL: TestAccessControlPageDisclosureLeavesTheSharedJarAlone (0.03s)
    accesscontrol_page_disclosure_test.go:540: the disclosure fetch read the shared jar:
    page request carried "ambient=planted"
```

**GREEN in the current tree** — this regression passes (§7, §9).

## 4. R2 — explicit authenticated cookies are redacted too — GREEN

QA reproduced, against the jar-fixed candidate:

```
--- FAIL: TestQAAuthedPageDisclosureEvidenceDoesNotPersistSessionCookieValue
raw saved-session cookie value persisted in access-control evidence:
Cookie: sid=qa-nonadmin-secret
```

Root cause: `NoJar` correctly attached the scan's explicit saved session, but
`persistPair` did not redact request cookies for these persists, so
`resp.Request.Headers` preserved the raw `Cookie` header.

The permanent behavioural test is
`TestAccessControlPageDisclosureEvidenceDoesNotPersistSessionCookieValue`. It runs a
real authenticated page-disclosure scan whose saved-session value is the
deliberately distinctive `qa-nonadmin-secret`, lists **every** evidence row for the
scan, and requires that no blob contains the value while the disclosure-page
request and the non-admin comparison request each show `Cookie: sid=<redacted>`. It
also asserts from the fixture's own observations that both requests still carried
their cookies on the wire. RED observed before the `persistPair` change; GREEN now.

Fix: `persistPair` always redacts request `Cookie` values and response `Set-Cookie`
values, for every access-control flow (no opt-in).

---

## 5. R3-A — the authenticated comparison must be `NoJar` — RED → GREEN

`probePanel`'s comparison was `e.send(ctx, httpengine.GET(rawURL))`, i.e. an
ordinary request: it inherited the process-wide jar (a planted ambient cookie could
authenticate it) and its own `Set-Cookie` was stored in that jar.

New behavioural regression:
`TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar`
(`internal/scan/accesscontrol_page_disclosure_test.go`). One shared client, an
explicit saved session (`sid=qa-comparison-secret`), and a fixture whose comparison
response sets `comparison-mint=comparison-issued`. It asserts (1) the comparison
still sends the saved session on the wire, (2) no `/admin-…` request carries the
planted `ambient=planted` jar cookie, (3) after the job an ordinary scoped engine on
the same client gets no `comparison-mint` (nor the page's `anon-session`) on a
capture request — and that the flow still ends `confirmed`, so isolation cannot be
achieved by simply breaking continuity.

**RED (before the fix):**

```
--- FAIL: TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar (0.04s)
    accesscontrol_page_disclosure_test.go:665: the comparison request read the shared jar:
    Cookie: "sid=qa-comparison-secret; ambient=planted"
```

**Fix:** `compareReq := httpengine.GET(rawURL); compareReq.NoJar = true`.

**GREEN:** the test passes, together with the rest of §7/§9.

## 6. R3-B — cookie values may not survive in bodies or details — RED → GREEN

`persistPair` redacted headers only; `Response.Body` was stored verbatim, and
body-derived data (an `accesscontrol.Action.Target` taken from an href) reached the
TestCase and Finding detail.

New behavioural test:
`TestAccessControlPageDisclosureRedactsReflectedCookieValues`
(`internal/scan/accesscontrol_reflection_redaction_test.go`). The fixture reflects
**both** the saved-session value (`qa-reflected-session-secret`) and the
page-issued anonymous value (`anon-secret-1`) into the disclosure page's HTML and
into the panel it serves — one of them inside an admin action's href, so it also
flows into the derived detail. Assertions: the wire still carries both values (from
the fixture's own request log), every evidence blob for the scan omits both values,
`tc.Detail`, `findings[0].Detail` and the finding summary/title/note omit both, the
request evidence still shows `sid=<redacted>`, and unrelated body content ("Admin
panel") survives.

The test was deliberately driven RED twice, once per data path.

**RED #1 — the stored response body (before any body redaction):**

```
--- FAIL: TestAccessControlPageDisclosureRedactsReflectedCookieValues (0.04s)
    accesscontrol_reflection_redaction_test.go:139: raw cookie value "qa-reflected-session-secret"
    persisted in response evidence 7e7d4821-47bf-40fc-8737-3c5be0ba2515:
        HTTP/1.1 200 OK
        Set-Cookie: anon-session=<redacted>; Path=/

        <!doctype html><html><body>
        <p>debug: sid=qa-reflected-session-secret</p>
        <p>debug: anon-session=anon-secret-1</p>
        ...
```

**RED #2 — the derived detail** (body redaction in place, detail redaction not yet):

```
--- FAIL: TestAccessControlPageDisclosureRedactsReflectedCookieValues (0.04s)
    accesscontrol_reflection_redaction_test.go:166: raw cookie value "qa-reflected-session-secret"
    persisted in the test-case detail:
        {"engine":"access_control","kind":"page",...
         "actions":[{"kind":"delete_user",
                     "evidence":"Delete wiener -> /admin/delete?username=wiener\u0026debug=qa-reflected-session-secret",
                     "target":"/admin/delete?username=wiener\u0026debug=qa-reflected-session-secret"}, ...], ...}
```

**Fix — one job-local redactor, applied at both persistence boundaries:**

- `internal/scan/evidenceredaction.go` (new): `cookieRedactor` lives in the job's
  context (created once in `Handle`). `observe(resp)` records only the values the
  pair already carries — every value in the captured request's `Cookie` header(s)
  and every value in the response's `Set-Cookie` header(s). `redact`/`redactBytes`
  rewrite those exact values (plus their URL-encoded, JSON-escaped and
  HTML-escaped forms) to `<redacted>`; longer values first. There is no length
  floor: every observed non-empty value is rewritten (see §6a), with a
  control-byte sentinel resolving to the marker only after all values are
  matched, so a one-character value cannot rewrite the marker itself.
- `persistPair`: `observe(resp)` then store `red.redactBytes(dumpRequest(...))` /
  `red.redactBytes(dumpResponse(...))`. This covers every access-control mode that
  uses `persistPair`, including the role-flag and role-field flows.
- `fetchDisclosingScript`: observes its response and redacts the persisted script
  blob and its evidence note.
- `finish`: redacts the serialised TestCase detail, `Note` and `Error`.
- `correlate`: redacts the Finding title, summary and detail (create and absorb).

The decision layer still sees the untouched bytes: redaction only rewrites the
persisted copy, so the verdict is unchanged (the test asserts `confirmed`).

**GREEN:** `TestAccessControlPageDisclosureRedactsReflectedCookieValues` passes, as
do the unit tests pinning the redactor's encoded forms, short-value behaviour and
longest-first ordering (`internal/scan/evidenceredaction_test.go`).

## 6a. R4 — no short-value exception — RED → GREEN

The R3-B redactor deliberately left values shorter than six bytes unchanged
(`minRedactableCookieValueLen`). That exception was active, and it violated the
requirement that raw cookie values never persist: `sid=abc`, `role=1` or a weak
lab session cookie can be the credential or the authorization state.

New behavioural test:
`TestAccessControlPageDisclosureRedactsShortCookieValues`
(`internal/scan/accesscontrol_reflection_redaction_test.go`). The fixture mints a
three-byte anonymous cookie (`anon-session=zqx`), reflects it into the disclosure
page's HTML, discloses `/admin-zqx` (so the finding title and reason quote the
value too), and embeds it in the panel's delete-action href — body-derived data
that `accesscontrol.Analyze` turns into `Action.Target`, so it reaches TestCase
and Finding detail. The scan is anonymous, so this also proves continuity still
carries the short cookie to the disclosed path. Assertions: the admin probe
carries `anon-session=zqx` on the wire; every evidence blob omits `zqx` while the
request evidence still shows `anon-session=<redacted>`; TestCase detail, note and
error plus Finding detail, title and summary omit it; the panel heading and the
action text ("Delete wiener") survive.

**Observed RED on the prior candidate #1 — stored response body:**

```
--- FAIL: TestAccessControlPageDisclosureRedactsShortCookieValues (0.03s)
    accesscontrol_reflection_redaction_test.go:278: raw short cookie value "zqx"
    persisted in response evidence 33bc48b4-fc0a-460e-8ee8-b15338d1ec1a:
        HTTP/1.1 200 OK
        Set-Cookie: anon-session=<redacted>; Path=/

        <!doctype html><html><body>
        <p>debug: anon-session=zqx</p>
        ...
```

**Observed RED #2 — Finding title** (same test with the disclosed path embedding
the short value; the old `len(value) < 6` guard was temporarily restored to
reproduce the candidate):

```
--- FAIL: TestAccessControlPageDisclosureRedactsShortCookieValues (0.03s)
    accesscontrol_reflection_redaction_test.go:285: raw short cookie value "zqx"
    persisted in the finding title:
        Access control: anonymous access to admin actions at GET /admin-zqx
```

**Fix:** `add` no longer applies a length floor (only empty values and the
marker itself are skipped). `redact` substitutes a control-byte sentinel for
every match and resolves all sentinels to `<redacted>` only after every value has
been processed, so a one-character value that also occurs inside the marker
(`e`, `a`, …) cannot corrupt or recursively rewrite it.
`TestCookieRedactorSingleCharacterValueCannotRewriteTheMarker` pins the sentinel,
and `TestCookieRedactorRedactsShortValuesAndLeavesUnknownTextAlone` replaces the
old leak-documenting short-value test with the safe expectation: `on`, `dark`
and `1` are redacted while a value the job never observed is untouched.

**GREEN:**

```
--- PASS: TestAccessControlPageDisclosureRedactsShortCookieValues (0.03s)
--- PASS: TestCookieRedactorRewritesEveryEncodedForm (0.00s)
--- PASS: TestCookieRedactorRedactsShortValuesAndLeavesUnknownTextAlone (0.00s)
--- PASS: TestCookieRedactorSingleCharacterValueCannotRewriteTheMarker (0.00s)
--- PASS: TestCookieRedactorRedactsLongerValueFirst (0.00s)
```

The accepted cost is over-redaction when a very short cookie value is also
ordinary prose (for example `on` inside `Content-Length`); credential
non-retention wins over evidence fidelity, as requirement 2 states.

## 6b. R5 — redaction must not corrupt structured detail — RED → GREEN

R4's no-floor redaction used blind byte substitution over the serialised JSON
detail, so a short value `1` turned `{"attempt":1,...}` into
`{"attempt":<redacted>,...}` (invalid JSON; broken UI/consumers).

Permanent tests (written first):

- `TestCookieRedactorJSONDetailKeepsStructuralPrimitives`
  (`evidenceredaction_test.go`) — the QA overlay repro, hardened: `role=1` string
  redacted; `attempt:1`, `status:200`, `true`, `null`, unknown nested fields,
  `2.50` and a 20-digit number stay byte-for-byte semantically unchanged; output
  parses; non-JSON input falls back to strict byte redaction.
- `TestAccessControlPageDisclosureNumericCookieKeepsDetailValid`
  (`accesscontrol_reflection_redaction_test.go`) — end to end with an anonymous
  cookie `anon-session=2` reflected into an action href: TestCase and Finding
  detail parse, verdict `confirmed`, `page_status`/`anonymous_status` == 200, and
  the action target is `/admin/delete?username=wiener&debug=<redacted>`.

**RED (against the byte-substituting candidate; `redactJSON` temporarily aliased to
`redactBytes` so the tests compile):**

```
--- FAIL: TestAccessControlPageDisclosureNumericCookieKeepsDetailValid
    test-case detail must remain valid JSON: invalid character '<' looking for beginning of value
    {"engine":"access_control",...,"anonymous_status":<redacted>00,...}
--- FAIL: TestCookieRedactorJSONDetailKeepsStructuralPrimitives
    redacted detail must remain valid JSON: invalid character '<' ...;
    bytes={"attempt":<redacted>,"cookie":"role=<redacted>","status":200,...}
```

**Fix:** `cookieRedactor.redactJSON` decodes the record (`json.Number`, so numbers
are preserved verbatim), redacts only string VALUES recursively (unknown fields and
object keys kept), and re-encodes with HTML escaping off so the `<redacted>` marker
stays literal. Invalid/multi-value input falls back to `redactBytes`. Used for
TestCase detail (`finish`) and Finding detail (`correlate`, create + absorb). Response
bodies/evidence blobs, notes, errors, title and summary still use strict
`redact`/`redactBytes`. Note: re-encoding sorts object keys alphabetically.

**GREEN:** both new tests pass; all earlier redaction tests (long/short/encoded/
sentinel/reflected/session/shared-jar) still pass.

```
go build ./...                                                    ok
gofmt -l .                                                        (empty)
go vet ./internal/scan                                            ok
go test -count=1 ./internal/accesscontrol ./internal/scan ./internal/httpengine   all ok
go test -count=1 -race -run 'TestAccessControl|TestContinuityCookies|TestScopedEngine|TestCookieRedactor' ./internal/scan   ok
```

## 7. R3-C — isolation modes fail closed outside `scopedEngine` — RED → GREEN

`httpengine.Client` is public and follows redirects itself. Before this change a raw
`Cookie` header (from `Config.DefaultHeaders` or `Request.Headers`) bypassed
`NoCookies`/`Jarless`/`NoJar` entirely, and an explicit cookie was copied by Go's
client to a same-host redirect (port change, HTTPS→HTTP) that the mode never
authorised.

New tests in `internal/httpengine/isolation_test.go`:

- `TestNoCookiesIgnoresRawAndDefaultCookieHeaders` — default header + raw header +
  `Request.Cookies`, all suppressed.
- `TestIsolationModesSendOnlyTheirExplicitCookies` — `Jarless`/`NoJar` send only
  `Request.Cookies`, with a seeded jar and both raw header sources present.
- `TestIsolationModesDoNotForwardCookiesOnRedirect` — six subtests: `{nocookies,
  jarless, nojar} × {changed-port, https-to-http}`; the landing request carries no
  cookie.
- `TestDefaultRequestKeepsNormalCookieBehaviour` and
  `TestClientJarStillSharedForOrdinaryRequests` — the control: a non-isolated
  request still sends its explicit + raw cookies across a same-host redirect, and
  still reads and writes the jar.

**RED (all nine paths, before the fix):**

```
--- FAIL: TestNoCookiesIgnoresRawAndDefaultCookieHeaders (0.00s)
    isolation_test.go:102: NoCookies request sent Cookie header "raw=leak", want no cookie at all
--- FAIL: TestIsolationModesSendOnlyTheirExplicitCookies (0.00s)
    --- FAIL: .../jarless: jarless request sent Cookie header "raw=leak; explicit=only", want only the explicit cookie
    --- FAIL: .../nojar:   nojar request sent Cookie header "raw=leak; explicit=only", want only the explicit cookie
--- FAIL: TestIsolationModesDoNotForwardCookiesOnRedirect (0.01s)
    nocookies/changed-port:    "raw=leak"
    nocookies/https-to-http:   "raw=leak"
    jarless/changed-port:      "raw=leak; explicit=only"
    jarless/https-to-http:     "raw=leak; explicit=only"
    nojar/changed-port:        "raw=leak; explicit=only"
    nojar/https-to-http:       "raw=leak; explicit=only"
```

**Fix (narrowest safe client-level behaviour):**

- `buildRequest`: for `NoCookies`/`Jarless`/`NoJar`, drop any `Cookie` header after
  the default and per-request header maps are applied, then add only
  `Request.Cookies` (and none at all for `NoCookies`).
- `Do`'s `CheckRedirect`: for those modes, delete the `Cookie` header on the next
  hop. The scope-enforcing engine follows redirects itself and re-derives its
  cookies per hop, so production per-hop behaviour is unchanged; this only affects
  direct `Client` use.

**GREEN:** all eight tests above pass, and the whole `internal/httpengine` package
passes (including the pre-existing cookie, redirect and jar tests).

---

## 8. Requirement mapping

| Requirement | Where it is proven |
|---|---|
| Works anonymously and with an existing authenticated session | `...CarriesIssuedCookieToDisclosedPath` (anonymous), `...KeepsTheSessionOutOfTheAnonymousProbe` + `...DoesNotPersistSessionCookieValue` (session), `TestScopedEngineNoJarKeepsExplicitSessionAndHidesTheJar` |
| Host/domain/path/Secure/expiry + same-origin rules | `TestContinuityCookiesObeyBrowserScope` (15 cases: default-path, explicit Path, Secure up/down, Max-Age=0, past Expires, Partitioned, Domain with/without leading dot, IP host, foreign Domain), `TestContinuityCookiesNeverCrossOrigins` (4), `TestScopedEngineSessionCookie*`, `TestScopedEngineRechecksSessionCookieScopeOnRedirects` |
| Never forward a response cookie to another origin | `...CookieNeverLeavesItsOrigin`, `TestScopedEngineJarlessCookieStopsAtAnOriginBoundary`, `TestIsolationModesDoNotForwardCookiesOnRedirect` |
| No raw cookie values in evidence / reports / logs / finding detail / config | `...Carries...` (anonymous value), `...EvidenceDoesNotPersistSessionCookieValue` (session value, **every** evidence row), `...RedactsReflectedCookieValues` (body + TestCase detail + Finding detail), `...RedactsShortCookieValues` (three-byte value, body + action detail), `TestCookieRedactor*` |
| Scan-local / ephemeral; no reuse across scans | `TestAccessControlPageDisclosureLeavesTheSharedJarAlone`, `TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar` (both directions, ordinary engine on the same client afterwards); `carry` and the redactor are call-scoped values, never stored |
| A 200 alone is not a finding | `...RejectsUnreachableDisclosedPath/bare-panel` (right cookie, HTTP 200, no privileged action → rejected); `accesscontrol.Decide` untouched |
| Scope / rate limit / redirects / auth unchanged | same `scopedEngine`, same per-hop scope check and limiter, same manual redirect loop. The isolation modes only narrow cookie state; the comparison keeps its decision role |

## 9. Gates (run in this worktree)

```
go build ./...                                                        -> ok
gofmt -l .                                                            -> (empty)
go vet ./...                                                          -> ok
go test -count=1 ./internal/accesscontrol ./internal/scan ./internal/httpengine
    ok internal/accesscontrol   0.004s
    ok internal/scan           22.221s
    ok internal/httpengine      1.472s
go test -count=1 -race \
  -run 'TestAccessControl|TestContinuityCookies|TestScopedEngine|TestNoJar|TestJarless|
        TestNoCookies|TestIsolationModes|TestDefaultRequest|TestClientJar|TestCookieRedactor' \
  ./internal/scan ./internal/httpengine
    ok internal/scan 2.275s
    ok internal/httpengine 1.071s
go test -count=1 ./...
    only the three PRE-EXISTING failures below; every other package ok
    (internal/accesscontrol, internal/httpengine, internal/scan, … all ok)
```

Selected GREEN results:

```
--- PASS: TestAccessControlPageDisclosureCarriesIssuedCookieToDisclosedPath
--- PASS: TestAccessControlPageDisclosureRejectsUnreachableDisclosedPath (no-cookie, mismatched, bare-panel)
--- PASS: TestAccessControlPageDisclosureKeepsTheSessionOutOfTheAnonymousProbe
--- PASS: TestAccessControlPageDisclosureCookieNeverLeavesItsOrigin
--- PASS: TestAccessControlPageDisclosureEvidenceDoesNotPersistSessionCookieValue
--- PASS: TestAccessControlPageDisclosureLeavesTheSharedJarAlone               <- R1 regression
--- PASS: TestAccessControlPageDisclosureComparisonIsIsolatedFromTheSharedJar  <- R3-A
--- PASS: TestAccessControlPageDisclosureRedactsReflectedCookieValues          <- R3-B
--- PASS: TestAccessControlPageDisclosureRedactsShortCookieValues             <- R4
--- PASS: TestCookieRedactorRewritesEveryEncodedForm
--- PASS: TestCookieRedactorRedactsShortValuesAndLeavesUnknownTextAlone
--- PASS: TestCookieRedactorSingleCharacterValueCannotRewriteTheMarker
--- PASS: TestCookieRedactorRedactsLongerValueFirst
--- PASS: TestContinuityCookiesObeyBrowserScope (15 subtests)
--- PASS: TestContinuityCookiesNeverCrossOrigins (4 subtests)
--- PASS: TestContinuityCookiesAreBounded
--- PASS: TestScopedEngineJarlessRequestSendsOnlyItsOwnCookies
--- PASS: TestScopedEngineJarlessCookieStopsAtAnOriginBoundary
--- PASS: TestScopedEngineNoJarKeepsExplicitSessionAndHidesTheJar
--- PASS: TestAccessControlConfirmsAnonymousAdminPanel
--- PASS: TestAccessControlRejectsAdminRequiringSession
--- PASS: TestAccessControlRejects200WithoutPrivilegedAction
--- PASS: TestAccessControlAnonymousScanStillConfirmsMissingAuth
--- PASS: TestAccessControlCorrelationKeepsOneFinding
--- PASS: TestNoCookiesRequestIsAnonymous
--- PASS: TestJarlessRequestSendsExplicitCookiesAndIgnoresTheJar
--- PASS: TestNoJarRequestSendsExplicitCookiesAndLeavesTheJarAlone
--- PASS: TestNoCookiesIgnoresRawAndDefaultCookieHeaders
--- PASS: TestIsolationModesSendOnlyTheirExplicitCookies
--- PASS: TestIsolationModesDoNotForwardCookiesOnRedirect (6 subtests)
--- PASS: TestDefaultRequestKeepsNormalCookieBehaviour
--- PASS: TestClientJarStillSharedForOrdinaryRequests
```

Pre-existing failures, identical on a pristine `de03251` worktree and unrelated to
this slice:

- `internal/domain` — `scope_host.go` is a committed placeholder (`PermitsHost`
  always false): `TestPermitsHostAgreesWithPermitsOnHostRules`,
  `TestPermitsHostIgnoresPathRulesThatPermitsEnforces`.
- `cmd/indago` — `TestRawQueryModeFlag` (`Set("false"): unknown raw query injection
  mode`).
- `internal/browser` — `TestIntegrationDefaultConfigRendererIsSandboxed`
  (Chromium's process sandbox aborts in this container).

## 10. Changed / added files

```
internal/httpengine/engine.go          Request.NoJar + the documented contract of all three modes
internal/httpengine/client.go          jar hidden (read+write) for the three modes; raw/default
                                       Cookie headers dropped; redirects fail closed
internal/httpengine/client_test.go     TestNoJarRequestSendsExplicitCookiesAndLeavesTheJarAlone
internal/httpengine/isolation_test.go  NEW — R3-C fail-closed tests + normal-behaviour controls
internal/scan/cookiecontinuity.go      NEW — continuityCookies (origin/domain/path/Secure/expiry, cap)
internal/scan/scoped.go                Jarless branch, per-hop replay scoping and origin gate
internal/scan/evidenceredaction.go     NEW — job-local cookieRedactor (body/detail redaction; no
                                       length floor, sentinel-protected marker)
internal/scan/evidenceredaction_test.go NEW — encoded forms, short-value redaction, sentinel, ordering
internal/scan/accesscontrol.go         disclosure page + disclosing script are NoJar; comparison is
                                       NoJar; carry wiring; unconditional header redaction in
                                       persistPair; body/detail/finding redaction
internal/scan/accesscontrol_test.go    authenticated comparison evidence assertion (redacted format)
internal/scan/accesscontrol_page_disclosure_test.go   NEW — Lab 19 flow, negatives, cross-origin,
                                       authenticated separation, R1/R2/R3-A regressions
internal/scan/accesscontrol_reflection_redaction_test.go NEW — R3-B and R4 regressions
internal/scan/cookiecontinuity_test.go NEW — scope / cross-origin / isolation tests
```

No new dependency; no change to AGENTS.md, browser verification, payloads, evasion,
role/IDOR behaviour, scope, rate limiting, redirects, auth, or any state-changing
request.

## 11. Residual limitations (deliberate, pre-existing or out of this slice)

1. The HTTP client's jar is still process-wide for every NON-isolated request path
   (discovery, candidate traffic). This slice removes the whole page-disclosure job —
   page, scripts, anonymous carry, comparison — from it in both directions; a
   per-scan jar remains the wider fix and needs its own slice.
2. `NoJar` does not carry a cookie across a redirect hop inside one fetch (the jar
   that would do that is exactly what it hides). A disclosure page that only becomes
   readable after a redirect that sets a session cookie is not covered; today's flow
   reads the final response and carries only what that response issued.
3. The disclosure fetch no longer replays cookies an earlier crawl request left in
   the shared jar — only the scan's explicit saved session travels with it. That is
   the deliberate consequence of the scan-local requirement; a page whose disclosure
   depends on another scan's ambient cookie would need its own explicitly modelled
   continuity.
4. Body/detail redaction knows only the values the job itself saw on the wire
   (request `Cookie`, response `Set-Cookie`). A secret a target invents, or a value
   encoded some third way (e.g. base64), is not rewritten. Every observed non-empty
   value IS rewritten (R4): a very short value that also occurs as ordinary prose is
   over-redacted by design, and within a detail record's STRING values (R5) a one-digit value is replaced
   everywhere it occurs, including inside other strings such as UUID evidence IDs or
   ports in URLs (e.g. `9e0a4b<redacted>f-…`), which can break those IDs as links.
   The JSON stays valid and numeric/boolean fields are untouched, but string-level
   over-redaction of very short values remains by design; credential non-retention
   outranks evidence fidelity, per requirement 2.
5. The IDOR executor (`internal/scan/idor.go`) has its own `persistPair` that still
   redacts headers only. It is object-level authorization, a different engine, and
   changing it would touch the IDOR/role behaviour this slice must not alter; the
   same treatment is the natural follow-up.
6. Page mode does not record the comparison fields (`Compared`/`NonAdminStatus`/
   `NonAdminActions`) although the comparison runs. Pre-existing detail gap.
7. `internal/domain/core.go` points at `docs/access-control.md`, which does not exist
   in this tree (pre-existing dangling reference). The mechanism is documented in
   code (`cookiecontinuity.go`, `evidenceredaction.go`, `Request.NoJar`) and here.
8. Continuity is wired only into the page-disclosure source; the robots/sitemap
   panel mode has no disclosure response to bind to and still passes `nil`.

## 12. Notes for the coordinator's live validation

- Run the lab scan with the page-disclosure pass enabled
  (`-access-control-pages` on the CLI, `enable_access_control_pages` over the API)
  and anonymous auth.
- Expected in the `access_control` TestCase detail: `kind=page`,
  `refs=[{path:"/admin-<nonce>",source:"inline script"}]`, `page_status=200`,
  `anonymous_status=200`, `verdict=confirmed`, one
  `access control: anonymous access to admin actions at GET /admin-<nonce>`
  finding.
- Expected in evidence: the anonymous probe request shows `Cookie: <name>=<redacted>`;
  the disclosure page response shows `Set-Cookie: <name>=<redacted>; Path=/` with the
  note "(Set-Cookie values redacted)". No raw cookie value appears anywhere —
  including inside a body that echoes it.
- Path confirmed working locally with `TestAccessControlPageDisclosureCarries...`;
  the disclosed path varies per root request, so nothing is reused across runs.
- Do **not** read a 200 on the disclosed path alone as the finding: the verdict still
  requires an observable privileged action (`accesscontrol.Decide`), which the
  `bare-panel` negative pins.

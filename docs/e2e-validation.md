# Indago — End-to-End Validation & Hardening

This phase added no detection features. It built a local test corpus and ran
the complete Reflected XSS pipeline — discovery → endpoint/parameter → queue
→ reflection → context → candidate → HTTP test → browser verification →
finding → correlation → report — against it with real Chromium, then fixed
only what those tests actually found broken. Five real gaps surfaced this way;
each is a fix to existing, already-designed behavior, not new functionality.

## The corpus (`internal/scan/e2e_corpus_test.go`)

One httptest server, `newCorpus`, with one handler per scenario:

| Path | Scenario | Expected verdict |
|---|---|---|
| `/safe` | value never reaches the response | no finding at all |
| `/encoded` | HTML-escaped reflection | `rejected` |
| `/attr` | unescaped HTML-attribute reflection | `confirmed` |
| `/js` | unescaped `<script>` string reflection | `confirmed` |
| `/multi` | one parameter, two reflection sites/contexts | two distinct findings, both `confirmed` |
| `/confirmed` | the headline executable case | `confirmed` |
| `/noisy` | encoded (non-executable) reflection **plus** an unrelated script error on every load | `rejected` — the unrelated error must never be mistaken for the candidate's own signal |
| `/auth` | reflects only with the session cookie present | `confirmed`, and only once authenticated |
| `/outside` → `/outside/secret` | linked but out of scope | never requested |
| `/form`, `/json` (POST) | state-changing reflection | skipped by default; sent (→ `pending`, see below) with the opt-in |

`addJSONEndpoint` seeds the POST-JSON endpoint/parameter/injection-point
directly — discovery has no JSON-body source (adding one would be a detection
feature, out of scope here) — then lets the ordinary
queue→reflection→…→finding chain run it exactly like a discovered endpoint.

Companion files: `e2e_recovery_test.go` (a `JobVerify` job interrupted
mid-navigation, then a real restart with a **fresh** `browser.Manager`),
`e2e_hardening_test.go` (concurrent scans sharing one browser pool, a
goroutine-leak check across a full scan lifecycle, malformed/oversized
responses, a larger crawl, and throughput/memory measurements logged for
inspection, not gated on exact numbers).

## What these tests found and fixed

**Session expiration was never wired up.** `domain.SessionExpired`,
`domain.ScanAwaitingAuth`, and `auth.Authenticator.Validate` all already
existed — `domain.Session`'s own doc comment says "on expiry the owning scan
moves to AwaitingAuth" — but nothing in `internal/scan` ever checked
`ExpiresAt` or called `Validate`. `Controller.evaluate`'s monitor pass now
does (`sessionExpired` / `pauseForExpiredSession`), and `Resume` re-establishes
the session when resuming from `AwaitingAuth`
(`reauthenticateIfAwaitingAuth`). See `TestSessionExpiryPausesScanAwaitingAuth`
and `TestSessionExpiryReestablishedOnRestoredResume` in
`internal/scan/session_test.go`.

**There was no way to test "authenticated scan flow" at all.** Re-establishing
a session on `Start`/`Resume` always re-ran `Anonymous.Establish`, which
resets `StatePath` to empty — so even seeding a session's storage state
directly in the store before `Start` was immediately overwritten.
`auth.Existing` (importing session material saved by a prior interactive
login, via `CreateScanParams.AuthStatePath` → `auth.Input.StatePath`) is now
implemented — it performs no network or browser activity itself, just
validates the file is present — which is what makes an authenticated
end-to-end test possible. See `internal/auth/auth_test.go` and
`TestE2E_AuthenticatedScanFlow`.

**The HTTP-level executor never carried the scan's session.** Browser
verification already read `domain.Session.StatePath` per job, but the plain
HTTP engine used for discovery and the reflection/candidate steps never did —
a cookie-gated endpoint would never even reflect for the HTTP executor, so no
candidate would ever be planned and verification would never run.
`scopedEngine.WithSessionCookies` (fed by `sessionCookies`, a small parser for
the browser storage-state JSON format) now carries the same session's cookies
on every HTTP request for that scan — scan-scoped, never leaking into another
concurrently-running scan's requests even though the underlying transport is
shared. See `internal/scan/scoped.go` and its tests.

**A POST/JSON candidate that reflected produced no `Finding` at all.**
`docs/scan-orchestration.md` already documented the intent — "a POST/body-
carrying reflection has no browser-navigable form … and stays `pending`" —
but the code gated Finding *creation* and the verify-job *enqueue* behind the
same `isSafeMethod` check, so a POST candidate got neither: not even a
`Pending` record the operator could see. `enqueueVerification` now always
correlates a Finding when a candidate reflects; only the verify-job enqueue is
gated on the method. See `TestEnqueueVerificationSkippedForStateChangingEndpoint`
(updated) and `TestE2E_StateChangingAllowedSendsPostCandidates`.

**A scan with `BrowserConcurrency: 0` could never complete.** That is a
legitimate, already-supported configuration — "no browser available for this
scan" — and `verifyExecutor` already handles it by skipping `JobVerify` jobs
gracefully. But a zero-sized worker group never *leases* anything, so any
reflected GET candidate's verify job sat queued forever and the scan hung.
`minBrowserWorkers` now floors the browser group at 1 regardless of the
configured value, in both `poolConfig` and `Reconfigure`.

**Finding correlation had two read-then-write races.** `upsertPendingFinding`
looks up a correlating Finding by scanning existing ones and comparing dedup
keys — not an atomic store operation — so two candidates reflecting into the
same site on different workers could both see "no match" and each create a
Finding, producing a duplicate. `correlateVerification`'s Get→mutate→Update
had the same shape: two verify jobs completing for the same correlated
Finding could race, and whichever `Update` committed last would silently
overwrite the other's evidence/verdict. Both are now serialized behind one
`*sync.Mutex` shared between a scan's `executor` and `verifyExecutor`
(constructed once in `defaultHandlers`). This one was caught by
`go test ./...` running the full suite together (SQLite's extra latency
widened the race window), not by `-race` — it is a logical race in
application logic, not a Go memory-model data race. See
`TestEnqueueVerificationConcurrentCandidatesDoNotDuplicateFinding` (run with
`-race`, 10x in a loop during development) and the now-reliable
`TestE2E_RestartRecoversInterruptedVerification`.

## What was checked and found already correct

Scope enforcement at discovery, HTTP, and browser layers; evidence integrity
(every evidence reference resolves and its blob is readable); report
determinism (JSON and Markdown, 20 repeated `Generate` calls); crash/restart
recovery for ordinary `JobTest` work (already covered before this phase);
duplicate-endpoint prevention during a crawl; `-race`-clean concurrency
everywhere else. CLI vs. Web UI parity was reviewed by reading
`cmd/indago/cli.go`: the CLI is a thin HTTP client over the same
`internal/web` API the browser UI calls, so the two cannot diverge in
behavior by construction — no `Finding`/`Report` endpoint exists in either
yet, which is a product gap to consider separately, not a parity bug.

## Boundaries

No new detection features, no new payload types, no DOM/Stored XSS. Every fix
above completes or connects something already designed in an earlier phase
(a state machine, an interface method, a documented behavior) rather than
introducing new product surface — the one exception, `auth.Existing` and its
`CreateScanParams.AuthStatePath` field, is the minimum needed to make the
already-designed "authenticated scan" scenario testable at all, and performs
no network/credential activity of its own. See `AGENTS.md` §2–§3.

## Production Candidate Hardening phase

A broader security/reliability pass (API security, process/resource
lifecycle, persistence consistency, SSRF, and more) — findings are
summarized in the hardening report delivered with that phase, not
reproduced here. Two items specific to this file's territory (real-Chromium
test reliability):

**A genuine data race in concurrent browser-context/page creation.**
`go test -race ./...` (run with `-p 1` to remove unrelated cross-package
contention — see `docs/testing-strategy.md` §3) surfaced one confirmed
`WARNING: DATA RACE` in `TestE2E_RestartRecoversInterruptedVerification`,
inside Playwright's own context-creation event-handler registration
(`newBrowserContext` → `eventRegister.callHandlers` →
`connection.Dispatch`), racing against this test's discovery goroutine
(`execution.go` `runDiscovery` → `disc.Run`). The scenario needs discovery's
browser-network-observation source and candidate verification both using the
same shared `browser.Manager` at once (both are enabled together whenever
`Options.Browser` is set) — plausible any time a scan runs discovery and
verification concurrently with a Chromium instance shared between them.
Root cause: nothing in Indago's own bookkeeping (already mutex-guarded) —
the evidence points at `NewContext`/`NewPage` not being safe to call
concurrently from independent goroutines on the same underlying Playwright
browser connection. Fixed by serializing just the *creation* of a context or
page through a new `Manager.createMu`, in `internal/browser/manager.go`;
operations on an already-created context/page are unaffected. The race
reproduced only once in roughly 20 attempts before the fix and did not
reproduce in 18 further attempts after it — treat this as strong, not
absolute, confirmation; it is exactly the kind of low-probability
interleaving that warrants a follow-up stress run (`go test -race
./internal/scan/... -run TestE2E -count=30`) before relying on it fully.

**A residual, lower-rate completion-timing flake, same test, unresolved.**
Independent of the race above: repeated `-race` runs of the full
`TestE2E_*` suite (`-count=10`) showed `TestE2E_RestartRecoversInterruptedVerification`
occasionally (~1 in 10–15 runs under that specific heavy back-to-back
repetition, not observed in isolated or lightly-repeated runs) finishing in
under 2 seconds with "expected exactly one finding ... got 0" — i.e. the
scan reached `ScanCompleted` without the post-restart verification having
actually produced a Finding yet. This was true before this phase's
`createMu` fix and is still true after it, so it is not the same bug. Not
root-caused: plausibly a completion-policy race specific to restart recovery
under heavy `-race` scheduling overhead (the monitor may see "no job queued/
leased/running" become true a tick before a just-requeued verify job's
result is persisted), but this is a hypothesis, not a diagnosis. Classified
as an accepted limitation for now — rare, needs artificially heavy repeated
iteration to observe, and the restart-recovery behavior itself (the thing
e2e_recovery_test.go exists to prove) passes reliably in normal use — but it
should be root-caused before relying on restart recovery under real
concurrent production load.

# P0 slice 1 — local scope-boundary validation

Base: `36d6d4496a25019395261967a8fc9310865a8f0b`, branch
`fix/xss-scope-verdict-auth`. Uncommitted bounded slice; no staging, commits,
pushes, branch changes or AGENTS.md writes. Verdict/auth/UI audit findings are
untouched. See [browser-scope-boundary.md](browser-scope-boundary.md) for the
implemented boundary and compatibility limits.

All logs below are under:
`/home/udalah/.hermes/cache/scratch/indago-p0-fixes/`.
Lab drivers are under:
`/home/udalah/Documents/Developments/indago_lab/p0-fixes/`.

## Observed RED, then GREEN

| Run / exact command | Exit / observation | Log |
|---|---|---|
| `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test ./internal/browser -run '^TestIntegrationScopeGate(RejectsUnmanagedTargets\|ManagedFramesAndSubresources)$' -v -count=1` (before production edits) | **1**; late anchor, closed-shadow anchor and late form each sent one initial redirect request and one forbidden `/outside` request; ordinary anchor already passed | `slice1-red.log` |
| `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test ./internal/browser -run '^TestIntegrationScopeGate' -v -count=1` | **0**; every scoped popup initial/destination counter zero, every unscoped control actually hit its destination | `slice1-green.log` |
| `go test ./deploy -run '^TestCIRuntimeRejects' -v -count=1` (before required roots added) | **1**; missing/skipped/failed new roots/children were incorrectly accepted | `slice1-preflight-contract-red.log` |
| `go test ./deploy -run '^Test(CIContract\|CIRuntimeRejects)' -v -count=1` | **0** after wiring required inventory | `slice1-preflight-contract-green.log` |
| `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test ./internal/browser -race -run 'Test(IntegrationScopeGate\|IntegrationRequestObserverDoesNotWaitForResponse\|IntegrationNavigateJSON\|IntegrationCancellation\|.*Close\|.*ClosesResourceCreated)' -v -count=3` (before local dependency patch) | **1**; real popup denial exposed `newPage` / `Request.safePage` race inside Playwright's `Route.Abort`; scope counters themselves were zero | `slice1-race.log` |
| Same browser race selection, `-count=5`, after dependency patch | **0**, 111.70 s; scope, pending response/close, cancellation and lifecycle selections | `slice1-race-green.log`, `.exit.json` |
| Nested module: `go test -race -count=10 ./...` | **0**; deterministic early-frame publication-reader regression | `slice1-dependency-race-green.log` |
| Nested module: `go test -overlay /home/udalah/Documents/Developments/indago_lab/p0-fixes/upstream-race-control-overlay.json -race -run '^TestEarlyFramePagePublicationReaders$' -count=1 -v` | **1**, expected; reverting only accessors to upstream via overlay reproduces the race; no production rollback | `slice1-dependency-upstream-control-red.log` |
| `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test ./internal/browser -race -run '^Test(NewContextClosesResourceCreatedAfterCancellation\|ContextNewPageClosesResourceCreatedAfterCancellation\|CloseReturnsPromptlyDespiteAWedgedDriver\|ContextCloseUntracks\|CleanupClosesContexts)$' -count=20 -v` | **0** | `slice1-lifecycle-stress.log` |
| `go test ./deploy -run '^TestDockerContract$' -v -count=1` before allowing local dependency in Docker context | **1**, expected missing allowlist; fixed `.dockerignore` and covered by final gate | `slice1-docker-context-contract-red.log` |

The first RED is behavioral and uses the original production implementation,
not missing-symbol/compilation errors. Managed redirect/frame/subresource and
body-replay tests are compatibility coverage, not claims of newly found bugs.

## Required gates and build

- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`: **exit 0**,
  239.38 s (`slice1-make-check.log`, `.exit.json`). Some unrelated packages
  were cached; browser and scan packages ran against the local replacement.
- Same exact `make check` rerun after Docker-context contract change:
  **exit 0**, 6.80 s (`slice1-final-make-check.log`, `.exit.json`); unchanged
  packages cached, changed deployment contract reran.
- Exact `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome python3
  scripts/ci-browser-check.py`: **exit 0**, 117.55 s; **all 26 required roots
  passed, no skipped roots/descendants** (`slice1-browser-preflight.log`,
  `.exit.json`). This includes the two existing source/sink matrices and the
  default-on real renderer sandbox checks.
- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags
  browser_integration -race -p 1 -count=1 -v ./internal/verification -run
  '^TestIntegrationVerifyJSONPOST'`: **exit 0**; five real-browser JSON tests
  including execution/safe response, both redirect policies and saved-session
  cookies (`slice1-json-compatibility.log`, `.exit.json`). Form/JSON exact body,
  media type and cookie-preserving positive tests also ran in scope race/preflight.
- `go mod verify`, `git diff --check`: **exit 0**. Copied-runtime hash manifest
  differs from upstream in exactly `frame.go`, `request.go`, `page.go`.
- `make build` + `./bin/indago version`: **exit 0**, final rebuilt binary
  `36d6d44-dirty`, base commit `36d6d44`, build time
  `2026-10-19T05:16:54Z`. The live run used the same production code built at
  `05:06:39Z`; its exact executable SHA256 is retained in
  `slice1-live-server.process.json`. Later changes were tests/docs/build-context
  packaging, not browser implementation.

## Actual binary CLI/controller run

Owned fixture: `127.0.0.1:43549`, PID 564094.
Owned browser-enabled server: `127.0.0.1:57605`, PID 605989.
Chromium sandbox **on** (`slice1-live-server.log`), no opt-out, no proxy,
no auth secrets, no state-changing scanner opt-in. Target scripts themselves
contain the popup/form regression triggers; scanner automation was not taught
to click target controls.

Actual CLI: project create → scope set/show (`127.0.0.1`, include `/api/`,
exclude `/outside`) → target add → scan create/start/status → endpoint/finding
readback. Extent: `-profile fast -quick -max-pages 1 -max-endpoints 2
-candidate-profile minimal -max-candidates 1`; configured shared rate 50 req/s.
Exact commands/stdout/statuses: `slice1-live-cli.json`.

Scan: `97b6c220-b6e2-4d97-a9d5-e9b90bf547f1`.

- Completed, 2 endpoints (1 seed, 1 browser-network fetch), 25 succeeded jobs,
  zero failed/dead, 20 completed successful test cases, 5 explicit irrelevant
  source skips (four absent storage-key probes and one absent query selector on
  the neutral control endpoint). Skip details:
  `slice1-live-outcome-classification.json`.
- 1 reflected-XSS Confirmed positive, exact marker
  `ind0c044a85f107dbc5`; browser log bytes read back as
  `playwright: ind0c044a85f107dbc5 is not defined`.
  This is a compatibility positive, not a verdict-provenance fix or accuracy
  claim. No verdict code was changed.
- Destination readback: **GET `/api/page`=20**, **GET `/api/control`=21**;
  all three `/api/popup-*` initial destinations and `/outside` **zero**.
  The counters endpoint was read independently, not inferred from observations.
- API and SQLite raw finding detail/verdicts matched; all **35** evidence rows
  checked for stored size/SHA256 and exact API-download bytes. Readbacks:
  `slice1-live-status.json`, `slice1-live-findings.json`,
  `slice1-live-db-findings.json`, `slice1-live-db-tests.json`,
  `slice1-live-readback.json`, `slice1-live-counters-readback.json`.
- `slice1-live-verify.exit.json` and `slice1-live-readback-green.exit.json`:
  **exit 0**. Initial readback helper used the wrong evidence-root prefix and
  failed (`slice1-live-readback.log`); corrected to `data/evidence` and reran
  against real bytes. The initial summary grouped empty outcomes separately;
  the later read-only classification explicitly resolves them as skipped status.

## Cleanup and remaining limits

Both tracked long-lived processes were stopped. Independent readback:
`slice1-cleanup.json`: both PIDs absent, no members of either owned process
group, **118** distinct recorded loopback listener ports checked closed
(including RED/GREEN/race/preflight fixtures). No blanket process kill/prune,
no recursive data deletion; evidence and disposable no-secret data retained.
All tracked gates finished; none left running.

**NOT VERIFIED / deferred:** full uncached `go test -tags browser_integration
-race -p 1 ./...` is left for the parent's combined final gate, explicitly
per this slice's authorization. No hosted CI, Docker image build/runtime,
Internet target, external proxy, full OOPIF/worker/protocol matrix, UI journey,
or exhaustive Chromium-network isolation claim. The Docker packaging change
is contract-checked only. Blank popup objects may survive until context close;
all popup HTTP(S) requests are denied rather than supported. The local patched
runtime is maintenance overhead until a pinned upstream release fixes early
page publication. Other audit findings require subsequent slices.

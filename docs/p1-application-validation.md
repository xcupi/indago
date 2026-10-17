# P1 application-behavior validation

## Transient startup overrides

Startup only writes a config template when `config.json` is absent. The
snapshot is taken before any serve overrides; an existing file is never
rewritten (including unknown fields/formatting). Runtime address/rate/burst,
TLS paths, browser/AI flags, and environment secrets are not persisted.
Stored settings/defaults apply on the next start. P0 token/TLS/bind policies
are unchanged.

- TDD RED: `TestServeOverridePreservesExistingConfigBytes` failed with the
  runtime port written into the config, unknown field dropped, formatting
  replaced. GREEN: same real `cmdServe` startup test passed after fix.
- Regression tests: new template with TLS/token/rate overrides keeps defaults,
  explicit `-api-rate 0`, existing custom config, invalid rate/burst/TLS/remote
  flags leave config unchanged. Tests drive startup to an occupied-port bind
  failure, not a stub of the config logic.
- Live rebuilt binary with disposable data: custom saved `127.0.0.1:45221`,
  first run `-addr 127.0.0.1:50357 -api-rate 0 -api-burst 3` returned health
  200. Config remained byte-identical (SHA256
  `1736aa601bb34e118056e27d7e0f8792fa04f151321dca13a3cf4606ad18c313`).
  After stopping, restart without overrides returned health 200 on **45221**.
- New data: override port 33473 returned health 200; saved template retained
  `127.0.0.1:8750`, rate 50, burst 200. Did not need to occupy default port or
  disturb any existing process.
- All three owned server processes exited after SIGTERM; each port refused
  a fresh connection. Task dummy data/scripts/binary removed at final cleanup.

## JSON request-body limit

All seven JSON-consuming handlers use the same typed-error mapping. The
complete request body is read through `http.MaxBytesReader` (1 MiB inclusive),
then decoded as exactly one document; whitespace counts toward the limit.
Memory/read size is bounded. Unknown fields stay disallowed; public shapes
are unchanged. Oversize is 413 with `JSON body exceeds 1 MiB limit`; malformed
or read errors return 400 with `invalid JSON body`, never raw parser/body
content. An unavailable feature/missing parent can still fail its prerequisite
before parsing; no guards or instrumentation wrappers changed.

- RED/GREEN 1: oversized project returned 400 instead of 413; typed error
  mapping passed the same test.
- RED/GREEN 2: early valid object plus >1 MiB whitespace returned 201;
  bounded whole-body read made it 413.
- RED/GREEN 3: a second small document returned 201; requiring EOF made it 400.
- RED/GREEN 4: six remaining handlers returned 400 for oversize; shared
  mapping made all seven pass. Additional regression tests cover exact
  1 MiB (201), limit+1 (413), malformed/second-document/trailing-garbage
  400, reader failures and secret-free errors.
- Live rebuilt binary on disposable loopback port 33341: project, scan,
  report creation each returned **201 normal, 400 malformed, 413 oversized,
  413 early-valid + padding, 400 second document**. Lists read back after
  rejected bodies had unchanged counts. Created report list returned 200.
  No scan was started; target port 9 was only dummy metadata.
- Owned server exited and port refused connections after SIGTERM.

## UI 429 recovery

Exact policy is documented in `deployment.md`, “UI recovery from throttling.”

- TDD RED/GREEN: first numeric 429 produced no waiting status/recovery; the
  same controlled-clock test passed after shared cooldown + bounded retries.
  Subsequent assertion REDs reproduced HTTP-date early retry, raw/non-actionable
  POST errors, 50 duplicate requests for one URL, stale route retries/results,
  four simultaneous pending polls, late old-route rendering, project selection
  cleared on load failure, and initial scan throttling mislabeled as missing.
  Each was fixed before the next tracer bullet. A regression test caught the
  Refresh control being shown on ordinary static settings; fallback now applies
  only to a failed/throttled load, preserving the normal behavior.
- `TestUICooldownClock` invokes 20 Node built-in tests (no npm dependency)
  with controllable time: seconds/date/invalid/missing/negative/huge headers,
  clamp boundaries, GET/HEAD recovery, three-attempt ceiling, POST once plus
  fail-fast during cooldown, coalescing, navigation during fetch/body-read,
  unchanged auth/CSRF/body, one 401 token prompt then 429, and no secret echo.
  This clock suite skips if Node is unavailable; Node v26.7.0 ran it here.
- Go real-Chromium tests additionally verify poll coalescing, route isolation,
  throttled initial-load retry controls, normal navigation and token-mode
  sandboxed evidence. The full web suite is included in `make check`.
- **Live rebuilt binary + local Chromium** (`/usr/bin/google-chrome`, isolated
  scratch Python Playwright 1.64.0): `-api-rate 1 -api-burst 1`, dummy bearer
  mode active. Setup used `/healthz` only before the browser so it did not
  consume API budget. Actual version 200, projects 429→200, scans 429→200,
  scan status 429→200. Measured post-429 request gaps were **1.0031, 1.0024,
  1.0058 seconds** for `Retry-After: 1`. Visible waiting banner recovered
  automatically to a populated dashboard at approximately 3.06 seconds.
- Browser-intercepted dummy paths using real UI helpers: numeric header
  retried after **1.0062s**, HTTP-date after **2.3293s**, invalid header after
  **2.0050s**, two attempts each. POST 429 sent once, returned a safe actionable
  error, and did not replay. Clock tests cover persistent 429 exhaustion.
- On the same live token-mode server, a genuine API-generated HTML report
  rendered with visible “Indago Scan Report” in `iframe[sandbox=""]`, opaque
  origin; protected download bytes matched the API exactly. No UI page errors
  and no token in rendered body. Existing Go evidence-viewer regression passed.
- Nonsecret evidence retained outside the repo at
  `/home/udalah/.hermes/cache/scratch/indago-p1-results/`:
  `ui-results.json`, `ui-429-waiting.png`, `ui-429-recovered.png`,
  `ui-token-protected-viewer.png`. Final live listener port 42483 closed after
  the owned server exited. A first harness run put a localStorage init script
  inside the sandbox; it was corrected to top-frame-only and rerun cleanly.

## Quality gates and limits

Each of the three commits is preceded by
`INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`: gofmt clean,
`go vet ./...`, `go test -race -p 1 ./...`, exit 0. Go reused unchanged-package
cache entries; changed command/web packages ran. No scanners/guards disabled.

Not verified here: cross-browser/multi-tab cooldown coordination, a prolonged
load/soak test, or new TLS certificate behavior (unchanged; P0 validation covers
TLS). CI and Docker were separate work. Protected `AGENTS.md` was
not edited. All task dummy data, logs, downloaded report, scripts, binary and
scratch venv were removed after validation; only the nonsecret results above
remain.

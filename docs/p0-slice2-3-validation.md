# P0 slices 2 and 3 — verdict provenance, attempt isolation, authenticated crawl

Base: `36d6d4496a25019395261967a8fc9310865a8f0b`, branch
`fix/xss-scope-verdict-auth`. Uncommitted work on top of the uncommitted slice 1
([p0-slice1-validation.md](p0-slice1-validation.md)); no staging, commits or
pushes, no AGENTS.md writes. Contract: [verdict-provenance.md](verdict-provenance.md).

Logs: `/home/udalah/.hermes/cache/scratch/indago-p0-fixes/`. Lab drivers:
`/home/udalah/Documents/Developments/indago_lab/p0-fixes/` (`run_s23_gates.sh`,
`live_fixture.py`).

## Observed RED, then GREEN

| Defect | RED observed on | GREEN |
|---|---|---|
| DOM: thrown `ReferenceError` naming the marker on a safe sink was `Confirmed` | original code at `36d6d44` in a clean worktree, `s2-dom-red-baseline-36d6d44.log` | `s2-dom-green.log` |
| DOM: forged harness-prefixed console report plus thrown error without any sink was `Confirmed` | same | same (now a visible "untested" probe error) |
| DOM: execution inside a child frame labelled a top-level sink `Confirmed` | same | same (`Inconclusive`) |
| DOM: storage key `b` `Confirmed` from key `a`'s leftover payload | same; also `s2-dom-mid-provenance-only.log` | same (fresh browser context per selector) |
| DOM: fragment route parameters `a` and `b` collapsed into one finding | same; unit RED in terminal | same (selector in dedup key) |
| Reflected: forged marker exception, console-only marker | audit probes at `36d6d44` (see readiness report); verdicts now asserted exactly (`Inconclusive`, `Rejected`) | `s2-verification-tagged-2.log`, final gate |
| Authenticated discovery sent 3 requests to logout-looking URLs (2 crawler, 1 content discovery) | terminal output, new `logout_fetch_test.go`; not saved to a log file | discovery package green |
| Stale `?token=` in the endpoint URL beat the refreshed token (reflection and candidate) | terminal output, new `dynamic_params_test.go`; not saved to a log file | green |

Controls proving the new tests are not vacuous: a genuine `innerHTML` sink and a
genuine reflected payload stay `Confirmed`; an operator seed and an anonymous
scan still request logout-looking URLs; an ordinary query value already in the
URL is still kept as observed.

## Regressions found while doing this, and fixed

- First draft of `hasUnattributedMarkerException` flagged **every** error on every
  reflected page: the CDP exception description includes the stack, and the stack
  carries the page URL, which carries the payload and so the marker. Found by
  `TestIntegrationVerifyUnrelatedPageErrorDoesNotConfirm` going `Inconclusive`
  (`s2-verification-tagged-0.log`); only the first line is compared now.
- Playwright wraps the init script, so the exact-equality identity check never
  matched and engine-attributed reports were empty (`TestDOMXSSPostMessage...`
  failed). The identity check is an exact match against the wrapped form.
- My rewrite of `probeDOMXSSCandidate` dropped the storage "attacker-control
  caveat" note. Caught by the required preflight (`run1-before-timer-contract-fix/`,
  both source matrices, all storage rows). Restored.
- `TestDOMStringTimerNativeContract/*-reporting-failure` simulated a reporting
  failure by overriding `console.log`. The harness now captures the natives
  before any page script runs (so a page that silences `console.log` cannot hide a
  reachable sink), which made that injection ineffective. The test now injects
  the failure through `String.prototype.indexOf`; its intent (a reporting failure
  must not change native timer semantics, 0 reports) is unchanged.

## Independent static review (`deleg_cc736f58`) and disposition

- **B1 fixed.** Bare-CR line mapping let a forged `throw` be paired with a marker
  placed where an LF-only split pointed. V8 line terminators are now used. Unit
  cases plus a real-Chromium test (`TestIntegrationRejectCarriageReturnLineMappingForgery`).
  The engine-level RED was **not** observed against the old splitter (it was
  replaced before that test existed); the unit case encodes the reviewer's exact
  exploit.
- **B2 fixed.** Marker-less exceptions no longer cost source fetches or budget;
  pausing stops after the first genuine hit; script metadata budget 256 → 8192
  and exceeding it no longer flips the page to unavailable; `Available` can no
  longer be overwritten during enable. Tests: error/script flood still `Confirmed`,
  `setInterval` string throwing every tick still `Confirmed`.
- **B3 fixed.** Docs corrected (sitemap index, budgets, overclaims); this file
  exists.
- Also fixed: harness captures natives; unknown main frame or child-frame
  execution is `Inconclusive`; initial main frame via `Page.getFrameTree`;
  in-flight handler wait before a read; report dedup; nested sitemap URL is
  scope-checked and guarded; `_` is a separator in the logout heuristic; an empty
  refreshed token no longer erases the URL's token; negative tests assert exact
  verdicts and live provenance.
- Not addressed: pages that use `debugger;` (every statement pauses and resumes;
  not measured); `isInstalledInitScript` is tied to the vendored driver's wrapper
  (a mismatch surfaces as an "untested" error only when harness-shaped console
  output exists); redirect-to-logout, query-string logout and CamelCase logout
  names; lexer recall cost (`Inconclusive` for unusual but genuine shapes).

## Gates on the final tree

All three exit 0 (`s23-*.exit.json`):

- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`: exit 0. The final run
  took 2 s because every package was cached (the last change was a tagged test
  file). The uncached run on the preceding tree took 251 s, exit 0.
- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome python3 scripts/ci-browser-check.py`:
  exit 0, 142 s, **all 36 required roots passed, no skips** (26 from slice 1 plus
  10 new). `deploy` contract tests prove each new root fails the preflight when
  missing, skipped or failed.
- `go test -tags browser_integration -race -p 1 -count=1 ./...`: exit 0, 429 s,
  all 21 packages `ok`, no `FAIL` and no `DATA RACE`.
- `gofmt`, `go vet ./...` (plain and `-tags browser_integration`) and
  `git diff --check` clean.

## Real binary, owned fixtures

`./bin/indago version` → `36d6d44-dirty`. `serve -browser`, sandbox on, no opt-out,
anonymous. CLI: project create → scope set (`127.0.0.1`) → target add → scan
create (`-profile fast -max-pages 10 -max-endpoints 12`) → start → status →
finding list/show. Scan `573bc338-6f68-4d29-ac09-e35dd407251c`:

- completed; 119 jobs succeeded, 0 failed/dead; tests 105 success, 0 error, 15
  skipped (irrelevant sources); 7 endpoints, 27 parameters.
- `confirmed`: Reflected XSS `GET /reflect?q`, DOM XSS `location.search q → innerHTML`
  at `GET /dom?q`. `rejected`: `GET /safe?q` (escaped), `GET /forged?q`.
- The DOM finding's note carries the attribution caveat ("execution is proven by
  the engine, the sink label … is not proven to be the executing code path") and
  its browser-log evidence carries the engine provenance record.

Limits of this run: it did not exercise the forgery paths (the planner does not
generate a forging candidate for an escaped page, and `textContent` is not a
hooked sink); those are covered by the integration tests. It was anonymous, so
the authenticated crawl guard is covered by tests only.

Cleanup: fixture (pid 1282289, :18971) and server (pid 1282299, :18970) stopped;
both ports and pids verified gone (`s23-live-cleanup.json`). Disposable data kept
in `s23-live-data/`, no credentials.

## NOT VERIFIED

- Mutation checks for two small tests (sitemap-index guard, empty-token guard):
  the mutation command timed out waiting for approval and was not run, so those
  two tests were never seen to fail. Likewise no RED was observed for the
  harness native-capture change.
- Hosted CI, Docker image build or runtime, any Internet target, any real-world
  site's script count or pause rate against the budgets.
- Live authenticated scan with a real logout link (guard proven by tests only).
- Per-sink attribution of execution (documented limit), postMessage delivery by a
  real attacker window, storage poisoning.
- A scratch git worktree of `36d6d44` used for the RED runs still exists at
  `~/.hermes/cache/scratch/indago-p0-fixes/baseline-wt` and is registered in the
  repository's worktree list; it was not removed because deleting it recursively
  needs your explicit approval.

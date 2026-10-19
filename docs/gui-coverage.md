# GUI readiness and coverage transparency

A scan that finishes with zero findings can mean two very different things:
the target was tested and nothing was found, or most probes never ran. The
dashboard now says which one it was. Nothing here changes a verdict; it only
reports what was and was not tested.

## What the server reports

`GET /api/capabilities`

| field | meaning |
|---|---|
| `browser_enabled` | the server was started with `-browser` |
| `browser_sandbox` | Chromium sandbox on (off with `-browser-no-sandbox`); false when the browser is off |
| `state_changing_allowed` | `-allow-state-changing`; POST/PUT/PATCH/DELETE candidates are sent |
| `interactive_login` | an interactive-login function is wired (needs the browser) |

A `Server` that never calls `SetCapabilities` reports everything off. The UI
treats an unreadable response as "capabilities unknown", never as "on".

`GET /api/scans/{id}/coverage`

Groups the scan's skipped tests by reason and reports warnings:

- `browser_disabled` (high): DOM probes did not run and nothing could be
  confirmed in a browser. Zero findings is not a clean result.
- one warning per skip reason that is not informational (for example
  `state_changing_disabled`, `verification_unsupported`, `other`)
- `tests_errored`: tests that ended in an error or a timeout are untested, not
  negative
- `jobs_failed`: failed or dead jobs

`coverage_gaps` is true when any high or medium warning exists. Skips with
severity `info` ("this endpoint had no query parameter for that DOM source")
never count as a gap, so a normal scan does not show a permanent alarm.

`GET /api/scans/{id}/tests`

The per-test log: class, result, method and URL, HTTP status, and the note
explaining a skip. Filters: `status`, `outcome` (comma list), `reason`.
Paging: `limit` (default 100, capped at 500) and `offset`. The engine's opaque
`Detail` blob is never returned. Notes are clipped to 500 characters.

`GET /api/scans/{id}/explorer`

What discovery FOUND, joined to what ran. The test log lists tests; this lists
endpoints and parameters, so a discovered parameter that never got a test is
visible instead of absent. Filters: `gaps=1`, `q` (URL substring), `method`;
paging: `limit` (default 50, capped at 200) and `offset`. Endpoints with gaps
sort first. `summary` always covers the whole scan, `total` the filtered list.
(`GET /api/scans/{id}/endpoints` is the older plain list and is unchanged.)

Each parameter and each DOM source gets one status:

| status | meaning |
|---|---|
| `tested` | at least one test completed |
| `skipped` | every test was skipped; `reason_code` says why |
| `errored` | tests ran but ended in an error or timeout |
| `not_run` | nothing ran: no job, job dead/failed/canceled, or job never produced a test |
| `partial` | some tests completed but the job behind them did not finish (dead, canceled, or still queued after the scan ended). A completed test does not prove the job finished: storage key discovery completes, then a per-key probe fails |
| `pending` | the scan is still running and the work is queued (not a gap) |

`gap` is true for `errored`, `not_run` and `partial`, and for `skipped` unless the
reason is informational. A job that failed and was retried to success is
`tested`: only the job's final state counts, not an earlier errored attempt. Queued work only counts as a gap once the scan has ended.

How the joins work, because they decide what "tested" can mean:

- Reflected tests carry `TestCase.InjectionPointID`; an injection point maps to
  one parameter. That is per parameter.
- DOM probes are one job per (endpoint URL, source) and are deduplicated by URL,
  so DOM coverage is per page and per source, never per parameter. Two
  endpoints with the same URL share the same DOM jobs.
- A fragment-route parameter is not an injection point. Its status is the
  `location.hash` DOM source of the same URL.
- Only GET/HEAD pages get DOM probes. A POST endpoint with no DOM entry is not a
  gap. A GET page with no DOM job on an ended scan is.

`GET /api/scans/{id}/coverage` also carries `parameters` totals, and these
warnings so that it can never read cleaner than the explorer:

- `scan_failed` (high) and `scan_canceled` (medium): the scan did not finish, so
  whatever it recorded is partial even if every recorded test passed
- `tests_incomplete`: cancelled or never-finished test cases on an ended scan.
  `tests.total` always equals completed + skipped + failed + incomplete
- `parameters_untested`: errored, never-run or partial parameters on an ended scan
- `dom_sources_untested`: errored, never-run or partial DOM source probes,
  including a GET page no DOM job was ever scheduled for
- `coverage_unavailable`: the explorer could not be built. This fails closed
  instead of dropping the warning

Skipped work is not repeated; its skip reason already is. The UI only says
"all tested" or "no gaps" when nothing is pending, and a running scan is never
shown as clean.

## Skip reasons

`classifySkip` (internal/web/coverage.go) maps the free-text note an executor
writes to a stable code. The notes are the only record of why a probe was
skipped, so the mapping depends on their wording. Two tests guard that:
one pins each known note to its code, and one fails if an executor in
internal/scan stops writing a pattern the classifier relies on. A note nobody
anticipated becomes `other` with medium severity; it is never dropped.

## What the dashboard shows

- Overview: readiness chips (browser engine, sandbox, state-changing methods,
  interactive login), then the coverage warnings, then a link to the Coverage tab.
- Coverage tab: skipped probes grouped by reason with the fix, and the test log
  with filters (All, Tested, Skipped, Errors/timeouts), a reason filter and paging.
- Scan header: a "coverage gaps" badge next to the state when there are gaps.
- New scan form: a warning before Start when the browser engine is off; advanced
  options (candidates, proxy pool, performance, stop policy) are folded; login
  modes that need the browser say so when it is unavailable.
- The header and its Pause/Cancel/Resume controls follow the scan's state. They
  used to stay on "running" after the scan had finished.
- A finding's title is a real button (focusable, `aria-expanded`) instead of a
  clickable table cell.
- Endpoints tab: summary, "with gaps only" filter, URL search, paging, and rows
  that open to show every parameter and DOM source with its reason. Open rows
  survive live refresh.
- The project-level Findings table, the test log, the reasons table and the
  explorer stack at phone width instead of overflowing.

## Not covered

- The coverage view reports what the scan recorded. A probe that was never
  planned (for example an endpoint the crawler did not find) does not appear.
  Discovery limits are shown on the Discovery tab, not here.
- Skip reasons are classified from note text. A reworded note degrades to
  `other` until the classifier is updated.
- The explorer joins to recorded tests and jobs. It cannot show a parameter that
  discovery never registered, and "tested" means a test completed: a reflection
  test that found nothing counts, and later candidate failures do not undo it.
- DOM coverage is per page and source; which query parameter or storage key a DOM
  probe tried is not recorded in a joinable form.
- Authenticated-scan state (session expired, a request that landed on a login
  page) is not part of coverage yet.
- UI tests are real-browser tests against a seeded store. The explorer was also
  checked against two real scans by recomputing every parameter's status straight
  from SQLite; those scans had no errored, skipped or never-run parameters, so
  those states are covered by seeded tests only.

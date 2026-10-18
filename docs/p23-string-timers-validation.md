# P2.3 — bounded primitive-string timers

## Delivered boundary

Based on `3a3f8730847d8ffff656594afcfe695b310576dd`, on
`feat/p23-dom-string-timers`. This work adds exactly two DOM sink identities:
`setTimeout` and `setInterval`. It adds no source, domain schema, candidate
category, activation, eval/Function wrapper, location/src sink, WAF path,
protocol/trust/scope default, transport redesign or sandbox-policy change.
`AGENTS.md` was read but is protected: the parent's separately approved boundary
edit is preserved and was not modified or staged by this implementation.
The implementation handoff was **uncommitted** for independent parent review;
parent checks are recorded below, with final publication/remote CI supplied in
the delivery summary. P2.2 records remain historical HTML validation.

## Design and deterministic proof

The pure planner accepts only known sources/sinks and a nonempty bare ASCII
identifier marker (not supplied code, JS literals/keywords or undefined/NaN/Infinity).
For the two timers, the complete verification candidate is just `MARKER`, a
benign JavaScript expression. Existing HTML payloads remain exactly
`<img src=x onerror=MARKER>`. Existing `dom_xss` Candidate shape, builtin source,
source/sink context fields, named selector and dedup provenance are reused.
Timer rationale describes native scheduling, bounded observation, cancellation,
CSP/Trusted Types and page-error proof; storage rationale retains the manual
attacker-poisonability caveat. Planning remains deterministic and immutable.

A pre-navigation init script wraps each window timer with a **strict** function:

1. Call the captured native function first, using the exact original receiver
   and all original arguments. Strictness preserves null/undefined receivers.
2. Only after success, observe argument zero if `typeof handler === 'string'`.
3. Return the identical native timer ID. Native exceptions are not intercepted
   or replaced. Observation failures cannot replace a successful native return.

There is no second object coercion. Function handlers, boxed strings,
TrustedScript objects and other non-strings pass unchanged and are not observed
as string sinks. The harness never invokes a callback, evaluates handler code,
converts a string handler to a function, schedules an extra timer, changes a
delay, accelerates/reschedules execution, changes cancellation, or bypasses
CSP/Trusted Types. Scope/network/session/pacing code is unchanged.

Reachability remains insufficient for confirmation. Only the exact marker's
unresolved-identifier **browser page error** confirms; arbitrary console output,
including exact forged `ReferenceError: MARKER is not defined`, is evidence only.
Timer browser logs additionally retain the observed sink and exact primitive
string value, attributed alongside screenshot/DOM evidence to the verification
TestCase. No verdict matcher was weakened.

The existing observation window remains load plus ordinary bounded readback,
with the existing short postMessage settling only. It is not a general timer
waiter. A 60-second delayed timer is observed as reachable but not confirmed;
this is a timing coverage limit, not proof that it can never execute.

## Actual vertical TDD

Logs are retained in `/home/udalah/.hermes/cache/scratch/p23-results/`.
These are observed assertion failures, not compilation failures:

| Slice | RED, actual exit 1 | GREEN, actual exit 0 |
|---|---|---|
| setTimeout pure plan | `01-timeout-plan-red.log`: no timer candidate | `03-timeout-plan-green.log`: complete detection package |
| setTimeout real browser | `04-timeout-browser-red.log`: zero findings | `05-timeout-browser-green.log`: native execution and evidence |
| setInterval pure plan, after timeout worked | `06-interval-plan-red.log`: no timer candidate | `07-interval-plan-green.log`: complete detection package |
| setInterval real browser | `08-interval-browser-red.log`: zero findings | `09-interval-browser-green.log`: both timer execution tests |
| timer evidence attribution | `17-timer-evidence-red.log`: exact hook value missing from browser log | `18-timer-evidence-green.jsonl`: all 52 matrix cases under race |
| required CI wiring | `13-ci-wiring-red.log`: timer matrix missing from required script | `14-ci-contract-green.log`, actual preflight below |

`02-timeout-plan-green.log` is intentionally retained as a **failed** initial
package run: the new timeout planner passed, but an older HTML test still listed
setTimeout as out of scope. Only that newly authorized exclusion was removed;
eval/Function/location/src exclusions remain. No compiler error is called RED.
Native contracts, source matrix and control-plane coverage initially passed;
those coverage-only tests are not presented as additional behavioral RED.

## Native differential/spy contracts

`TestDOMStringTimerNativeContract` contains exactly **30 cases**, fifteen for
each timer. Each runs a native baseline and a hooked document with comparable
ordering: one init script installs a transparent native-entry spy, then the
optional scanner harness. It never relies on ordering between separate
AddInitScript registrations.

Each timer covers receiver/all arguments/exact returned ID, original function
identity and real callback behavior/receiver/extra arguments, delay coercion
exactly once, object handler coercion once without observation, boxed strings,
exact thrown handler and delay sentinels, invalid receiver and missing-argument
native errors, null/undefined receivers, clearTimeout and clearInterval including
shared-ID cancellation, canceled callbacks, TrustedScript identity/native behavior,
and Symbol-handler errors. Every case checks native-call count, so duplicate
scheduling cannot pass. Callback/object/boxed/TrustedScript/failed-call controls
must produce no string-sink reports. Event-loop checkpoints use captured native
timers; there are no arbitrary sleeps or enlarged production waits.

`10-native-contract.jsonl` passed all thirty cases immediately. The complete
uncached tagged race gate re-exercises these contracts.

## Required real-browser source matrix

`TestDOMStringTimerSourceMatrix` has exactly **52 scenarios**:

- 14 required positive pairs: both timers × all seven existing sources;
- 14 safe JS-string-literal/non-executing-code negatives;
- 14 exact forged-runtime-console negatives;
- canceled, CSP-blocked string evaluation, function callback only,
  origin/source-rejecting postMessage and delayed controls for **each** timer.

All safe/forged controls must create the correctly attributed finding and finish
payload verification, not succeed on an undiscovered selector or skipped source.
The CSP fixture legitimately allows its page script by nonce while prohibiting
unsafe-eval. Canceled/CSP/delayed controls are reachable and Rejected; callback
and rejected-message controls have no string-sink reachability. Regression
assertions independently prove native callback execution and real receipt and
rejection of an opaque non-self message sender. All required TestCases complete
successfully. The matrix does not relax old HTML/Range insertion controls.

Source realism:

- decoded fragment; discovered `timer_query` via URLSearchParams;
- window.name set before navigation on the same tab;
- existing sandboxed opaque-origin srcdoc sender, **never self-post**;
- absolute document.referrer, with the application extracting and decoding only
  `new URL(document.referrer).pathname.slice(1)` before using it as JavaScript;
  executing the entire absolute URL would not be meaningful marker JS;
- actual native `getItem('timer_profile_note')` and
  `getItem('timer_tab_note')` reads select custom storage keys.

Storage execution after a scanner-only isolated write does not establish
attacker poisonability. No new source or synthetic default key is introduced.

## Control-plane and old HTML regression

`TestDOMStringTimerControlPlane` exercises both timers through current
`Controller.defaultHandlers` helpers with a real browser, configured lab proxy
and dummy session state. Consuming the shared limiter then canceling before the
next permit yields DeadlineExceeded and zero target/proxy requests. An explicitly
out-of-scope endpoint fails permanently before any request. Successful canary and
payload navigations both use the proxy and session cookie; the target's denied
subrequest never reaches the proxy. Source/sink and hashed evidence attribution
are checked. Dummy session material stays temporary and is not retained.

`12-control-html-regression.jsonl` passed the timer control-plane test, existing
seven-navigation limiter/storage observation controls, proxy/session/referrer/
scope controls, `TestDOMHTMLSourceMatrix` (46 scenarios), and Range native,
detached and innocent-sibling controls under race. There is no shared browser or
transport redesign. Pacing remains one permit per explicit navigation, not per
browser-generated subresource/redirect; request scope still gates those requests.

## Production CLI/server/controller validation

Real binary, real project/scope/target/scan, normal discovery/queue/controller
and Chromium `/usr/bin/google-chrome`; no fake executor or SQLite writes.
Binary: `indago 3a3f873-dirty`; precise version/hash is in `binary.json`.
One live scan, not repeated scans until green:
**`24f3a357-514f-422f-83fb-2d30c4aacb5d`**.

Owned target `127.0.0.1:18771` served **52 scenario routes plus one neutral
origin/index root**, exactly 53 total. Scanner API: `127.0.0.1:18772`, disposable
`/home/udalah/.hermes/cache/scratch/p23-lab/data`. The launch harness removed
inherited auth/AI/token settings without printing values. Base live validation
used no credentials or storage-state file.

```sh
./bin/indago serve -browser -chromium /usr/bin/google-chrome \
  -data /home/udalah/.hermes/cache/scratch/p23-lab/data -addr 127.0.0.1:18772
export INDAGO_SERVER_URL=http://127.0.0.1:18772
./bin/indago project create 'P2.3 owned string timer matrix'
./bin/indago scope set -project PROJECT_ID -include 127.0.0.1
./bin/indago target add -project PROJECT_ID -name 'owned p23 loopback' -url http://127.0.0.1:18771/
./bin/indago scan create -project PROJECT_ID -target TARGET_ID \
  -name 'P2.3 53-route corpus' -profile fast -candidate-profile minimal \
  -depth 1 -max-pages 53 -max-endpoints 53 -stop continue_all
./bin/indago scan start SCAN_ID
./bin/indago scan status SCAN_ID
./bin/indago endpoint list -scan SCAN_ID -json
./bin/indago finding list -scan SCAN_ID -verdict all -json
./bin/indago finding show -scan SCAN_ID FINDING_ID
```

Finite lab caps are per scan, not changes to defaults or production limits.
Actual commands/IDs and exact API readbacks are retained in `cli-transcript.log`,
`ids.json`, project/scope/target/scan readback files and `status.json`.

### Required positive pair inventory: expected versus actual

Every row represents three distinct live scenarios and three regression cases.
Both paired negatives reach the selected sink and finish real verification.

| Source | Sink | Positive expected → actual | Safe expected → actual | Forged expected → actual |
|---|---|---|---|---|
| location.hash | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| location.search | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| window.name | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| postMessage | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| document.referrer | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| localStorage | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| sessionStorage | setTimeout | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| location.hash | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| location.search | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| window.name | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| postMessage | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| document.referrer | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| localStorage | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |
| sessionStorage | setInterval | Confirmed → Confirmed | Rejected → Rejected | Rejected → Rejected |

For **each timer**: canceled, CSP-blocked and delayed expected Rejected → actual
Rejected; callback-only and rejecting-message expected unreachable → actual no
finding with completed reachability-negative tests. Root: expected no finding →
actual none. No control was Confirmed. The complete 52-row explicit inventory,
expected/actual, source, sink, selector, marker and evidence IDs is retained in
`expected.json`, `scenario-outcomes.csv` and `live-verification.json`.

### Independent readback and accounting

`20-live-run.log` and `21-live-verification.log`: actual exit **0**. CLI/API/raw
read-only SQLite independently agree:

- **53 endpoints, 165 parameters and 165 injection points**;
- **589 succeeded jobs**, including **371 DOM jobs**, exactly seven per endpoint;
- zero queued/leased/running/failed/canceled/dead jobs, retries or retained errors;
- **508 completed/success tests**, zero error/timeout/cancelled/running tests;
- **141 explicit irrelevant-source not-tested skips**: 47 absent query names,
  47 absent localStorage keys and 47 absent sessionStorage keys; none substitutes
  for a required source/control verification;
- **14 Confirmed, 34 Rejected, zero Inconclusive/Pending findings**.

All 48 findings were read through CLI list/show and API. Raw base64 API Detail
matches raw SQLite Detail; every displayed projection field was independently
checked. Marker is recomputed from scan/endpoint IDs, not inferred loosely.
Each finding's exact source/sink/selector/bare payload, native hook report,
page-error signal where positive, verification TestCase and screenshot/DOM/
browser-log attribution were checked. Message evidence retains origin null and
non-self source; storage findings retain manual attacker-control caveats.

**All 910 scan evidence rows**, not just positives, were downloaded through the
API and compared byte-for-byte with their stored files, metadata size and SHA256.
This includes all **42 positive browser evidence rows**. Every retained copied
blob was independently rehashed again before cleanup. Duplicate content-addressed
paths can have multiple metadata rows; retained per-ID copies total **611,938
bytes**. Readback was paced at 25 requests/s below the unchanged API limit, with
no retry-until-success. No SQLite record was inserted, updated or deleted by a
validation harness.

## Gates and CI

Required CI roots are now eight, preserving the HTML matrix and adding exactly
`TestDOMStringTimerSourceMatrix`. Missing/skipped/failed roots and skipped/failed
descendants of any required root fail preflight. Nine synthetic parser-contract
streams test rejection rules explicitly; these are unit fixtures, not fabricated
browser results. The real preflight is exercised separately.

- `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check`: exit **0**, log
  `22-make-check.log` (standard race tests; tagged matrices excluded).
- Initial full tagged race invocation hit the **terminal's 360-second timeout**
  (tool exit 124), not a test failure. Its preserved `23-full-tagged-race.jsonl`
  contains no failed events; the scan package had passed in 309.69 seconds and
  verification was still running. The tool killed the command. A tracked
  background gate with streamed logs removes the tool timeout, without changing
  tests, assertions, scanner limits or rerunning a failing test until lucky.
- Final full uncached tagged race: exit **0**, **384.05 seconds**, log
  `24-full-tagged-race.jsonl` and its `.exit.json` manifest; **691 top-level
  tests/fuzz roots, 1,184 tests-and-subtests, 21 tested packages, zero test skips
  or failures**. Two additional packages have no test files, not skipped tests.
  Both matrices (46 HTML / 52 timer) and all 30 native contracts passed.
- Final actual `python3 scripts/ci-browser-check.py`: exit **0**, **82.03 seconds**,
  `26-final-ci-browser-preflight.log` and exit manifest; all **eight required
  roots / 106 tests-and-subtests**, zero skips/failures. `preflight-counts.json`
  records the exact roots, and `test-counts.json` records JSON-suite accounting.
- Extra uncached standard race/counting run (no browser_integration tag): exit
  **0**, **288.32 seconds**, `27-standard-race-counts.jsonl`; **669 top-level
  tests/fuzz roots / 1,000 tests-and-subtests**, 21 tested packages, zero test
  skips/failures. This provides explicit ordinary-suite counts; the earlier
  make check output contains some cached packages and no verbose test events.
- Final `make build`: exit **0**, `28-final-build.log`; executable reports
  `indago 3a3f873-dirty (commit 3a3f873, built 2026-10-18T01:59:56Z)`.
  `binary-final.json` records its size/SHA256 separately from the live-run binary.
- Offline retained-state verifier: exit **0**, `25-retained-verification.log`;
  independently checks all 52 scenarios, 14 pairs, 48 raw API/SQLite finding
  snapshots, job/test accounting and all 910 copied evidence rows after cleanup.
  Parent can rerun `verify_retained.py` without the deleted fixture/database.

## Retention and cleanup

Safe results/snapshots/harnesses are outside the disposable fixture:
`/home/udalah/.hermes/cache/scratch/p23-results/`. Evidence files are under
`evidence/`; metadata and verification are in `db-evidence.json` and
`evidence-verification.json`. Raw finding/job/test/endpoint snapshots, full
expected/actual tables, CLI transcript, logs and independent cleanup proofs are
retained. They contain no credentials, private keys or auth-state contents.
P2.2 artifacts were neither modified nor removed.

Owned target PID **3294425**, listener **18771**; scanner PID **3294434**,
listener **18772**. `owned-identities.json` records all eleven live owned tree
identities with PID/start ticks; `listeners-before-cleanup.json` records exact
listeners. Only those two verified root identities were sent SIGTERM. Scanner
exited **0**, target **-15**. `cleanup-independent.json` independently proves all
eleven recorded identities absent and both ports closed and bindable. After all
910 retained blob checks, only `/home/udalah/.hermes/cache/scratch/p23-lab` was
removed (`cleanup-data.json`); deletion is independently checked separately.
No broad kill/prune, user Chrome manipulation, host service, external target,
commit, staging, push, PR or merge occurred.

## Remaining limits / NOT VERIFIED

- Arbitrary long timers, execution after the current observation window, JS
  string-literal breakouts, worker timers and all input transformations are not
  promised. A delayed timer's non-Confirmed result is not a lifetime safety claim.
- Non-string native behavior is preserved but not string-sink reachability
  coverage. TrustedScript identity is regression-tested, not every enforced
  Trusted Types deployment, policy callback or browser engine.
- Storage attacker poisonability, every sender topology/allowlist/CSP setup,
  authenticated production flows, TLS differentials, throughput/load and
  cross-browser behavior are not established by this loopback corpus.
- Existing first-reachable-sink, GET/HEAD, discovered-query and bounded storage
  selector limits remain. Old Range transient/delayed/shadow-tree/insertion
  limits are unchanged. Skipped selectors are not clean negatives.
- Existing Playwright sandbox policy is unchanged and is not newly hardened.
- Parent independent checks are recorded below. Publication/final-remote-SHA CI
  remain delivery gates, not facts inferred from the child implementation.

## Parent independent verification

The parent verified all fifteen task-file handoff hashes against the reviewed
worktree and the exact protected AGENTS.md hash against the already approved
parent edit. It read the planner, production hooks, native/source/policy tests,
CI parser contracts and validation record before publication.

The parent reran real Chromium with `-tags browser_integration -race -count=1`
for the timer planners/execution tests, both timer-specific browser suites and
policy controls, the old HTML matrix and deployment/CI contracts: exit 0,
52 timer matrix cases, 30 native contracts, 46 HTML matrix cases and both timer
policy controls passed, with no failed or skipped test events. Logs:
`parent-targeted-race.jsonl` and `parent-targeted-summary.json` in p23-results.

After reviewing the retained-state verifier, the parent reran it and independently
checked all fourteen positive exact timer sink/payload reports, all 910 retained
evidence sizes/hashes, 52 scenario expectations, API/CLI/SQLite snapshot agreement,
job/test accounting and both source/sink inventories. The original scratch DB
and API server had already been removed/stopped; these are preserved readbacks,
not a claim of new queries against that deleted DB or a second live scan.

It independently confirmed all eleven recorded PID/start-tick identities absent,
both owned ports 18771/18772 closed and independently bindable, and the exact
p23-lab fixture directory absent. Full uncached tagged/ordinary gate logs were
parsed independently: 691/669 top-level roots respectively, no test skips or
failures, with initial handoff source hashes matching those tested files.
Independent review and exact final commit/remote CI outcomes are reported in the
delivery summary rather than predicted in this pre-publication record.

### Review follow-up

Independent static review found no blocking security or logic issues. Two
non-blocking suggestions were addressed without expanding the inventories:

- Unreachable diagnostics now say `no implemented DOM-XSS sink reachable`, not
  HTML-only wording. Four real-browser callback/rejected-sender controls first
  failed the new diagnostic assertion, then passed after this text-only engine
  correction (`parent-diagnostic-red-detailed.log`). An initial log-check harness
  expected text hidden by a pointer-only test message; its failure is retained
  in `parent-diagnostic-red.log`, and the test now prints the exact diagnostic.
- The existing receiver/argument/return-ID native contract also installs a
  throwing `console.log`. Native IDs and all argument assertions still pass;
  observation failure cannot replace a successful native return. This coverage
  passed immediately against the existing catch-protected reporter, not an
  invented behavioral RED. The contract inventory remains thirty cases.

The parent reran all 52 timer scenarios and 30 native contracts under real
Chromium/race/count=1: 82 cases passed, zero failures or skips
(`parent-review-followup-green.jsonl`). The original live scan predates only
this diagnostic correction and test refinements; its native hooks, planner and
verdict logic are unchanged. Final gates run on the publication worktree.

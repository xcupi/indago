# P2.2 — seven-source HTML-method validation matrix

## Scope and outcome

Coverage-only follow-up on `feat/p2-dom-html-sinks`, starting at
`27cc5f2d1ea6ff831e5fe3c7a6056e83cfa1e864`. No production code, source, sink
category, payload, verdict rule, browser limit, authorization or transport policy
changed. Existing tests remain intact. No genuine engine bug was found, so no
behavioral RED was manufactured and no production fix was needed.

P2.2 supersedes **only the hash/query-only positive-validation limit** in
[`p21-html-sinks-validation.md`](p21-html-sinks-validation.md). That report's
historical runs, failures, fixes and other limits remain accurate and unchanged.
`AGENTS.md` is protected and was not edited.

## Real-browser regression matrix

New file: `internal/scan/domxss_html_source_matrix_integration_test.go`.
`TestDOMHTMLSourceMatrix` has **46 table scenarios**, below the 65-scenario ceiling:

- 14 required positive source/sink pairs;
- one escaped negative and one exact forged-runtime-console negative per pair
  (28 controls, giving 42 required cases);
- two postMessage origin/source-rejecting controls, one per sink;
- Range detached-fragment and innocent-text-sibling-only insertion controls.

All 46 passed without test skips, initially against the unchanged engine, and
again in the uncached full tagged race suite. Every positive requires exactly
one Confirmed finding, correct source/sink/selector, actual marker-specific
`playwright: TOKEN is not defined` page error, DOM marker handler, and
screenshot/DOM/browser-log metadata whose file bytes match size and SHA256.
Range additionally requires marker-handler connection evidence. Escaped and
forged negatives must reach the hook and **complete verification** with two
finding attempts, successful test cases and a Rejected verdict; a missing
query/storage selector cannot satisfy these controls. Forged cases must really
log `ReferenceError: TOKEN is not defined` without the page-error signal.

PostMessage uses the existing sandboxed opaque `srcdoc` sender, never self-post.
Positive/escaped/forged DOM evidence records origin `null` and a non-self source.
Each rejecting regression additionally delivers a real payload through that
same sender and independently asserts the handler received and rejected it,
without hook reachability or marker execution. Range sibling control asserts
that the innocent prefix actually was inserted while no marker connection was
reported. All existing policy/native/source/opaque-message tests remain intact.

## Actual binary / CLI / server / controller run

Built with `make build`: `indago 27cc5f2-dirty`, commit `27cc5f2` (the dirty
worktree contains this coverage/docs slice). Binary version and SHA256 are in
`p22-results/binary.json`. Real Chromium: `/usr/bin/google-chrome`.

The owned target served **46 routes total** on `127.0.0.1:18761`: 45 scenario
routes plus the neutral index/origin root. The server used scratch data only:

```sh
./bin/indago serve -browser -chromium /usr/bin/google-chrome \
  -data /home/udalah/.hermes/cache/scratch/p22-lab/data \
  -addr 127.0.0.1:18762
```

The environment-only server/CLI harness removed inherited Indago auth/AI/token
settings without printing values. No credentials or state files were supplied.
The real CLI created project, explicit `127.0.0.1` scope, target, and scan, then
read the exact records back. Configuration was fast/minimal, depth 1, 46-page and
46-endpoint caps, `continue_all`, unchanged fast-profile 50 req/s / 4 browser
workers. No scan reconfiguration or production limit change was used.

```sh
export INDAGO_SERVER_URL=http://127.0.0.1:18762
./bin/indago project create 'P2.2 owned HTML source matrix'
./bin/indago scope set -project PROJECT_ID -include 127.0.0.1
./bin/indago target add -project PROJECT_ID -name 'owned p22 loopback' -url http://127.0.0.1:18761/
./bin/indago scan create -project PROJECT_ID -target TARGET_ID \
  -name 'P2.2 46-route corpus' -profile fast -candidate-profile minimal \
  -depth 1 -max-pages 46 -max-endpoints 46 -stop continue_all
./bin/indago scan start SCAN_ID
./bin/indago scan status SCAN_ID
./bin/indago endpoint list -scan SCAN_ID -json
./bin/indago finding list -scan SCAN_ID -verdict all -json
./bin/indago finding show -scan SCAN_ID FINDING_ID
```

Actual IDs and expanded commands are retained in `ids.json` and
`cli-transcript.log`. Scan: **`44be6b62-f74f-4b6c-a74a-d7be5e95a02a`**.
There was one live scan, not repeated scans until green.

### All 14 positive outcomes and paired controls

Each row below is independently represented in regression tests, live API
records, CLI list/show, read-only SQLite records, and the generated CSV/JSON.
`C=1` means exactly one Confirmed finding; each escaped/forged route had zero
Confirmed and exactly one Rejected finding.

| Source | Sink | Positive, expected → actual | Escaped, actual | Forged console, actual |
|---|---|---|---|---|
| location.hash | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| location.search | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| window.name | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| postMessage | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| document.referrer | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| localStorage | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| sessionStorage | insertAdjacentHTML | C=1 → C=1 | Rejected | Rejected |
| location.hash | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| location.search | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| window.name | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| postMessage | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| document.referrer | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| localStorage | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |
| sessionStorage | Range.createContextualFragment | C=1 → C=1 | Rejected | Rejected |

Query uses discovered `matrix_query`. Storage keys are custom, page-observed
native `getItem('matrix_profile_note')` / `getItem('matrix_tab_note')` reads,
not assumed defaults. Referrer is a realistic absolute URL whose entire value
is decoded with `decodeURIComponent`; the sink receives the URL prefix followed
by markup. It is not a network request to the reserved `.invalid` host.

Live sender-reject routes produced no findings for either sink, with completed
reachability-negative tests. The live detached Range route was Inconclusive,
with the explicit insertion-not-observed note and no connection report. The root
produced no findings. Innocent-sibling-only insertion was exercised in the
regression matrix, **not as an additional CLI route**.

### Exact completion/error/skip accounting

API status and independent read-only SQLite aggregation agree:

- **46 endpoints, 144 parameters, 144 injection points.**
- **512 succeeded jobs**, including **322 DOM jobs**: exactly one job for every
  endpoint and every existing source, checked programmatically.
- **0 queued, leased, running, failed, canceled or dead jobs**; all jobs had one
  attempt and no retained job error.
- **447 successful/completed tests**, **0 error, timeout, cancelled or running**.
- **120 skips**: 40 query-source cases with no discovered query name, 40
  localStorage cases with no present/read key, 40 equivalent sessionStorage
  cases. These are irrelevant-source **not-tested** diagnostics, not clean
  negatives. None belongs to a required source/control verification above.
- **14 Confirmed, 28 Rejected, 1 Inconclusive, 0 Pending findings**;
  **zero unexpected Confirmed controls**.

The intentional broken-image requests can log HTTP 404 resource errors. They
are the canonical marker handler's trigger, not failed scanner jobs or test
errors. No unexpected execution errors remained to classify.

### Independent record and artifact checks

`run_live.py` and `verify_live.py` are preserved outside the deleted lab. The
verifier compares the complete expected route inventory to actual outcomes in
`scenario-outcomes.csv` and `live-verification.json`, not mental counts.

All 43 finding records were read through the API and CLI list/show, with
independent read-only scratch SQLite finding/job/test/endpoint queries. Raw API
`detail` matches SQLite exactly; the displayed `parsed_detail` is intentionally
a projection and its displayed fields were checked against the stored record.
Source, sink, named selector, browser provenance, verification TestCase IDs,
and storage manual-attacker-control caveats were checked.

**All 42 positive screenshot/DOM/browser-log rows** were downloaded through the
API and independently read from stored filesystem paths, requiring equal bytes,
metadata size and SHA256, matching scan/verification attribution, real runtime
signal and DOM handler. All seven Range positives include the exact sink value
and `connected:true` for the canonical marker handler; both message positives
retain opaque/non-self sender DOM metadata. The same checks covered negative
artifacts too: **122 browser evidence rows total**. The nonsecret copied files
and per-row integrity results remain in `p22-results/` after lab deletion.

## Commands and gates

All commands used Chromium `/usr/bin/google-chrome`. True exit codes were
captured directly with subprocess or shell status, never hidden by grep/tail
pipelines. `-json` preserves individual test outcomes.

```sh
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^TestDOMHTMLSourceMatrix$' -count=1 -json
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^Test(DOM(Policy|InsertAdjacentHTML|CreateContextualFragment|XSSSourceSelection|XSSPostMessage)|SelfPostFalsePositiveControl)' -count=1 -json
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration -race -p 1 ./... -count=1 -json
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check
make build
python3 /home/udalah/.hermes/cache/scratch/p22-results/run_live.py
python3 /home/udalah/.hermes/cache/scratch/p22-results/verify_live.py
```

- Targeted matrix: **exit 0**, 46 leaf scenarios, no skips.
- Existing controls: **exit 0**, 16 top-level tests / 48 tests-and-subtests,
  no skips.
- Full uncached tagged race suite: **exit 0**, 683 top-level tests /
  1083 tests-and-subtests, 21 tested packages, zero test skips or failures.
  Go additionally reports two packages with **no test files**, not skipped tests.
- Standard `make check`: **exit 0**; gofmt and vet pass, ordinary race test
  results were cached. This is not presented as another uncached browser run.
- Build: **exit 0**. CLI live harness: **exit 0**. Final readback verifier:
  **exit 0**. Exact timings/results are in `gates.json` / `test-counts.json`.

### Harness failures retained, not scanner fixes

No regression/gate or live scan failed or was rerun until lucky. Validation
harness development did encounter these errors, retained rather than hidden:

1. Two initial inline Python preparation/preflight commands had literal `\\n`
   SyntaxErrors before executing their actions. Replaced with script files or
   proper multiline code (`harness-setup-errors.json`).
2. First readback assertion incorrectly compared the lossy presentation
   projection to full SQLite Detail. Corrected to compare raw API Detail exactly
   and validate every projected field (`live-verification-first-schema-error.log`).
3. Unpaced evidence readback hit the unchanged API's HTTP 429 limiter. Added
   deterministic 25 req/s readback pacing, not retries or a server-limit change
   (`live-verification-second-readback-429.log`).
4. A connection assertion initially assumed sink input equaled the bare payload
   for referrer too. The fixture decodes the entire absolute URL. Corrected to
   require that exact prefix-plus-payload value, preserving the connection guard
   (`live-verification-third-referrer-shape.log`).
5. An early test-log summary treated Go's two no-test-file package events as
   test skips; corrected by distinguishing package from test events. Actual
   tests and exit statuses were unchanged (`test-counts.json`).

These were explicit readback/analysis harness corrections against the **same**
completed scan, not altered scanner behavior, weakened verdict assertions or
silent scanner retries.

## Retained artifacts and cleanup

Nonsecret evidence/harness/logs are under the ephemeral scratch directory:

`/home/udalah/.hermes/cache/scratch/p22-results/`

Key files: `matrix.jsonl`, `controls.log`, `tagged-race.log`, `make-check.log`,
`build.log`, `gates.json`, `test-counts.json`, `binary.json`, `run_gates.py`,
`target-fixture.py`, `run_live.py`, `verify_live.py`, `expected.json`, `ids.json`,
`cli-transcript.log`, `status.json`, `status.txt`, `findings-api.json`,
`findings-cli.json`, `finding-*-cli.txt`, `db-findings.json`, `db-jobs.json`,
`db-test-cases.json`, `db-endpoints.json`, `scenario-outcomes.csv`,
`live-verification.json`, `evidence-verification.json`, `skips-by-reason.json`,
`unexpected-errors.json`, per-route PNG/HTML/log files, server/target logs,
and the retained harness-failure logs above. No credentials/cookies/private
keys/auth-state contents were created or exported.

Owned roots: target PID **2870126**, port **18761**; scanner server PID
**2918060**, port **18762**. Their 11-process owned tree was recorded by exact
PID/start-time identity. SIGTERM stopped those roots only; the server exited 0,
target exited by SIGTERM. All recorded processes were independently verified
absent; both exact ports were closed and bindable. Evidence was copied first,
then **only** `/home/udalah/.hermes/cache/scratch/p22-lab` (including its dummy
SQLite data/fixture) was removed. A separate command verified its deletion.
Proof: `cleanup-owned-identities.json`, `cleanup-processes.json`,
`cleanup-independent.json`. No broad kill/prune, production DB mutation, service,
Docker rebuild, release, branch switch, commit, push, PR or merge occurred.

## Remaining limits / NOT VERIFIED

- Storage execution after an isolated scanner write does **not** establish an
  attacker's ability to poison that key; manual exploitability review remains.
- Opaque-origin postMessage is not every real sender topology, object/message
  format, allowlist or CSP deployment. This tests serialized string data from
  an opaque non-self sender, not all origins or trusted sender compromises.
- Object, boxed-string and TrustedHTML inputs preserve native behavior but are
  not primitive-string reachability coverage. No new Trusted Types/CSP
  deployment or cross-browser validation was performed.
- Range's existing observation window can miss delayed insertion, transient
  insert/remove, unobserved shadow trees, or transformations into unrelated
  nodes. Detached runtime errors alone are insufficient. The innocent-sibling
  case is regression-tested but was not an additional CLI route.
- Existing first-reachable-sink, GET/HEAD and query/storage selector bounds
  remain. No absent/unobserved key or undiscovered query name is called safe.
- No eval/Function, location/src, string-timer, encoding/mXSS, Stored XSS, new
  source, automatic click/exploitation, external target, authenticated production
  flow, TLS differential, benchmark or load promise is verified by this slice.

## Parent verification and publication

The required CI runtime preflight now also selects `TestDOMHTMLSourceMatrix`
with `-tags browser_integration`. Missing/skipped/failed matrix execution, including
skipped matrix subtests, fails the preflight rather than silently excluding the
new tagged tests. A deployment contract assertion first failed because the
matrix/tag were absent, then passed after wiring. Running the actual preflight
locally passed all seven required top-level tests, including all 46 matrix
scenarios. These CI/support changes do not modify scanner production behavior.

The parent independently reran the 46-scenario matrix with real Chromium,
`-race` and `-count=1`: exit 0, all 46 leaf cases passed, no failures or test
skips. It independently checked the complete seven-source/two-sink inventory,
all 45 live scenario expectations, 122 retained artifact sizes/SHA256 values,
positive marker/source/sink attribution, Range connection and message-sender
proof, matching raw API/SQLite snapshot details for all 43 findings, exact
job/test totals, and cleanup of all 11 owned process identities and both ports.
The original scratch database was already removed; this parent record review
uses the preserved readbacks, not a claim to have queried that deleted DB.

Independent diff review, publication and final-SHA CI are delivery gates; their
final result/commit/URL are supplied in the delivery summary rather than guessed
before publication. Publication does not merge any prerequisite or PR into main.

### Publication exposed an older referrer fixture race

The first P2.2 push, `4ea53b7`, passed the CI runtime preflight but failed the
clean-cache standard race gate in
`TestIntegrationNavigateRefererReachesDocumentReferrerRealBrowser`. The full
failure is retained at
https://github.com/xcupi/indago/actions/runs/39082671407. This is not a successful
remote gate and is not discarded by rerunning it unchanged.

The server handler wrote a plain shared string while the test read it without
Go synchronization. The handler also recorded every request, allowing favicon
requests to overwrite the document's Referer. A 20-repetition local real-browser
race run reproduced the same write/read stack. The fixture now records the root
document only and uses initialized `atomic.Value` storage for every write/read;
the exact HTTP Referer and rendered `document.referrer` assertions are unchanged.
A 100-repetition real-Chromium race run passed with no failures or skips. The
follow-up changes test code and this provenance record only, not the scanner,
verdict policy, browser limits or security boundaries.

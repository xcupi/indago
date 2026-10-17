# P2.1 — bounded HTML-method sink validation

## Change and dependency

P2.1 adds exactly `Element.prototype.insertAdjacentHTML` and
`Range.prototype.createContextualFragment` to the existing HTML sink category;
no source or other sink category is added. The prerequisite merge checkpoint is
`a542334` on `feat/p2-dom-html-sinks`, integrating P1 HEAD `45d0e53` and DOM
branch HEAD `659d51b`. This does not merge either prerequisite into main.

The merge retains shared pacing, Referer threading, per-hop cookie matching,
strict runtime matching, session/scope/evidence policy and the prior TLS fixes.
DOM source and storage-observation navigations now share the scan limiter and
DOM contexts select from the scan's proxy pool. Pacing remains one permit per
explicit browser navigation, not browser-generated subresources/redirects.

Both new hooks invoke native first with the original receiver and every
argument, return the same result and let native exceptions propagate. Only
successful primitive-string HTML arguments are observed; objects/TrustedHTML/
boxed strings are not coerced again for logging. See `dom-xss.md` for limits.

## Test-first evidence

Real failing assertions were executed before implementing each method. These
were behavioral failures, not package compilation failures:

| Slice | Observed RED | Observed GREEN |
|---|---|---|
| DOM prerequisite policy | unpaced source/storage navigation; proxy source failed with `ERR_NAME_NOT_RESOLVED` | limiter cancellation prevents target requests; proxy/session/referrer/scope confirmation retains evidence |
| insertAdjacentHTML | hash/query each had `Confirmed=0, want 1`; primitive-string hook report absent | both positives Confirmed; safe/escaped/console controls non-Confirmed; native contract passes |
| createContextualFragment | hash/query each had `Confirmed=0, want 1`; hook report absent | both inserted positives Confirmed; native contract passes |
| Detached fragment | native Chromium emitted a ReferenceError without inserting the image | require target connection of the canonical marker-handler node as well as runtime execution |
| Partial fragment | inserting only an innocent returned text sibling falsely satisfied an any-node insertion check | marker image left detached remains non-Confirmed |
| Forged console runtime error | escaped HTML plus `console.error('ReferenceError: '+marker+' is not defined')` incorrectly Confirmed | DOM confirmation uses page-error observations only; console output is evidence only |

Native contract assertions run in real Chromium and cover receiver identity,
all arguments (including ignored extras), native return identity, exactly one
object coercion, thrown-object identity, invalid receivers, missing arguments,
invalid insertAdjacentHTML position and Symbol conversion errors for Range.
The harness and native-entry spy are installed in one init script to avoid
relying on ordering between separately registered init scripts.

Commands used (Chromium `/usr/bin/google-chrome`):

```sh
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^TestDOMPolicy' -count=1 -v
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^TestDOMInsertAdjacentHTML' -count=1 -v
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^TestDOMCreateContextualFragment' -count=1 -v
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration ./internal/scan -run '^TestDOM(CreateContextualFragment|InsertAdjacentHTML)' -count=1 -v
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome go test -tags browser_integration -race -p 1 ./... -count=1
INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check
```

The prerequisite checkpoint was committed only after its full `make check`.
The sink checkpoint likewise requires both the tagged suite and `make check`.
Default `make check` does **not** include the build-tagged tests.

## Actual CLI/server scans

The real CLI created a project, explicit loopback scope, target and scan; the
real server ran with `-browser` and Chromium. Discovery followed a disposable
lab index's links, with fast/minimal profiles, depth 1, 30-page/endpoint caps,
`continue_all`, and a lab-only 40 req/s configuration. All target content and
data were disposable; authentication/AI/token environment variables were unset
for the lab server. No credentials or certificates were created.

Two independent final-code scans returned identical per-route results:

- `17eb2bd1-48cb-4804-9d54-db1dfb70394e`
- `c83506b4-2bb9-40cd-84b8-10bc74a646f7`

Each discovered 13 endpoints / 41 parameters / 41 injection points, completed
145 jobs with no failed/dead jobs, and recorded 119 successful tests, 37 skips,
no errors/timeouts, 4 Confirmed findings, 6 Rejected and 1 Inconclusive.

| Route | Source / behavior | Expected Confirmed | Actual, each scan |
|---|---|---:|---|
| `/adj-hash` | decoded hash → insertAdjacentHTML | 1 | 1, Confirmed |
| `/adj-query?q=unused` | query `q` → insertAdjacentHTML | 1 | 1, Confirmed |
| `/range-hash` | decoded hash → Range parse + target insertion | 1 | 1, Confirmed |
| `/range-query?q=unused` | query `q` → Range parse + target insertion | 1 | 1, Confirmed |
| `/safe-text` | decoded hash → textContent | 0 | 0, no finding |
| `/adj-escaped` | escaped hash → insertAdjacentHTML | 0 | 0, Rejected |
| `/range-escaped` | escaped hash → Range + target insertion | 0 | 0, Rejected |
| `/adj-console` | escaped markup + raw console.error only | 0 | 0, Rejected |
| `/range-console` | escaped markup + raw console.error only | 0 | 0, Rejected |
| `/adj-forged-console` | escaped markup + forged ReferenceError console text | 0 | 0, Rejected |
| `/range-forged-console` | escaped markup + forged ReferenceError console text | 0 | 0, Rejected |
| `/range-detached` | parse fragment, never insert it | 0 | 0, Inconclusive; explicit insertion-not-observed note |

The root index was also tested and did not Confirm. Counts were checked from
API finding records and independently from the scratch SQLite findings table,
not inferred from scan completion. CLI `finding list/show` was exercised.
Every positive retained its actual marker-specific `playwright: TOKEN is not
defined` error, correct source/sink candidate, screenshot, rendered DOM and
browser log. Range logs additionally contain `connected:true` for the actual
marker-handler element. The positive evidence blobs downloaded through the API
matched their SHA256 metadata. All 64 stored screenshot/DOM/browser-log rows
across the final two scans were independently checked against filesystem bytes,
size and SHA256. Negative-control logs were inspected too: forged console errors
remain Rejected; detached image runtime errors remain Inconclusive with no
connection report.

## Limits / NOT VERIFIED

- Hash and query were positively exercised against **each** new sink, not all
  seven sources. Limiter cancellation covers seven navigation mechanisms plus
  storage observation; that is not seven-source positive detection coverage.
- The existing source-selection/opaque-postMessage tests are also part of the
  tagged suite. Their passing does not establish every new source/sink pairing.
- No attacker-relevant storage poisonability, real external target, production
  authentication, Trusted Types/CSP deployment, cross-browser support, shadow
  DOM insertion, delayed insertion or transient insert/remove behavior is
  established by this loopback run.
- Object/non-string inputs execute native behavior but are not reachability
  coverage. Failed native calls are not sink hits. First-reachable-sink and
  query/storage selector bounds remain unchanged.
- Stored XSS, eval/Function, location/src assignment, string timers, service
  workers/websockets and other sink methods remain out of scope.
- Existing TLS code is unchanged by integration (`git diff 45d0e53 a542334 --
  internal/httpengine go.mod go.sum` is empty). No new live TLS differential,
  sandbox change or proxy-stack redesign was performed for P2.1.

## Cleanup and safe evidence

Only the owned lab/server/browser trees were terminated. Ports 18751 and 18752
were independently checked closed. The exact scratch fixture tree
`/home/udalah/.hermes/cache/scratch/p21-lab`, its dummy SQLite data, lab script
and metadata were removed and their absence verified. No host service, unrelated
browser, Docker resources or other profile was modified. Safe results (test
logs, readback JSON, dummy browser evidence, reproducer source and cleanup PID/
path verification) remain under
`/home/udalah/.hermes/cache/scratch/p21-results/`, outside the deleted fixture.
That cache is ephemeral, not durable artifact storage.

`AGENTS.md` was not manually edited in this work. The prerequisite merge brought
its already-authored version automatically. Proposed protected-file capability
text, requiring fresh parent/user permission before any write:

> DOM-XSS HTML sinks now include innerHTML/outerHTML/document.write/writeln,
> Element.prototype.insertAdjacentHTML and Range.prototype.createContextualFragment.
> The two method hooks observe successful primitive-string HTML arguments only,
> preserve native receiver/arguments/return/errors, and never insert fragments.
> DOM confirmation requires the exact marker-specific browser page-error signal;
> console output alone cannot confirm. Range also requires observed target
> connection of the canonical marker-handler element; detached or harmless-sibling
> insertion is non-Confirmed. Seven source types are implemented with the existing
> query/storage bounds, but P2.1 positively validates hash and query only against
> both new methods; other sink categories and Stored XSS remain out of scope.

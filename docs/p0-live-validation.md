# P0 live validation

## Scope and revision

Validated `d7e602c251ce156af06e89da2a9c74894e2bbd6a` on
`feat/p0-api-auth-tls-retention` (PR #6), using a freshly built executable.
This validates the P0 control-plane features, not scanner detection coverage
or an unrestricted production-readiness claim.

All targets and data were disposable loopback fixtures under the agent's
scratch directory. No primary data directory or real credentials were used.

## Setup and provenance

- Started an actual `indago serve` with native TLS and a randomly generated
  dummy bearer token. Generated a one-day self-signed certificate with
  `127.0.0.1` and `localhost` SANs.
- Created five scans via the real HTTP API using `auth_mode: existing` and
  valid Playwright storage-state files containing a dummy lab session cookie.
  The lab required that cookie. Three scans were actually run to completion;
  two were created as shared-session controls. This does not exercise password,
  interactive, or MFA login.
- Generated five HTML reports through the report API.
- For the sandbox security check, copied the body of a real captured HTTP
  response into a deliberately seeded HTML/DOM evidence record. It contained
  visible text, a script, an inline event handler, parent-access attempts,
  and a network image. This is a viewer-security fixture, not a claim that
  browser verification generated this particular DOM record.
- For retention age/state eligibility, stopped the server first and changed
  only the scratch DB: three old terminal scans and two old non-terminal
  scans. Read the states and timestamps back before pruning. Added an
  out-of-root report traversal canary.

## Retention: real CLI, database, and filesystem

Command shape:

    indago evidence prune -data SCRATCH_DATA -older-than 720h
    indago evidence prune -data SCRATCH_DATA -older-than 720h -apply
    indago evidence prune -data SCRATCH_DATA -older-than 720h \
      -include-sessions -include-reports -apply

Verified by reading files and DB rows back, not merely by checking CLI exit:

| Case | Observed |
| --- | --- |
| Dry run with both include flags | Exit 0; file-content hashes and DB rows unchanged |
| Apply without include flags | Session files and report files/index rows kept |
| Apply with `-include-sessions` | Eligible private session file actually deleted |
| Shared session referenced by a non-eligible scan | File kept |
| Session outside `SessionsDir` | File kept |
| Apply with `-include-reports` | Three eligible HTML report files and index rows deleted |
| Two non-terminal scans | Their session/report files and evidence rows/blobs kept |
| Findings | Rows kept |
| Traversal report row | Refused, row kept, canary outside root unchanged; warning and exit 0 |
| Repeat include apply | Exit 0; no additional file or DB changes |

The existing session metadata row is retained even after its file is removed.
A repeat run may therefore report that session file as `already-gone`; this
is not a second deletion. The test ran offline and does not establish
race-free pruning alongside a running server.

## Sandboxed artifact viewer over HTTPS

Used local, real headless Chromium against the TLS listener with token mode
active. The browser accepted only the disposable certificate's SPKI; it did
not globally disable certificate verification. Separately, the CLI and HTTP
client verified the certificate through the test CA, and a client without
that CA rejected it.

Both evidence HTML and an API-generated HTML report:

- Loaded through `openProtected`, the UI's authenticated fetch/viewer path.
- Visibly rendered as HTML, not source text. Report heading:
  `Indago Scan Report`.
- Were inside `iframe[sandbox=""]`, with no script or same-origin permission.
- Had opaque origins: the console's `iframe.contentDocument` was null;
  artifact access to the parent document and session storage produced
  `SecurityError`.
- Did not run the evidence's inline script/event handler. Chromium logged
  blocked-script messages; there were no sentinel messages, parent DOM
  changes, or external image requests.
- Produced no UI page errors in the successful run.
- Downloaded through the token-mode UI helper with bytes identical to the
  authenticated API response.

The API responses also carried the sandbox CSP. Token values were absent
from rendered console text and `localStorage`.

## TLS, auth, rate limit, and metrics smoke checks

| Case | Observed |
| --- | --- |
| `/healthz` without token | 200 |
| `/api/projects` without / with bearer | 401 / 200 |
| `/metrics` without / with bearer | 401 / 200 |
| HTTPS CLI with `INDAGO_CA_CERT` | `project list` exit 0 |
| HTTPS client without the test CA | Certificate verification failed |
| Plain HTTP request to TLS listener | 400; no successful API response |
| Remote bind without token | Startup exit 1 |
| Remote bind with token but no TLS | Startup exit 1 |
| Short token or cert without matching key flag | Startup exit 1 |
| Remote `-allow-plaintext-remote` opt-in | Started; bearer required; WARN about unencrypted transport |

On a separate TLS run with `-api-rate 2 -api-burst 4`, ten sequential API
requests produced:

    200 200 200 200 429 429 429 429 429 429

All rejections supplied `Retry-After: 1`. `/healthz` stayed 200 during the
flood. After refill, an authenticated scrape reported:

    indago_rate_limited_total 6
    indago_auth_rejected_total 1

The metrics scrape and server logs contained no bearer-token value; the
scrape contained no client IP.

## Limits

- Chromium was tested, not a cross-browser matrix. The iframe CSP attribute
  is Chromium-specific defence in depth; the empty sandbox is the essential
  isolation mechanism.
- This exercised the real UI viewer/download helpers, not every UI link or
  token-prompt interaction.
- No long-running load/soak test, multi-operator isolation test, concurrent
  retention safety test, or certificate-renewal test was performed.
- Original API rate-limit caveats still apply: behind a proxy clients share
  its bucket; forwarded headers are not trusted. UI refresh does not yet
  implement `Retry-After` backoff.
- Evidence retention does not securely erase disks or prune backups.
- The initial validation harness needed correction for the grouped evidence
  API response and top-frame-only test instrumentation; those were fixture
  issues, not product-code fixes. No product code changed in this validation.

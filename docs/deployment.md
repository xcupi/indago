# Indago — Deployment

This covers running `indago serve` outside a local dev loop: binding,
browser/Playwright setup, the on-disk data layout, backup/recovery, and
shutdown behavior. See `AGENTS.md` for the product's scope and safety rules;
this file is operational, not architectural. See
[p1-deployment-validation.md](p1-deployment-validation.md) for actual deployment
checks and the distinction between local and GitHub validation.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes, pull requests and manual dispatch;
it has read-only contents permissions and never deploys/releases. It provisions
Go from `go.mod`, Node 24, the documented Playwright driver and runner system
Chrome. `scripts/ci-browser-check.py` requires six actual passing runtime tests
(no skips), then the workflow runs `go mod verify`, clean-test-cache `make check`
and `make build`. Failure logs are retained for seven days. Locally set
`INDAGO_CHROMIUM_PATH` to your installed Chrome and follow the same commands.

---

## 1. Network exposure — read this first

**The control API (`/api/...`) has an optional bearer token and no per-operator
identity.** Whether it requires a token is decided at `indago serve` startup by
the `INDAGO_API_TOKEN` environment variable:

- **Unset (default):** the API is open to anyone who can reach the port. This is
  the single-operator loopback mode and is unchanged from before.
- **Set:** every `/api/` request must send `Authorization: Bearer <token>`.
  A missing or wrong token gets `401` with `WWW-Authenticate: Bearer`.
  `/healthz` and the static UI stay open so the page can load and prompt for
  the token. The token is accepted only in that header — never in a query
  string or a cookie.

Rules for the token:

- Use at least 32 characters with no whitespace, e.g.
  `export INDAGO_API_TOKEN="$(openssl rand -hex 32)"`. A shorter or malformed
  value makes `serve` refuse to start (the error does not print the value).
- It is read once, at startup, from the environment. It is never a
  command-line flag (shell history, `ps`), never written to `config.json`, and
  never logged or echoed in an error or response.
- The CLI sends it on every request when `INDAGO_API_TOKEN` is set in its
  environment. Without it, a token-protected server answers `401` and the CLI
  says which variable to set.
- The web UI asks for the token on the first `401` and keeps it in
  `sessionStorage` — cleared when the tab closes, never in `localStorage` or a
  cookie. Evidence and report links are fetched with the token too.
- It is one shared secret. There are no per-operator accounts, roles, audit
  trail, or rotation without restarting the server.
- **TLS is native but optional on loopback.** `indago serve -tls-cert FILE
  -tls-key FILE` serves HTTPS (TLS 1.2 minimum). Without them the server speaks
  plain HTTP, which is fine on `127.0.0.1` only. A remote bind **must** use TLS
  (see below); without TLS the token and all API traffic travel in clear text.

### Rate limiting

Every `/api/` request and `GET /metrics` is counted against a **per-client-IP
token bucket**, on by default:

- Defaults: 50 requests/second sustained, bucket of 200 (`-api-rate`,
  `-api-burst`, or `server.api_rate` / `server.api_burst` in `config.json`;
  a flag overrides the config value for that run). `-api-rate 0` disables the
  limiter. A negative rate, or a burst below 1 with a positive rate, is an
  error at startup.
- A refused request gets `429 Too Many Requests` with a `Retry-After` header
  (whole seconds, at least 1) and the body `{"error":"rate limit exceeded"}`.
- The client is the TCP peer address (`RemoteAddr`). `X-Forwarded-For` and
  `X-Real-IP` are **ignored**: any client can send them, so trusting them would
  let one client pick a fresh bucket on every request.
- `/healthz` and the static UI are not limited. The limiter runs after the
  Host/CSRF check and before the token check, so unauthenticated floods are
  limited too. Idle buckets are evicted after 10 minutes; at most 10,000 clients
  are tracked, and clients beyond that are refused rather than growing memory.
- The defaults clear the bundled UI and the CLI. The UI's "1 second" live
  refresh sends about one request per scan per tick on the Scans view (two per
  scan on the Dashboard, for scans with confirmed findings). At that setting a
  project with roughly 25 scans sustains about 50 requests/second. For larger
  projects use a longer refresh interval or raise `-api-rate`.

**Behind a reverse proxy, every client shares the proxy's address and therefore
one bucket.** The server cannot tell the clients apart, so one busy client can
exhaust the budget for all of them. The server will not read forwarded headers
to fix this. If you need per-client limits behind a proxy, enforce them in the
proxy, keyed on the client address the proxy itself sees.

### UI recovery from throttling

The console shares one API cooldown per browser tab across JSON loads,
actions, and protected content fetches. `Retry-After` accepts whole seconds or
an HTTP-date (IMF-fixdate, GMT). Waits are clamped to **1–60 seconds**;
missing/invalid/negative/past-date values use a **2-second fallback**. A
concurrent 429 can extend, never shorten, the current deadline. This is not
cross-browser-tab coordination and does not change the server's IP bucket.

GET/HEAD retry at most **twice** after the original attempt (three total).
POST/PUT/PATCH/DELETE are **never replayed after 429**; an action attempted
during cooldown fails locally without sending, with “Wait for the cooldown,
then try again. The action was not retried.” Existing 401 token prompting and
one authentication retry remain unchanged.

A persistent status banner says “API throttled — waiting …s before retrying
reads.” It clears on the next successful fetch outside cooldown, not on a
blind timeout. Exhausted reads explain the retry limit and offer Refresh;
initial scan-load throttling is not labeled “Scan not found.” Live polls skip
cooldown ticks and drop overlapping refreshes instead of queueing them.
Same-URL JSON loads within a route share one in-flight result; old-route
reads stop retrying/discard late results and cannot render into a new route.
Live polling may initiate a later bounded load after cooldown; with Live off,
use Refresh after an exhausted initial load. Server-provided 429 error bodies
are not copied into banners/action errors.

### Metrics (`GET /metrics`)

`GET /metrics` serves Prometheus text exposition format 0.0.4 (hand-written, no
extra dependency). It exposes:

- `indago_http_requests_total{method,route,code}`: `route` is the mux **pattern**
  (for example `GET /api/scans/{id}`), never the raw path. Requests that match no
  pattern are `unmatched`. Methods outside the standard set are `OTHER`.
- `indago_http_request_duration_seconds{route}`: histogram with fixed buckets.
- `indago_rate_limited_total`: requests refused with `429`.
- `indago_auth_rejected_total`: requests refused with `401` by the token check.
- `indago_build_info{version}`: always `1`.

Access follows the token setting:

- **`INDAGO_API_TOKEN` unset:** unauthenticated, the same as `/healthz`. This is
  acceptable only on loopback, the same rule as the rest of the server.
- **`INDAGO_API_TOKEN` set:** requires `Authorization: Bearer <token>`, as the
  API does. A missing or wrong token gets `401`.

`/metrics` is subject to the rate limit above. A scrape interval of 15 seconds or
more is far inside the default budget.

The output never contains a token, a client IP address, a target URL, finding
content, or an evidence path. Label values come only from the method, the route
pattern, and the status code. No per-scan job counter is exported yet.

Without a token, anyone who can reach the API can:

- create projects/scopes/targets and start scans against whatever target they
  specify (scope is enforced, but the API lets its caller set the scope)
- read every finding, including candidate values and evidence metadata
- fetch evidence **content**, which can include captured session cookies for
  the scanned target (`GET /api/evidence/{id}/content`). Content is served
  under a script-less CSP sandbox, so opening a captured page never runs the
  target's scripts with the console's origin — see
  `docs/finding-correlation.md` ("Opening evidence safely").
- generate and read reports

With a token configured, the same capabilities are available to whoever holds
the token. Keeping the token secret, and the port reachable only by intended
clients, is the actual security boundary.

This is an intentional trade-off for a local-first, single-operator tool, not
an oversight — see `AGENTS.md` §1.

### Secure default

`indago serve` binds `127.0.0.1:8750` by default (`config.DefaultServerAddr`).
A loopback bind is reachable only from the same machine, which is the
intended deployment for a single operator running Indago on their own
workstation or a dedicated scanning host they alone can SSH/console into.

### Binding beyond loopback

Binding any other address — `0.0.0.0`, a LAN IP, `::`, anything
`isLoopbackAddr` doesn't recognize as `localhost`/`127.0.0.1`/`::1` — is
**refused outright** unless you pass `-allow-remote` **and** set
`INDAGO_API_TOKEN`:

```bash
export INDAGO_API_TOKEN="$(openssl rand -hex 32)"
indago serve -addr 0.0.0.0:8750 -allow-remote
```

Either one missing fails fast with an explanatory error instead of starting.
The token is required for remote binds because otherwise any host that can
reach the port would have full control of the API. The goal is to make both
decisions deliberate, not something a log line warns about after the fact.

A remote bind also **requires TLS**: pass `-tls-cert` and `-tls-key` as well.
Without them `serve` refuses to start, because the token would otherwise travel
unencrypted:

```bash
# Throwaway self-signed certificate for a private host. Use a CA-issued
# certificate where you can. Keep the key file readable only by the service user.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /etc/indago/tls.key -out /etc/indago/tls.crt -days 365 \
  -subj "/CN=indago.internal" \
  -addext "subjectAltName=DNS:indago.internal,IP:10.0.0.5"
chmod 600 /etc/indago/tls.key

export INDAGO_API_TOKEN="$(openssl rand -hex 32)"
indago serve -addr 0.0.0.0:8750 -allow-remote \
  -tls-cert /etc/indago/tls.crt -tls-key /etc/indago/tls.key
```

- `-tls-cert` and `-tls-key` are file **paths**, given together. The pair is
  loaded and checked at startup, so a wrong path or a mismatched key fails
  immediately. Errors name the files and never print key material. Startup logs
  the two paths, never their contents.
- A remote bind without TLS is refused. The escape hatch is
  `-allow-plaintext-remote`: it is explicit, off by default, and logs a
  warning that the bearer token travels unencrypted. Prefer TLS.
- Loopback binds are unchanged: plain HTTP is allowed there, and a
  TLS-terminating reverse proxy in front works too.

If you cannot use native TLS, a TLS-terminating reverse proxy, a VPN/SSH tunnel,
or a firewall rule scoped to specific source IPs/users also works. Keep the
token requirement in either case.

**Using the CLI against an HTTPS server.** The CLI reads these environment
variables. None of them is a flag, and none of them takes a secret value:

| Variable | Purpose |
|---|---|
| `INDAGO_SERVER_URL` | Server base URL, e.g. `https://indago.internal:8750`. Default `http://127.0.0.1:8750`. `INDAGO_SERVER` is the older name and is still honoured. |
| `INDAGO_CA_CERT` | PEM file of CA certificate(s) to trust in addition to the system roots: a private CA or the self-signed certificate above. The file is read by path, and its contents are never printed. There is no option to skip certificate verification. |
| `INDAGO_API_TOKEN` | Bearer token, as on the server (§1). |

```bash
export INDAGO_SERVER_URL=https://indago.internal:8750
export INDAGO_CA_CERT=/etc/indago/tls.crt
export INDAGO_API_TOKEN=...   # the same token the server was started with
indago project list
```

Without `INDAGO_CA_CERT`, a self-signed server certificate fails verification,
and the CLI's error says which variable to set.

The web UI runs in the browser, so it trusts whatever the browser trusts. For a
self-signed certificate, import it into the browser's trust store.

Two request-level protections exist regardless of bind address and need no
configuration:
- **CSRF**: every mutating request (anything but GET/HEAD/OPTIONS) must carry
  `X-Indago-Client`, which a browser cannot attach to a cross-origin request
  without a CORS preflight the server never approves; a matching `Origin`
  header, when a browser sends one, is required too.
- **DNS-rebinding guard**: when bound to a specific (non-wildcard) address,
  the `Host` header on every request must name that address or a loopback
  alias; a wildcard bind can't enumerate valid hosts in advance; both bind
  modes keep the CSRF checks above.

Neither is a substitute for the token or for restricting network reach — they
stop a malicious web page from driving the API through your browser, not a
party that can already reach the port directly (`curl` doesn't care about
CORS).

---

## 2. Running the server

```bash
indago db init -data /var/lib/indago          # one-time: creates the DB, migrates, creates evidence/reports dirs
indago serve -data /var/lib/indago             # foreground; Ctrl-C / SIGTERM for graceful shutdown
```

Useful flags (`indago serve -h` or `cmd/indago/main.go` for the full list):

| Flag | Purpose |
|---|---|
| `-data DIR` | Data directory (default `./data`) |
| `-addr HOST:PORT` | Listen address (overrides `config.json`) |
| `-api-rate N` | Per-client-IP sustained requests/second on `/api/` and `/metrics`. Default `50`; `0` disables. Overrides `server.api_rate`. Flag values apply to this run only; they are not written back to `config.json`. Negative is an error (§1, *Rate limiting*) |
| `-api-burst N` | Per-client-IP burst size on `/api/` and `/metrics`. Default `200`; must be at least 1 while the rate is above 0. Overrides `server.api_burst` (§1) |
| `GET /metrics` | Prometheus exposition. Unauthenticated when `INDAGO_API_TOKEN` is unset; needs the bearer token when set (§1, *Metrics*) |
| `-allow-remote` | Allow binding a non-loopback address; also requires `INDAGO_API_TOKEN` and TLS (§1) |
| `-tls-cert FILE` / `-tls-key FILE` | Serve HTTPS with this PEM certificate and key. Give both or neither. Required for a remote bind (§1). Paths, not secret values |
| `-allow-plaintext-remote` | Permit a remote bind without TLS. Off by default; logs a warning that the token travels unencrypted (§1) |
| `INDAGO_API_TOKEN` (env) | Bearer token for the control API; unset = no token (§1). Never a flag |
| `-browser` | Enable browser-based discovery + verification (needs Chromium — §3) |
| `-chromium PATH` | Chromium binary to use (overrides `$INDAGO_CHROMIUM_PATH` / the Playwright cache) |
| `-allow-state-changing` | Also execute POST/PUT/PATCH/DELETE test requests against targets (default: GET/HEAD/OPTIONS only) |
| `-v` | Debug logging |

`indago serve` logs to stderr (structured, via `log/slog`) and never writes
secrets to it (session cookies, API keys, and the like are kept out of log
lines by design — see the hardening report delivered alongside this phase).

### Running as a service

There's no bundled unit file; a minimal `systemd` service looks like:

```ini
[Unit]
Description=Indago
After=network.target

[Service]
ExecStart=/usr/local/bin/indago serve -data /var/lib/indago
Restart=on-failure
User=indago
# The process handles SIGTERM/SIGINT itself (graceful shutdown, §5);
# systemd's default TimeoutStopSec is enough headroom for that.

[Install]
WantedBy=multi-user.target
```

Run `indago db init -data /var/lib/indago` once before the first start (or
let the service user do it — `serve` itself also runs migrations on startup,
so a missing-but-creatable data dir is fine; a missing *parent* directory is
not). Give the service user ownership of `-data`'s directory: everything
Indago writes (database, evidence, reports, config) goes under it, with
owner-only-plus-group file permissions (`0640`/`0750`) — see §4.

### Process model

One `indago serve` process per data directory. SQLite is opened with a
single connection (`SetMaxOpenConns(1)`) deliberately — it's a single-writer,
single-process design (`AGENTS.md` §1's "single-user"); do not point two
`indago serve` processes at the same `-data` directory concurrently.

---

## 3. Browser / Playwright requirements

Discovery and detection work without a browser at all (`-browser` off, the
default): HTTP-level crawling, reflection, context analysis, and candidate
planning need nothing beyond the Go binary itself.

**Browser verification and browser-based discovery (`-browser`) need a real
Chromium-family browser**, driven via `github.com/mxschmitt/playwright-go`
**v0.6201.1**, which uses the Playwright **1.62.1** driver.

**The driver (always required).** Install it once per host:
```bash
go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 --version   # installs the driver only, then prints "Version 1.62.1"
```
This assembles the driver in `~/.cache/ms-playwright-go/1.62.1/` from two
downloads: the `playwright-core` 1.62.1 package from `registry.npmjs.org`,
and Node.js v24.19.0 from `nodejs.org/dist`. It no longer uses Playwright's
retired `/builds/driver` CDN. Mirrors and offline options are set by
environment variable:
- `PLAYWRIGHT_GO_NPM_REGISTRY` and `NODE_MIRROR` point the two downloads at
  mirrors;
- `PLAYWRIGHT_NODEJS_PATH` uses an existing Node.js instead of downloading
  one;
- `PLAYWRIGHT_DRIVER_PATH` or `PLAYWRIGHT_CLI_PATH` use a pre-provisioned
  driver.

Re-run the install after changing the `playwright-go` version in `go.mod`.

**The browser (choose one).**

1. **A system browser (recommended; no bundled Chromium needed at
   runtime).** Pass `-chromium PATH` or set `$INDAGO_CHROMIUM_PATH`, e.g.
   `-chromium /usr/bin/google-chrome`. The driver launches that executable
   instead of a Playwright-managed one, so the browser's version doesn't have
   to match the driver's. Useful when Chrome/Chromium is already provisioned
   (a container base image, a shared CI runner, a workstation).
2. **A Playwright-managed Chromium.** Run
   `go run github.com/mxschmitt/playwright-go/cmd/playwright@v0.6201.1 install --with-deps chromium`.
   This downloads the Chromium build matched to driver 1.62.1 into
   `~/.cache/ms-playwright/` and installs the OS packages it needs
   (`--with-deps`). With no `-chromium`/`$INDAGO_CHROMIUM_PATH` set, Indago
   uses that browser.

History:
- `playwright-community/playwright-go` v0.5001.0 (driver 1.50.1) was
  replaced at the Reliability & Release Gate because of a data race in its
  close path.
- That module's v0.6000.0 (driver 1.60.0) was then superseded by this
  migration to the maintained `mxschmitt` module path. See
  `docs/e2e-validation.md`.

A host provisioned for an older driver needs the install step re-run.

Headless Chromium needs the usual sandboxing/shared-library support most
minimal container base images lack — the `--with-deps` install step above
handles that on Debian/Ubuntu-family images; for other bases install
Chromium's runtime dependencies manually (fonts, `libnss3`, `libatk`, etc.).

Without a usable driver or browser, `-browser` fails fast at startup. A
missing driver reports `run playwright (is it installed? …)`; a bad browser
path reports `Failed to launch chromium because executable doesn't exist at
…`. It's a hard dependency for
that flag, not a silent degrade. Everything else continues to work with
`-browser` simply left off.

Each `indago serve -browser` run launches its own browser pool (sized by a
scan's `browser_concurrency`) and tears it down on graceful shutdown (§5).
Chromium processes are not shared across separate `indago serve` invocations.

---

## 4. Storage / evidence layout

Everything lives under `-data` (default `./data`):

```
<data>/
  indago.db           SQLite database (WAL mode) — projects, scopes, targets,
                       scans, endpoints/parameters, jobs, test cases,
                       findings, evidence METADATA, reports index, sessions
  indago.db-wal        SQLite write-ahead log (present while the DB is in use)
  indago.db-shm        SQLite shared-memory index for the WAL
  config.json          Persisted server config (addr, default profile, AI
                        settings — never a secret value; see §6)
  evidence/
    <scan-id>/
      <kind>/<sha256>.<ext>   content-addressed blobs: captured request/
                               response bytes, screenshots, rendered DOM,
                               browser logs — NOT just metadata; request
                               blobs can contain the target's session cookie
  reports/
    <scan-id>/
      <report-id>.{json,md,html}   generated report files
```

- **The database holds structured records and evidence *metadata* only**
  (kind, media type, size, SHA-256, a relative path into `evidence/`) — never
  blob content.
- **Evidence blobs are content-addressed and written atomically** (temp file
  in the same directory, then renamed into place) specifically so a crash
  mid-write can never leave a truncated blob masquerading as valid evidence
  at its final path.
- **File permissions**: directories `0750`, files `0640` throughout
  (database, config, evidence, reports) — group-readable, not
  world-readable. An interactively-saved auth session (`indago`'s saved
  Playwright storage state, used for `auth_existing` scans) is tightened
  further to `0600` since it's a bearer credential for the *target*
  application. None of this substitutes for OS-level access control: anyone
  with an account on the host and read access to `-data` can still read
  everything in it if they're in the right group or run as the same user.
- **Reports are regenerable**: deleting `reports/` loses only the generated
  files and their index rows, not any source data — `POST
  /api/scans/{id}/reports` rebuilds them from findings on demand.
- **Evidence is not regenerable**: it's the actual captured proof behind a
  finding. Back it up with the database (§5) or accept that findings from a
  lost `evidence/` tree keep their records but lose their supporting
  blobs (evidence IDs that 404 on content, metadata intact).

---

## 5. Backup and recovery

### Backup

Stop the server, or at minimum ensure no scan is actively running, then copy
the whole data directory as a unit:

```bash
tar -czf indago-backup-$(date +%Y%m%d).tar.gz -C /var/lib/indago .
```

Copying `indago.db` alone while the server is running is unsafe — WAL mode
keeps uncommitted-to-the-main-file data in `indago.db-wal`, so a live copy of
just `indago.db` can be missing recent writes. Either stop the process first
(simplest, and what the command above assumes) or use SQLite's own online
backup mechanism (e.g. `sqlite3 indago.db ".backup backup.db"`, which is
WAL-aware) if you need a backup without downtime.

### Restore

```bash
indago serve -data /var/lib/indago-restored   # stopped
tar -xzf indago-backup-20260101.tar.gz -C /var/lib/indago-restored
indago serve -data /var/lib/indago-restored    # restart
```

On startup, `serve` always runs (idempotent) migrations and **restart
recovery** before accepting traffic:

1. **Job recovery** (`Controller.Recover`): any job a previous process left
   `leased`/`running` is requeued — no worker can legitimately hold a lease
   at a fresh process's startup — and `TestCase`s a dead process left
   `running` are marked `cancelled` (their job gets a fresh attempt).
2. **Scan recovery** (`Controller.RecoverScans`): a scan left `running` is
   restored as `paused` (resume it explicitly — `indago scan resume <id>` —
   restart never sends traffic on its own); a scan left mid-cancel has its
   cancellation completed.

Nothing is lost silently: a restored-as-paused scan's discovery state is
preserved, so `resume` picks up where it left off rather than re-crawling.

### Crash consistency, briefly

SQLite is opened with WAL + `synchronous(NORMAL)` + a 5s busy timeout and a
single connection (no cross-connection lock contention). Evidence blobs are
written atomically (§4). Both are specifically about what happens if the
process is killed mid-write, not just mid-request — see the hardening
report for what was verified here.

### Retention: `indago evidence prune`

Evidence is never expired automatically, and request blobs can hold the
target's session cookies verbatim (§6). `indago evidence prune` bounds how long
evidence lives. It reads the data directory directly, so the server does not
need to be stopped.

```bash
# Dry run (the default): lists what WOULD be deleted, deletes nothing.
indago evidence prune -data /var/lib/indago -older-than 720h

# Delete it.
indago evidence prune -data /var/lib/indago -older-than 720h -apply
```

- **`-older-than` is required**, with no default. It uses Go duration syntax
  (`h`, `m`, `s`; there is no `d`), and the minimum is `1h`. `720h` is 30 days.
- **Eligible:** scans in a terminal state (`completed`, `failed`, `canceled`)
  whose last activity is before `now − older-than`. Last activity is the later
  of `ended_at` and `updated_at`, so a recently touched scan is never pruned on
  the strength of an older end time.
- **Never touched:** evidence of `created`, `running`, `paused`,
  `awaiting_auth`, and `canceling` scans, however old. A terminal scan with no
  usable timestamp is skipped and listed in the output (fail closed).
- **Deleted, per evidence row:** the blob file under `evidence/`, then the
  metadata row. Only after the blob is confirmed gone is the row removed. A
  blob that is already missing is reported as `already-gone`, and its row is
  removed. A row whose path escapes `evidence/`, or that names a symlink or a
  directory, is `refused`: nothing outside the root is touched, and the row is
  kept.
- **Findings are kept.** Their evidence links to deleted rows are removed, and
  the output reports how many findings lost links. Verdicts and text are not
  changed.
- **`-include-sessions`** (off by default) also removes the saved session
  (storage-state) file that a scan recorded, but only when the file is inside
  `sessions/` and no non-eligible scan still uses it. Files outside `sessions/`
  (a login you keep elsewhere, passed with `-auth-state`) are never touched.
- **`-include-reports`** (off by default) removes the generated report files and
  their index rows for eligible scans.
- **`-scan <id>`** restricts the run to one scan.
- **Not deleted:** scan records, findings, endpoints, parameters, jobs, AI
  tasks, test-case records, the database itself, and anything in `config.json`.

**Exit status:** `0` when nothing failed, including a dry run. A row refused as
outside the evidence root is a **warning**: it is listed, the rest of the run
completes, and the exit status is still `0`. `1` only if an item failed with an
I/O or store error, or if the command itself errored. Failed items are listed,
and the rest of the run still completes.

**Audit trail:** one line per scan that had something deleted, on stderr, for
example `evidence pruned scan_id=... cutoff=... evidence_removed=12 ...`. It
carries IDs, counts, and the cutoff, never blob content or absolute paths.

**Concurrency with a running server.** The command opens `indago.db` the same
way the server does (WAL mode and a 5 s busy timeout), and it takes no lock
file, so it does not refuse to run when `serve` is up. It only deletes evidence
of terminal scans, and blobs are content-addressed, so a blob re-written by a
late writer is recreated rather than corrupted. The residual risks are a
finding in the same project being updated by the server at the same instant
its evidence links are cut, and a late in-flight write to a canceled scan
landing just after its row is removed. For the widest margin, run it when no
scan is active, or stop the server first.

**What this does not do:**

- It does not overwrite file contents before unlinking. On SSD, copy-on-write,
  or journaling filesystems, deleted cookies can remain recoverable from the
  disk. Use full-disk encryption if that matters to you.
- It does not remove copies in backups made under §5. Expire those separately.
- Test-case records keep the IDs of evidence that was deleted. Content lookups
  for those IDs return "not found", as §4 already describes for missing blobs.
- It considers only the most recent session record per scan (the store has no
  list-all for sessions), and it cannot reach evidence rows whose scan row no
  longer exists. Both are rare by construction; neither is deleted.
- There is no in-process schedule and no API endpoint. Use a timer (below).

**Scheduling, systemd example.** Run it daily with a fixed cutoff. Keep the
cutoff explicit in the unit so the policy is visible in one place.

```ini
# /etc/systemd/system/indago-evidence-prune.service
[Unit]
Description=Indago evidence retention prune

[Service]
Type=oneshot
ExecStart=/usr/local/bin/indago evidence prune -data /var/lib/indago -older-than 720h -apply
User=indago
```

```ini
# /etc/systemd/system/indago-evidence-prune.timer
[Unit]
Description=Daily Indago evidence retention prune

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `systemctl enable --now indago-evidence-prune.timer`. Check a
run with `journalctl -u indago-evidence-prune.service`. Before enabling `-apply`
in a unit, run the dry run by hand first and read its output.

---

## 6. Secrets and configuration

- `config.json` under `-data` never holds a secret value. The AI gateway
  (disabled by default) takes an **environment variable name**
  (`ai.api_key_env`), not a key — the actual key is read from that env var at
  call time and never persisted.
- A target's authenticated-session material (a Playwright storage-state
  JSON file: cookies + origins) lives in its own file, outside `-data` unless
  you put it there. Point a scan at it with `auth_mode: "existing"` plus
  `auth_state_path` (API), or `indago scan create … -auth-state FILE` (CLI).
  The **server** opens the path, so it must be absolute (the CLI makes a
  relative one absolute for you) and readable by the `indago serve` user.
  The file is validated when the scan is created, and again whenever the
  session is (re-)established on Start or on Resume from `awaiting_auth`. It
  must be a regular file of at most 10 MB holding a storage-state object. An
  unusable configuration is a `400` with an `authentication` message, never
  a silent fallback to an unauthenticated scan. The session is reused by
  every layer of the scan: HTTP-level requests (its cookies), browser
  discovery, and browser verification. If the file disappears mid-scan, the
  monitor moves the scan to `awaiting_auth`; restore it and resume.
  `password`/`interactive`/`mfa` modes are rejected at creation (not
  implemented). Treat the state file like a password: it *is* the session.
- Evidence request blobs can contain the target's session cookie verbatim
  (that's the point — full request capture for evidence integrity,
  `AGENTS.md` §2.6). Restricting who can read `-data` (§4) is what protects
  that, not anything in the API. To bound how long those blobs are kept, run
  `indago evidence prune` (dry run by default; see §5, Retention).

---

## 7. Graceful shutdown

`SIGINT`/`SIGTERM` stop `indago serve` gracefully:

1. The HTTP server stops accepting new connections and waits (up to 5s) for
   in-flight requests.
2. Every running scan's worker pool and browser pool are torn down — in
   parallel across scans, each bounded by its own shutdown timeout (30s
   default for both the worker pool and the browser manager) so one wedged
   handler or an unresponsive Chromium process can't block the others, or
   hang the whole shutdown indefinitely. A handler that doesn't return in
   time is logged and abandoned rather than waited on forever.
3. Scan state is left exactly as restart recovery (§5) expects — no special
   "clean shutdown" marker is needed or written.

A forced kill (`SIGKILL`, a host power loss) skips all of the above; restart
recovery on the next `serve` is what makes that safe rather than shutdown
being graceful.

---

## 8. Health and status

`GET /healthz` — `{"status":"ok"}` after a live store ping, `503` otherwise.
`GET /api/version` — `{"version": "...", "name": "indago"}`.
`GET /metrics` — Prometheus exposition (§1, *Metrics*). Needs the bearer token
when `INDAGO_API_TOKEN` is set, and is rate limited like the API.

Neither requires the `X-Indago-Client` header (both are GET) and neither
returns anything beyond those two fields — no internal paths, no config, no
counts that could hint at scan activity to an unauthenticated prober. Use
`GET /api/scans/{id}/status` (an authenticated-context operator call, not a
health check) for actual scan/job/finding counts.

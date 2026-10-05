# Indago — Deployment

This covers running `indago serve` outside a local dev loop: binding,
browser/Playwright setup, the on-disk data layout, backup/recovery, and
shutdown behavior. See `AGENTS.md` for the product's scope and safety rules;
this file is operational, not architectural.

---

## 1. Network exposure — read this first

**The API has no authentication.** `internal/auth` only implements anonymous
sessions for the *target* application a scan authenticates against —
Indago's own control API (`/api/...`) has no login, no token, no per-operator
identity. Anyone who can reach it can:

- create projects/scopes/targets and start scans against whatever target they
  specify (scope is enforced, but the API lets its caller set the scope)
- read every finding, including candidate values and evidence metadata
- fetch evidence **content**, which can include captured session cookies for
  the scanned target (`GET /api/evidence/{id}/content`)
- generate and read reports

This is an intentional trade-off for a local-first, single-operator tool, not
an oversight — see `AGENTS.md` §1. It means the deployment boundary that
actually matters is **who can reach the port**, not anything the API itself
checks.

### Secure default

`indago serve` binds `127.0.0.1:8750` by default (`config.DefaultServerAddr`).
A loopback bind is reachable only from the same machine, which is the
intended deployment for a single operator running Indago on their own
workstation or a dedicated scanning host they alone can SSH/console into.

### Binding beyond loopback

Binding any other address — `0.0.0.0`, a LAN IP, `::`, anything
`isLoopbackAddr` doesn't recognize as `localhost`/`127.0.0.1`/`::1` — is
**refused outright** unless you pass `-allow-remote`:

```bash
indago serve -addr 0.0.0.0:8750 -allow-remote
```

Without `-allow-remote` this fails fast with an explanatory error instead of
starting; the goal is to make the above trade-off a decision you make on
purpose, not something a log line warns about after the fact. If you do need
remote access (a shared scanning box, a container where `127.0.0.1` isn't
reachable from the host), put a real access-control layer in front of it —
a reverse proxy with its own auth, a VPN/SSH tunnel, or a firewall rule
scoped to specific source IPs/users. Indago itself still won't authenticate
the request.

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

Neither is a substitute for restricting network reach — they stop a
malicious web page from driving the API through your browser, not a party
that can already reach the port directly (`curl` doesn't care about CORS).

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
| `-allow-remote` | Required to bind a non-loopback address (§1) |
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
Chromium**, driven via `github.com/playwright-community/playwright-go`. Two
ways to provide one:

1. **Let Playwright manage it** (simplest): install the matching driver and
   browser once —
   ```bash
   go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium
   ```
   This downloads a Chromium build pinned to the `playwright-go` version in
   `go.mod` into Playwright's cache (`~/.cache/ms-playwright/chromium-*` on
   Linux) and installs the OS packages Chromium needs to actually launch
   (`--with-deps`; omit it if those are already present, e.g. in a minimal
   container you're building yourself). Re-run this after bumping the
   `playwright-go` dependency — the driver and the installed browser must be
   version-matched.
2. **Point at an existing Chromium** via `-chromium PATH` or
   `$INDAGO_CHROMIUM_PATH`: the Playwright *driver* (Node-side protocol
   handler) is still required from step 1, but it launches the browser you
   name instead of its own cached one. Useful when a specific Chromium
   build/revision is already provisioned (a container base image, a shared
   CI runner).

Headless Chromium needs the usual sandboxing/shared-library support most
minimal container base images lack — the `--with-deps` install step above
handles that on Debian/Ubuntu-family images; for other bases install
Chromium's runtime dependencies manually (fonts, `libnss3`, `libatk`, etc.).

Without a usable Chromium, `-browser` fails fast at startup (`run playwright
(is it installed? try \`playwright install\`)`) — it's a hard dependency for
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

---

## 6. Secrets and configuration

- `config.json` under `-data` never holds a secret value. The AI gateway
  (disabled by default) takes an **environment variable name**
  (`ai.api_key_env`), not a key — the actual key is read from that env var at
  call time and never persisted.
- A target's authenticated-session material (cookies/storage state) lives in
  its own file, wherever `browser.Manager.InteractiveLogin`'s caller pointed
  `StorageStatePath` — outside `-data` unless you put it there. **As of this
  writing, `InteractiveLogin` and `auth_existing`'s state-path
  (`auth.Input.StatePath` / `CreateScanParams.AuthStatePath`) are implemented
  and tested at the Go level but not yet wired to any CLI command or web API
  field** — `auth_mode: existing` can be requested through the API, but the
  server has no way to learn the state file's path, so it fails closed with
  `"auth: existing-session mode requires a state path"` rather than silently
  scanning unauthenticated. Treat the state file like a password once this
  gap is closed and you do have a path to it.
- Evidence request blobs can contain the target's session cookie verbatim
  (that's the point — full request capture for evidence integrity,
  `AGENTS.md` §2.6). Restricting who can read `-data` (§4) is what protects
  that, not anything in the API.

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

Neither requires the `X-Indago-Client` header (both are GET) and neither
returns anything beyond those two fields — no internal paths, no config, no
counts that could hint at scan activity to an unauthenticated prober. Use
`GET /api/scans/{id}/status` (an authenticated-context operator call, not a
health check) for actual scan/job/finding counts.

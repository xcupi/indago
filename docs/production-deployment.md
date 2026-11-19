# Indago — Production Deployment

This is the operational runbook for running `indago serve` as a long-lived
service: putting it behind a TLS-terminating proxy, wiring liveness/readiness
probes, backing up the SQLite database safely, choosing the Chromium binary and
sandbox policy, and the flags/environment that matter in production.

It complements, and does not replace:

- [deployment.md](deployment.md) — binding, TLS, Docker, browser requirements,
  data layout, backup/restore in full, graceful shutdown.
- [browser-sandbox.md](browser-sandbox.md) — Chromium sandbox behaviour and the
  Docker seccomp recipe.
- [scan-orchestration.md](scan-orchestration.md) — restart recovery semantics.

Everything here assumes the authorized-use rules in `AGENTS.md` §2: scope is
mandatory, verification is deterministic, and nothing in this document widens
what may be targeted.

---

## 1. Reverse proxy with TLS termination

Indago can serve HTTPS itself (`-tls-cert`/`-tls-key`), but a reverse proxy that
terminates TLS, owns the certificate, and enforces network policy is a normal
deployment. Two shapes work; pick one deliberately.

### Enabling the API token (`-api-token` / `INDAGO_API_TOKEN`)

The control API is unauthenticated by default — the single-operator loopback
mode. Turn the token on for **any shared or non-loopback deployment**; a
non-loopback bind already refuses to start without it.

```bash
# Recommended: environment variable (not visible in `ps` or shell history).
export INDAGO_API_TOKEN="$(openssl rand -hex 32)"
indago serve -browser

# Equivalent, for wrappers that build the command line; overrides the variable.
indago serve -api-token "$(openssl rand -hex 32)"
```

- Both forms require ≥32 characters with no whitespace; a shorter or malformed
  value refuses startup, and the error never prints it.
- With a token configured, every `/api/...` request and `GET /metrics` requires
  `Authorization: Bearer <token>` or `X-Indago-Token: <token>`. A missing or
  wrong value gets `401` with `WWW-Authenticate: Bearer`.
- `/healthz`, `/readyz` and the static UI stay open on purpose: probes have no
  token, and the dashboard must load before it can ask for one (§2).
- The CLI accepts the same variable, or `-api-token` on any client subcommand
  (the flag wins for that invocation): `indago scan list -api-token "$TOKEN"`.

### Shape A — proxy on the same host, Indago on loopback (recommended)

Run Indago with its default bind (`127.0.0.1:8750`) and proxy to it. No
`-allow-remote`, no plaintext exposure, no certificate on the backend.

```nginx
server {
    listen 443 ssl;
    server_name indago.example.com;

    ssl_certificate     /etc/letsencrypt/live/indago.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/indago.example.com/privkey.pem;

    # The control API rejects JSON bodies over 1 MiB.
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8750;
        proxy_http_version 1.1;

        # Forward the UPSTREAM address, not the public name. The server builds
        # a DNS-rebinding allow-list from the address it bound (loopback names
        # here); a public Host would be refused with 403 "host not allowed".
        proxy_set_header Host $proxy_host;

        # The CSRF guard requires Origin == Host on POST/PUT/PATCH/DELETE.
        # A browser talking to https://indago.example.com sends that public
        # Origin, so rewrite it to the upstream value. Without this line reads
        # work and every write fails with 403 "cross-origin request refused".
        proxy_set_header Origin http://$proxy_host;

        # Every client reaches the server from the proxy's address, so all
        # clients share one rate-limit bucket. Per-client limits belong here.
        proxy_read_timeout 300s;
    }
}
```

Caddy equivalent:

```
indago.example.com {
    reverse_proxy 127.0.0.1:8750 {
        header_up Host {upstream_hostport}
        header_up Origin http://{upstream_hostport}
    }
}
```

Notes that matter:

- **Host and Origin are both load-bearing.** Verified behaviour: with the
  backend on `127.0.0.1:8750`, a request carrying the public Host gets
  `403 host not allowed`; forwarding the upstream Host but leaving the public
  Origin gets `403 cross-origin request refused` on writes. The two
  `proxy_set_header` lines above are what make the dashboard fully usable
  through a proxy.
- **Keep the API token.** Set `INDAGO_API_TOKEN` on the server (or pass
  `-api-token`) and leave the proxy's `Authorization` header untouched. The UI
  prompts for the token on the first `401` and keeps it in `sessionStorage`.
  `/api/...` and `/metrics` require it; `/healthz`, `/readyz` and the static UI
  deliberately do not.
- **Forwarded headers are ignored on purpose.** `X-Forwarded-For`/`X-Real-IP`
  are not trusted for client identity or rate limiting — any client can set
  them. Enforce per-client limits in the proxy.
- **Expose only what you need.** The dashboard needs `/`. Prometheus scraping
  needs `/metrics` (token-protected when configured). Health checks need
  `/healthz` and `/readyz`; they can be restricted to the proxy/load balancer.
- **WebSocket/SSE are not used.** The UI polls ordinary JSON endpoints, so no
  upgrade headers or long-lived streaming timeouts are required.

### Shape B — proxy on another host, or TLS passthrough

A loopback backend is not reachable from another host. Either put the proxy on
the same host, tunnel it (SSH/VPN) to loopback, or expose Indago directly with
its own TLS:

```bash
export INDAGO_API_TOKEN="$(openssl rand -hex 32)"   # required
indago serve -addr 0.0.0.0:8750 -allow-remote \
  -tls-cert /etc/indago/tls.crt -tls-key /etc/indago/tls.key
```

- A non-loopback bind is refused unless `-allow-remote`, an API token
  (`INDAGO_API_TOKEN` or `-api-token`), and TLS are all present.
  `-allow-plaintext-remote` exists but logs a warning and
  sends the token in clear text; prefer TLS.
- Binding a wildcard address disables the Host allow-list (the valid hostnames
  are unknowable), which is what lets a proxy forward the public Host and
  browser Origin unchanged. That is safe only because the token is required;
  firewall the port to the proxy.
- If the proxy re-originates TLS, trust the backend certificate explicitly
  (`proxy_ssl_trusted_certificate` / `proxy_ssl_verify on`). Never disable
  verification to "make it work".
- If the proxy is on another host but you want a loopback backend, terminate
  TLS at the proxy and forward over an encrypted tunnel; do not bind the
  backend to a public interface just to reach it.

### Behind either shape

- `/metrics` is rate limited and token-protected like the API. A 15s scrape
  interval is far inside the default budget.
- Set `INDAGO_SERVER_URL`, `INDAGO_CA_CERT`, and `INDAGO_API_TOKEN` for the CLI
  when it talks to the proxied/public URL.
- Give the service its own unprivileged user and a data directory readable only
  by it (`0700`). Evidence request blobs can contain the target's session
  cookies verbatim.

---

## 2. Liveness and readiness probes

Two unauthenticated endpoints exist for orchestrators and proxies:

| Endpoint | Meaning | Healthy | Unhealthy |
|---|---|---|---|
| `GET /healthz` | Liveness: the process is up and serving HTTP | `200` `{"status":"ok","version":"<build>"}` | only if the process is down/unreachable |
| `GET /readyz` | Readiness: the store answers a ping within 2s | `200` `{"status":"ready","db":"ok"}` | `503` `{"status":"not_ready","db":"error"}` |

Design rules, and why:

- **`/healthz` never touches the database.** A transient store problem must not
  make an orchestrator restart a healthy process — and a restart mid-write is
  exactly what WAL recovery then has to undo. Use `/readyz` to gate traffic,
  `/healthz` only to decide whether the process exists.
- **`/readyz` bounds its check at 2 seconds.** A hung probe is worse than a
  failed one: without the bound, the orchestrator's own timeout is the only
  backstop. The driver error is logged server-side and never returned — this
  endpoint is unauthenticated, and a driver error can name the database path or
  DSN.
- **Both bypass the control-plane protections.** No `Authorization`, no
  `X-Indago-Client` header, no rate-limit budget, and no Host allow-list match
  is required. A kubelet, Docker `HEALTHCHECK`, or proxy health check sends its
  own Host (pod IP, `127.0.0.1`) and knows no token; refusing a probe for that
  would take a healthy instance out of rotation. The responses contain only
  status and version, so nothing sensitive is exposed.
- **`/readyz` reports the store only.** It does not claim the browser engine,
  OAST collaborator, or any scan is healthy. Check `/api/capabilities` and
  per-scan status for those.

Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8750
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /readyz
    port: 8750
  initialDelaySeconds: 2
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

Use a `startupProbe` on `/healthz` if migrations on a large database make
startup slow; the HTTP listener opens only after migrations and restart
recovery have completed (`cmd/indago`), so a probe cannot see a half-migrated
database.

Docker (the shipped image's own check is `/readyz` over the container's TLS
listener — see `deploy/docker/healthcheck.sh`):

```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8750/readyz"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 20s
```

Restrict `GET /readyz` at the proxy if the deployment should not disclose
up/down state publicly; the endpoint itself is safe to expose (no data), but
there is no reason to advertise it.

---

## 3. SQLite WAL backup hygiene

The store is SQLite in WAL mode with `synchronous(NORMAL)` and a 5s busy
timeout. Three files matter:

```
<data>/indago.db        main database
<data>/indago.db-wal    write-ahead log (present while the DB is in use)
<data>/indago.db-shm    shared-memory index for the WAL
```

### Clean shutdown makes the database file self-contained

`SIGINT`/`SIGTERM` shutdown closes the store last, and `Close` runs
`PRAGMA wal_checkpoint(TRUNCATE)` before closing the handle. After a clean
stop the `-wal` file is empty (SQLite normally removes it at that point):
every committed transaction is in `indago.db`, so copying that one file is a
complete database backup. If the
checkpoint cannot complete (for example another process still has the database
open), shutdown logs a warning naming the incomplete checkpoint and leaves the
WAL in place — copy the whole directory in that case, not just the `.db`.

### Rules

- **Never copy `indago.db` alone while the server is running.** WAL mode keeps
  committed data in `indago.db-wal` until a checkpoint; a live copy of only the
  `.db` can silently miss recent writes.
- **Never copy `-wal`/`-shm` on their own** or pair them with a `.db` from a
  different moment. They are a set.
- **Preferred offline backup:** stop the service cleanly, then archive the
  whole data directory:

  ```bash
  systemctl stop indago
  tar -czf /backup/indago-$(date +%F).tar.gz -C /var/lib/indago .
  systemctl start indago
  ```

- **Online backup (no downtime):** use SQLite's WAL-aware backup, not `cp`:

  ```bash
  sqlite3 /var/lib/indago/indago.db \
    ".backup '/backup/indago-$(date +%F).db'"
  # or, on a SQLite new enough for it:
  sqlite3 /var/lib/indago/indago.db \
    "VACUUM INTO '/backup/indago-$(date +%F).db'"
  ```

  Both produce a consistent single-file snapshot while the server keeps
  serving. The `sqlite3` CLI is not a build dependency of Indago; install it on
  the backup host if you use this method.
- **A filesystem/VM snapshot of the whole data volume is also consistent**
  (SQLite WAL recovery handles the crash-consistent image). Copying individual
  files out of a live volume is not the same thing.
- **Verify before trusting a backup:**

  ```bash
  sqlite3 /backup/indago-2026-01-01.db "PRAGMA integrity_check;"   # expect: ok
  sqlite3 /backup/indago-2026-01-01.db "PRAGMA quick_check;"
  ```

- **The database is not the whole backup.** Evidence blobs, generated reports,
  and saved session files live in sibling directories under the data
  directory; see [deployment.md](deployment.md) §4–§5. A restore that brings
  back only `indago.db` restores findings whose evidence content 404s.
- **Restore:** stop the service, replace the database (remove any stale
  `-wal`/`-shm` from the old file), start the service. Migrations are
  idempotent; interrupted scans are restored as `paused` and never resume on
  their own — see [deployment.md](deployment.md) §5.
- **Permissions:** `0700` on the data directory and `0600` on the files. Request
  evidence can contain the target's session cookies verbatim; disk-level
  protection is the control, not the API.

For retention (bounding how long evidence lives), use
`indago evidence prune` with the server stopped — see
[deployment.md](deployment.md) §5, *Retention*.

---

## 4. Chromium: sandbox policy vs `INDAGO_CHROMIUM_PATH`

These are two independent knobs and are often confused.

| Knob | What it controls | Default |
|---|---|---|
| `-browser-sandbox` policy (`-browser-no-sandbox`) | Whether Chromium's **process sandbox** is used | Sandbox **ON** |
| `INDAGO_CHROMIUM_PATH` / `-chromium` | **Which executable** is launched | Playwright's cached Chromium |

### Sandbox

- The sandbox is on by default (`browser.Config.DisableSandbox` zero value).
  Turning it off requires `-browser-no-sandbox`, which is refused unless
  `-browser` is also set, and logs a warning. It is never an automatic fallback:
  if a sandboxed launch fails, the failure is reported with a pointer to the
  opt-out rather than silently retried without isolation.
- `-browser-no-sandbox` lowers isolation from hostile pages. Use it only on a
  dedicated scanning host/VM, or in a container whose seccomp profile blocks the
  sandbox (the shipped Docker image does exactly this and passes the flag
  explicitly).
- Prefer fixing the environment over disabling the sandbox: Docker's default
  seccomp can be extended with `clone`, `unshare`, and `chroot` to let the
  sandbox start. [browser-sandbox.md](browser-sandbox.md) has the tested recipe.
- Verify what is actually running: `GET /api/capabilities` reports
  `browser_enabled` and `browser_sandbox` (the latter is true only when the
  browser is enabled *and* the sandbox is on).

### Binary selection and why it interacts with the sandbox

Resolution order for the executable:

1. `-chromium PATH`
2. `$INDAGO_CHROMIUM_PATH`
3. Chromium shipped/cached by the Playwright driver

Some Chromium builds cannot sandbox on a given host — typically a build without
the setuid `chrome-sandbox` helper, on a system that also disallows unprivileged
user namespaces. In that situation, pointing `INDAGO_CHROMIUM_PATH` at a
different install (for example a distro Google Chrome with its setuid helper)
can restore a sandboxed launch, which is strictly better than
`-browser-no-sandbox`. This is the one reason to prefer the environment
variable over the Playwright cache: the variable changes *which* binary, not
*whether* isolation is used.

`INDAGO_CHROMIUM_PATH` also feeds PDF report export (the same executable is
used to print HTML to PDF), so setting it once fixes browser automation and
PDF export together. PDF export uses the same sandbox opt-out flag as the
browser engine.

---

## 5. Operational flags and environment

### `indago serve` flags that matter in production

| Flag | Default | Purpose |
|---|---|---|
| `-data DIR` | `data` (`/var/lib/indago` in the image) | Data directory: DB, evidence, reports, sessions |
| `-addr HOST:PORT` | `127.0.0.1:8750` | Listen address; overrides `config.json` |
| `-tls-cert FILE` / `-tls-key FILE` | off | Native HTTPS (TLS 1.2 minimum); both or neither |
| `-allow-remote` | off | Permit a non-loopback bind; requires token + TLS |
| `-allow-plaintext-remote` | off | Accept a non-loopback bind without TLS (warned) |
| `-api-token TOKEN` | empty → `$INDAGO_API_TOKEN` | Control API token; overrides the variable. Prefer the variable: a flag is visible in `ps`/shell history |
| `-api-rate N` / `-api-burst N` | `50` / `200` | Per-client-IP limiter on `/api/` and `/metrics`; `0` disables |
| `-browser` | off | Enable browser discovery/verification (needs Chromium) |
| `-chromium PATH` | empty → `$INDAGO_CHROMIUM_PATH` → Playwright cache | Chromium executable for `-browser` and PDF export |
| `-browser-no-sandbox` | off | Disable Chromium's process sandbox (needs `-browser`) |
| `-allow-state-changing` | off | Also send POST/PUT/PATCH/DELETE; otherwise skipped |
| `-oast-addr HOST:PORT` | off | Built-in OAST collaborator listener |
| `-oast-public-url URL` | off | URL a remote target can reach for callbacks |
| `-oast-allow-external-bind` | off | Permit a non-loopback OAST listener (floodable) |
| `-allow-private-oast` | off | Let SSRF use a private-address collaborator |
| `-ai-provider`, `-ai-model`, `-ai-base-url` | off | Advisory AI gateway (never decides verdicts) |
| `-v` | off | Debug logging |

### Environment variables

| Variable | Read by | Purpose |
|---|---|---|
| `INDAGO_API_TOKEN` | server, CLI | Control API token for `/api/` and `/metrics` (≥32 chars, read once at startup, never logged); overridden by `-api-token` |
| `INDAGO_CHROMIUM_PATH` | server | Chromium executable when `-chromium` is empty; also PDF export |
| `INDAGO_AUTH_USER` / `INDAGO_AUTH_PASS` | server | Password-mode login credentials; never persisted or accepted over the API |
| `INDAGO_AI_API_KEY` | server | Advisory AI key; never a flag, never stored |
| `INDAGO_LLM_KEY_<PROVIDER>` | server | Per-provider advisory key override |
| `INDAGO_SERVER_URL`, `INDAGO_CA_CERT` | CLI | Server URL and extra CA bundle for CLI calls (token: `-api-token` or `INDAGO_API_TOKEN`) |
| `INDAGO_HEALTH_CA` | container healthcheck | CA bundle used by `deploy/docker/healthcheck.sh` |

Configuration precedence: `-addr`, `-api-rate`, and `-api-burst` override
`config.json` for that run; other values come from `config.json` under
`-data`. `indago serve` only writes the template config when the file does not
exist — it never rewrites an operator's config at startup.

---

## 6. Shutdown and restart

`SIGINT` or `SIGTERM` triggers a bounded shutdown, in dependency order:

1. **HTTP server:** stops accepting connections and waits up to **5s** for
   in-flight requests.
2. **Scan controller:** stops every running scan's worker pool, in parallel
   across scans, each bounded at **30s**. A wedged handler is logged and
   abandoned rather than waited on forever.
3. **Browser manager:** closes Chromium contexts/browsers, bounded at **30s**.
4. **Store:** `Close` runs the WAL checkpoint (bounded at **5s**) and closes the
   handle. Anything still holding the database open is reported, not hidden.

Worst case is roughly 70 seconds. If you run under an orchestrator, make sure
its kill grace period exceeds that — Docker's default 10s sends `SIGKILL`
before the controller and browser can finish:

```yaml
stop_grace_period: 90s
# docker run equivalent: --stop-timeout 90
```

A `SIGKILL` or power loss skips all of this and is still safe: WAL recovery
replays on the next open, and restart recovery requeues orphaned jobs and
restores interrupted scans as `paused`. Nothing resumes sending traffic until
an operator explicitly resumes the scan.

---

## 7. Production checklist

- [ ] `indago serve` binds `127.0.0.1:8750` behind a same-host TLS proxy, or a
      non-loopback bind has `-allow-remote`, an API token (`INDAGO_API_TOKEN` or
      `-api-token`), and native TLS.
- [ ] Proxy forwards `Host` as the upstream address and rewrites `Origin` for
      Shape A (or preserves the public Host with a wildcard, token-protected
      Shape B).
- [ ] An API token is set — `INDAGO_API_TOKEN` ≥32 random characters in the
      service environment (preferred), or `-api-token` only where a wrapper
      builds the command line — and it is not in `config.json` or in a file
      readable by others.
- [ ] Liveness probes `/healthz`; readiness probes `/readyz`.
- [ ] Orchestrator stop grace period ≥ 90s.
- [ ] Data directory `0700`, owned by the service user; backups include the
      whole data directory or a `.backup`/`VACUUM INTO` snapshot, verified with
      `PRAGMA integrity_check`.
- [ ] Browser engine: sandbox on unless the host/container cannot provide it;
      document any `-browser-no-sandbox` exception and restrict the host.
- [ ] `GET /api/capabilities` matches the intended deployment
      (`browser_enabled`, `browser_sandbox`, `state_changing_allowed`,
      `oast_enabled`).
- [ ] Logs and `/metrics` are collected; the bearer token and session material
      are never logged.

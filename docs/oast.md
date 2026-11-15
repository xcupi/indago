# Indago — Built-in OAST Collaborator

One local listener that answers the only question an out-of-band engine needs:
*did the target actually call back?*

Code: `internal/oast/` (manager + poll API), `internal/scan/oast_wiring.go`
(wiring), `cmd/indago/oast_flags.go` (flags).

**Off by default.** Nothing starts, and no scan behaviour changes, unless
`indago serve -oast-addr` is given. Without it every out-of-band engine keeps
exactly the configuration it had before: an operator-supplied callback pair, or
none.

## Usage

```bash
# Local target / test corpus: an ephemeral loopback listener, no configuration.
indago serve -oast-addr 127.0.0.1:0

# Remote target: the listener stays on loopback, published through a tunnel.
indago serve -oast-addr 127.0.0.1:8751 -oast-public-url https://abc.example-tunnel.net

# Deliberately reachable listener on the LAN.
indago serve -oast-addr 0.0.0.0:8751 -oast-allow-external-bind
```

| Flag | Meaning |
|------|---------|
| `-oast-addr` | `host:port` for the local listener (`:0` = ephemeral). Empty (default) starts nothing |
| `-oast-public-url` | URL a **target** can reach for that listener (tunnel / reverse proxy). Requires `-oast-addr` |
| `-oast-allow-external-bind` | Permit a non-loopback `-oast-addr`. Never implied by anything else |

On startup the server logs the callback URL, the bound listener address and the
poll URL, so an operator can see exactly what a target will be asked to fetch.

## What gets wired

`scan.Options.OAST` carries the process's single `*oast.Manager`. When it is set,
`defaultHandlers` gives the engines that confirm by callback a collaborator
automatically:

| Engine | Callback it receives | Confirms when |
|--------|----------------------|---------------|
| XXE (`-enable-xxe`, XML body) | `<callback>/<marker>` | the marker appears in the poll body |
| OS command injection (`-enable-command-injection`) | `<callback>?marker=…` | the marker appears in the poll body |
| SSRF (on by default) | `<callback>/<canary>` | the canary token appears in the poll body |

Rules, in order:

1. **Operator configuration always wins.** If either half of an engine's
   callback pair is set in the scan config (`ssrf_callback_url`,
   `xxe_callback_url`, `command_injection_callback_url` and their `_poll_url`
   partners), it is passed through untouched. A half-configured pair is *not*
   mixed with the built-in poll API: that poll knows nothing about another
   service's hits, so mixing would silently break confirmation.
2. **Otherwise the built-in collaborator is used** — the manager's `BaseURL()`
   for the target, its poll API for the scanner.
3. **SSRF additionally needs a canary its own rules accept.** `ssrfOASTCanary`
   refuses a loopback/instance-metadata host, because asking a target to fetch
   `127.0.0.1` is the canonical *internal* probe, not a collaborator, and it
   refuses a private (RFC 1918/ULA) host too unless the operator opted in with
   `-allow-private-oast` (`allow_private_oast` on a scan) — that flag is the
   explicit statement that a lab listener on the target's own private network,
   e.g. `192.168.103.1:8751` for a target at `192.168.103.20`, is the intended
   deployment. The opt-in never relaxes loopback, link-local/metadata,
   unspecified, multicast or CGNAT. A loopback-only listener therefore leaves
   SSRF on its existing response-differential path (logged at startup). Set
   `-oast-public-url` to wire it.

   That differential no longer requires the response to echo the canary: over a
   **clean 2xx baseline**, two independent canaries that each turn the endpoint
   into a resolver/dial/fetch failure (a generic 500/502/504 or a generic
   "could not connect …" message included) are enough for a Medium-confidence
   confirmation. A baseline that already failed, was not 2xx, or a 3xx/4xx
   canary response never confirms.

Each engine keeps its own correlation marker (it was written against an external
webhook service), so the manager's job here is the listener, the retained
interactions and the read API — the verdict stays with the engine's own
deterministic rules (AGENTS.md §2.5).

## The poll API

`Manager.PollURL()` starts (once) and returns
`http://127.0.0.1:<port>/poll/<secret>`:

- **Loopback always**, whatever `Config.ListenAddr` says — a hit list is never
  reachable from a target, even when the callback listener is published.
- **Unguessable path** — a 21-character base32 secret per process, compared in
  constant time; every other path (and any non-`GET`/`HEAD` method) is a 404/405.
- **Plain text, one line per interaction**, carrying the raw host, path and query
  the callback used (so `strings.Contains(body, marker)` works), plus the
  correlated `token=`/`probe=`/`tag=` when the interaction matched an issued
  one. Example:

  ```
  indago-oast poll: 1 interaction(s), 1 correlated
  2026-11-15T10:31:07.412Z http GET https://abc.example-tunnel.net/p/abc... token=abc... probe=scan-1:xxe tag=xxe remote=203.0.113.9 source=local
  ```

- **Bounded** — at most 512 interactions per response, each field capped at 512
  bytes and stripped of control characters, so a flooded listener cannot turn a
  poll into a memory or terminal-escape amplifier.
- **Poll traffic never touches the callback listener**, so a poll can never be
  recorded as an interaction and inflate the evidence it reports on.

The poll listener is created on first use and closed with the manager, which the
server defers at shutdown.

## Boundaries (unchanged, and load-bearing)

- The manager **never sends a request to the target**. It listens, and it serves
  the loopback poll API. Scope enforcement stays in the scan layer
  (`scopedEngine`, `AllowRequest`), and these URLs only change *how* a callback
  is observed, never *what* may be targeted.
- The callback response is a **constant inert canary** (`ok`): nothing from the
  request is echoed, so the listener cannot become an injection source.
- A recorded interaction is **evidence, not a verdict** — same rule as any other
  engine evidence.
- Non-loopback binds require the explicit `-oast-allow-external-bind`, and the
  poll API never follows them off-host. There is no public/vendor default; local
  mode is built in, and the interactsh client remains for operators with their
  own server.

## Tests

`go test ./internal/oast/... ./cmd/indago/... ./internal/scan -run TestOASTWiring`

| Test | Proves |
|------|--------|
| `TestOASTWiringDisabledByDefault` (scan) | no manager → empty callbacks and the unchanged `no XXE callback configured` skip |
| `TestOASTWiringLoopbackWiresXXEAndCommandInjection` | one listener + one loopback poll URL reach XXE and command injection; SSRF is deliberately left unwired, with a reason |
| `TestOASTWiringOperatorOverrideWins`, `…HalfConfiguredPairIsNotMixed` | operator configuration wins and is never mixed |
| `TestOASTWiringPublicBaseURLWiresSSRF` | a published base URL is accepted by both `ssrfOASTCanary` and `ssrfPollURL` |
| `TestOASTWiringPrivateLabCollaboratorNeedsOptIn` | a private-LAN listener is left unwired (reason names `-allow-private-oast`) until the server opts in, and the per-scan opt-in reaches the SSRF executor config |
| `TestOASTWiringXXEEndToEnd`, `…CommandInjectionEndToEnd`, `…SSRFEndToEnd` | target → manager listener → poll API → `VerdictConfirmed` + finding, through the real handlers |
| `TestOASTWiringXXEOperatorBodyIsRegistered` | an operator XML body is registered as an endpoint when the built-in collaborator can confirm it (and not otherwise) |
| `TestOASTWiringPoll*` (oast) | loopback-only, stable, secret path, hits reported verbatim, no line forgery, stops with the manager, safe under concurrent callbacks |
| `TestOASTWiringServeFlags*` (cmd) | flags are a no-op by default, validated, and produce a usable manager |

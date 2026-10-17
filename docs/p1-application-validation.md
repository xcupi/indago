# P1 application-behavior validation

## Transient startup overrides

Startup only writes a config template when `config.json` is absent. The
snapshot is taken before any serve overrides; an existing file is never
rewritten (including unknown fields/formatting). Runtime address/rate/burst,
TLS paths, browser/AI flags, and environment secrets are not persisted.
Stored settings/defaults apply on the next start. P0 token/TLS/bind policies
are unchanged.

- TDD RED: `TestServeOverridePreservesExistingConfigBytes` failed with the
  runtime port written into the config, unknown field dropped, formatting
  replaced. GREEN: same real `cmdServe` startup test passed after fix.
- Regression tests: new template with TLS/token/rate overrides keeps defaults,
  explicit `-api-rate 0`, existing custom config, invalid rate/burst/TLS/remote
  flags leave config unchanged. Tests drive startup to an occupied-port bind
  failure, not a stub of the config logic.
- Live rebuilt binary with disposable data: custom saved `127.0.0.1:45221`,
  first run `-addr 127.0.0.1:50357 -api-rate 0 -api-burst 3` returned health
  200. Config remained byte-identical (SHA256
  `1736aa601bb34e118056e27d7e0f8792fa04f151321dca13a3cf4606ad18c313`).
  After stopping, restart without overrides returned health 200 on **45221**.
- New data: override port 33473 returned health 200; saved template retained
  `127.0.0.1:8750`, rate 50, burst 200. Did not need to occupy default port or
  disturb any existing process.
- All three owned server processes exited after SIGTERM; each port refused
  a fresh connection. Task dummy data/scripts/binary removed at final cleanup.

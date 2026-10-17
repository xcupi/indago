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

## JSON request-body limit

All seven JSON-consuming handlers use the same typed-error mapping. The
complete request body is read through `http.MaxBytesReader` (1 MiB inclusive),
then decoded as exactly one document; whitespace counts toward the limit.
Memory/read size is bounded. Unknown fields stay disallowed; public shapes
are unchanged. Oversize is 413 with `JSON body exceeds 1 MiB limit`; malformed
or read errors return 400 with `invalid JSON body`, never raw parser/body
content. An unavailable feature/missing parent can still fail its prerequisite
before parsing; no guards or instrumentation wrappers changed.

- RED/GREEN 1: oversized project returned 400 instead of 413; typed error
  mapping passed the same test.
- RED/GREEN 2: early valid object plus >1 MiB whitespace returned 201;
  bounded whole-body read made it 413.
- RED/GREEN 3: a second small document returned 201; requiring EOF made it 400.
- RED/GREEN 4: six remaining handlers returned 400 for oversize; shared
  mapping made all seven pass. Additional regression tests cover exact
  1 MiB (201), limit+1 (413), malformed/second-document/trailing-garbage
  400, reader failures and secret-free errors.
- Live rebuilt binary on disposable loopback port 33341: project, scan,
  report creation each returned **201 normal, 400 malformed, 413 oversized,
  413 early-valid + padding, 400 second document**. Lists read back after
  rejected bodies had unchanged counts. Created report list returned 200.
  No scan was started; target port 9 was only dummy metadata.
- Owned server exited and port refused connections after SIGTERM.


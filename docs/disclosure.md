# Information disclosure (cases 38 and 39)

Both cases are **passive**: the engine classifies bytes the scan already
discovered. Nothing is mutated, nothing is submitted, and the finding quotes what
the response actually showed.

## Rules

`internal/disclosure.Classify(url, status, contentType, body)` decides, from a
pure table:

- **debug page (38)** — a reachable 200 dumps the runtime's own configuration.
  Accepted shapes: `phpinfo()` (PHP Version **and** PHP Credits **and** php.ini —
  prose that merely says "PHP" is not a dump), a Django debug page, a Spring Boot
  actuator document (`activeProfiles` + `propertySources`/`systemProperties`).
  The verdict names the first dangerous key the dump carries (`secret_key`,
  `db_password`, `aws_secret`, `jdbc:`, …), which raises it to high.
- **backup source (39)** — the URL names a backup artefact (`.bak`, `.old`,
  `.orig`, `.save`, `.backup`, `.swp`, `.swo`, `.tmp`, `~`) **and** the response
  is source code: a source marker is present (`package `, `import `, `<?php`,
  `#include`, `public class `, …) while the body is not HTML. An HTML error page
  served under `/x.bak` is not a disclosure. A database-connection literal
  (`postgres`/`jdbc`/`driver` context plus a quoted ≥12-char literal) raises the
  finding to high.

## What the pass fetches

One job per candidate endpoint, bounded at **40 per scan**:

- every discovered `GET` endpoint without a query string (name-suggestive URLs —
  `phpinfo`, `debug`, `actuator`, `env`, backup suffixes — first);
- from each fetched page, up to **4** links the ordinary crawler ignores:
  `href`s inside **HTML comments** (a page that "hides" a debug link behind
  `<!-- -->` has still published it) and the file names an **open directory
  listing** prints.

Every follow-up stays on the same origin. The rules are discovery *priority*, not
confirmation: a page named `/debug` that discloses nothing is never a finding.

## Measured live

- case 38 (scan `7a2640dc`): *a reachable page dumps the runtime's own
  configuration (phpinfo()) including secret_key* — confirmed / high. The link was
  `<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->`.
- case 39 (scan `62a87e1e`): *a backup artefact (producttemplate.java.bak) serves
  source code (package) … contains database credential literal (postgres
  connection)* — confirmed / high. Found via `robots.txt → /backup` and the
  listing's own link.

## Wiring

`JobDisclosure` shares the HTTP worker group and the findings mutex. The pass runs
once per execution (`disclosurePassDone`) and needs no opt-in: it is GET-only and
bounded, like the access-control header bypass. Accounting: the passive pass adds
one case per candidate endpoint, which the integration tests count explicitly
(`disclosureJobCount`).

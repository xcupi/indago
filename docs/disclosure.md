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

## Case 37: the wrong-typed value

The one case in this family that sends a request of its own. For each discovered
`GET` endpoint whose query carries a **numeric** value, the pass re-requests it
once with that value replaced by a word (`indago-not-a-value`) — bounded at **20
per scan**. A handler that parses the number before answering throws, and what it
prints is the disclosure.

`ClassifyError` requires an error status (4xx/5xx) **and** a real stack-trace
fragment (`at java.`, `Traceback (most recent call last)`, `PHP Fatal error`, …).
The verdict names the runtime plus the framework version when the body carries one
(`apache struts 2 2.3.31`), falling back to `Server`/`X-Powered-By`. A polite
"Internal Server Error" page and a 200 that merely mentions a class name are not
disclosures.

Measured live: case 37 (scan `b929ea93`) — *parameter productId with a wrong-typed
value: an error response prints the server's own Java stack trace and names apache
struts 2 2.3.31* — confirmed / high.

## Wiring

`JobDisclosure` shares the HTTP worker group and the findings mutex. The pass runs
once per execution (`disclosurePassDone`) and needs no opt-in: it is GET-only and
bounded, like the access-control header bypass. Accounting: the passive pass adds
one case per candidate endpoint, which the integration tests count explicitly
(`disclosureJobCount`).

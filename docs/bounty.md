# Bug-bounty platform integration (YesWeHack)

Status: browsing implemented and verified live; importing a program's scope is
implemented and waits for a personal access token.

## Authentication: token, not password

YesWeHack's API authenticates with a **personal access token** sent as
`X-AUTH-TOKEN`. Indago never stores or accepts a platform password.

Important: according to YesWeHack's help center, **only Business Unit Owner,
Business Unit Manager and Program Manager roles can create a PAT** ("MyYesWeHack
tools" → Create Token). A hunter account has no such menu, so the API's
authenticated endpoints (scopes, report templates, drafts) are out of reach for
a normal researcher. That is why the hunter path does not depend on a token:

- **Scopes** are read from the program's public page, whose server-rendered
  transfer state contains the scope table. `PublicScopes` extracts the
  `"scopes":[...]` array.
- **Program browsing** uses the public `/programs` endpoint.

A hunter can still authenticate: after logging in at yeswehack.com, the web app
keeps a JWT in `localStorage.access_token`, and the API accepts it as
`Authorization: Bearer …` (verified against `/programs/{slug}/scopes`, 200).
Indago treats a credential with two dots as that session JWT and anything else
as a personal access token, validates it against `/programs/count` (readable by
both), and decodes the JWT's `exp` so the UI can show when it expires.

A token, when available, is still useful: the importer prefers the API scopes,
and report templates/drafts become readable. It is validated before storage,
written `0600` in a `0700` directory (`<data>/bounty/yeswehack.token`), and the
API only reports `configured: true/false` — never the value. Clear it with
`DELETE /api/bounty/providers/yeswehack/token`.

One trap in the public page: `asset_value` there is the **severity**
(`MEDIUM`), while `scope` is the asset. The importer only accepts a value that
parses as a host and never a severity word.

## What works without a token

`GET /programs` is public. Indago filters it to the two dimensions that matter
for this scanner:

```
filter[type][]=bug-bounty
filter[scopeType][]=web-application
```

`GET /api/bounty/programs?search=acme&refresh=1` returns that list. The scopes,
report templates and drafts of a program are **not** public (401), which is why
import needs a token.

## Loading is an explicit action

The UI has a **Load programs** button and does not fetch on page load or on
re-render. The server caches a query for ten minutes; **Refresh** sends
`refresh=1` to bypass the cache. Browsing therefore costs one platform call when
the operator asks for it, not one per page view.

## Import: scope first, no scan started

`POST /api/bounty/import {"slugs":["acme","globex"]}` creates, per program:

- a **project** named after the program (notes record the platform slug);
- a **scope** whose `include_hosts` are the program's `web-application` assets
  (wildcards become the parent host, subdomains allowed), and
- one **seed target** per host root (`https://host/`).

Assets of other scope types (api, mobile, …) are listed in `skipped`, not turned
into targets. No scan is created: the operator checks the targets they want in
the project and starts scans with the normal form, so rate/profile controls and
the scope enforcement stay where they already are. Out-of-scope hosts never run
because the scan's scope rejects them — not because the importer remembered to
filter.

## Still to wire (needs the token to be verified, not guessed)

- **Required request headers**: many programs require a header such as
  `X-Bug-Bounty: <username>` so the platform can attribute traffic. The program's
  rules are public in the detail response; once a token is present the rules and
  the per-program report template are both available, and the header should be
  stored on the scan/target and applied by the HTTP engine to every request.
- **Report template**: `GET /programs/{slug}/report-templates` returns the
  program's own submission template, and `reports/draft` defines the fields a
  report must fill (`title`, `scope`, `description`, `technical_information`,
  `end_point`, `vulnerable_part`, `payload_sample`, `cvss`, `criticity`,
  `impact`, …). The YesWeHack template for Indago's report renderer should map
  onto those fields rather than inventing a layout, which is why it is not
  guessed here.

## What a hunter actually needs (audit, 2026-11)

All 48 public programs filtered to `bug-bounty` + `web-application` were
inspected (public detail/rules + the logged-in submission form):

- **Required custom headers: none found.** Only 4 of 48 rules mention "header",
  and every mention is policy prose — security headers that must not be
  reported (`X-Frame-Options`, `X-XSS-Protection`, `X-Content-Type-Options`) or
  a general "User-Agent, VPN" hunting policy. No program required a
  `X-Bug-Bounty`-style identifying header. The feature was left out rather than
  invented.
- **Report submission form** (HARMAN, representative): bug type, scope,
  endpoint, vulnerable part, part name, payload, technical environment,
  application fingerprint, CVE, impact, IPs used, CVSS 3.1 vector
  (AV/AC/PR/UI/S/C/I/A), title, description (Markdown), attachments, chainable.
- **Description template** is the platform's standard Markdown skeleton:

  ```markdown
  ## Description
  ## Exploitation
  ## PoC
  ## Risk
  ## Remediation
  ```

  The "YWH Report Template" tab in the editor inserts exactly that skeleton,
  plus Markdown tips. A report renderer for YesWeHack should therefore emit
  those five sections, map Indago's finding to the field list above, and use
  the finding's evidence as the PoC.
- Scopes on the API and on the public page both put the severity in
  `asset_value`; the asset lives in `scope`.

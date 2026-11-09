# Bug-bounty platform integration (YesWeHack)

Status: browsing implemented and verified live; importing a program's scope is
implemented and waits for a personal access token.

## Authentication: token, not password

YesWeHack's API authenticates with a **personal access token** sent as
`X-AUTH-TOKEN`. Indago never stores or accepts a platform password. Create the
token on yeswehack.com (profile → API tokens), then paste it into the Bug bounty
page; it is validated against the API before being stored, written `0600` in a
`0700` directory under the data dir (`<data>/bounty/yeswehack.token`), and the
API only ever reports `configured: true/false` — never the value.

Revoke a leaked token on the platform and clear it here
(`DELETE /api/bounty/providers/yeswehack/token`).

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

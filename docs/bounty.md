# Bug-bounty platform integration (YesWeHack)

Status: browsing and public-scope import are implemented and verified live.
A personal access token is optional; it unlocks API scopes and templates.

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

Hunter session JWTs are short-lived. Indago decodes their `exp` claim and the
UI shows the expiry in local WIB time; after expiry the credential is marked
**expired**, API scopes/templates/drafts require a replacement, and public
program browsing continues without it. The UI explains how to copy the token
from the logged-in browser (`copy(localStorage.access_token)`) and offers
**Replace credential**.

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

## Where this sits in the workflow

Bug bounty is **program intake**, not a post-scan submission screen. The order is:

```
find program -> import scope as a new project -> scan targets
             -> generate YesWeHack report -> submit manually
```

Scope is always project-level: the imported project gets the program's
`include_hosts` and path prefixes, and every scan under it is enforced against
that scope. Importing creates a **draft scan for the first web target with
anonymous auth**, but does not start it.

If a project already has a manually-entered scope and has already been scanned,
do **not** import the program to "attach" it: import always creates a new
project and never edits an existing one. Keep the existing project, generate a
YesWeHack report from its scan, and check by hand that the finding's asset is in
the program's published scope before submitting. To make the imported scope
drive a fresh scan, import the program and scan the new project instead.

## Import: scope first, draft scan created

`POST /api/bounty/import {"slugs":["acme","globex"]}` creates, per program:

- a **project** named after the program (notes record the platform slug);
- a **scope** built from the program's `web-application` assets, which keeps the
  two authorization shapes apart instead of flattening them into one:

  | asset row | goes into | authorizes | does **not** authorize |
  |---|---|---|---|
  | exact, `https://www.example.com` | `include_hosts` + `allowed_origins: ["https://www.example.com"]` | `https://www.example.com` on port 443 | `http://www.example.com`, `:8443`, `a.www.example.com` or any other host |
  | exact, `http://www.example.com:8080` | `include_hosts` + `allowed_origins: ["http://www.example.com:8080"]` | that exact origin | `https`, the default ports, or any other host |
  | wildcard, `https://*.example.com` | `subdomain_only_hosts` + `allowed_origins: ["https://*.example.com"]` | `https://a.example.com`, `https://a.b.example.com` | `example.com` (a wildcard never covers its apex), `http`, or another port |

  Import never sets `allow_subdomains`: that flag would turn every exact asset
  into a wildcard, authorizing hosts the program never listed. A wildcard row's
  concrete asset (`app.example.com` in the API's `asset_value`) is already
  authorized by the wildcard, so it is also kept as an exact host and as a seed;
  a row whose asset is the apex, or a host outside the wildcard, is **not**
  adopted — it is reported in `skipped` and only the wildcard is kept. A
  leading-dot row (`.example.com`) is ambiguous across platforms and is skipped
  rather than guessed at. Import also never sets `allow_any_scheme_ports`: each
  row's own scheme and port becomes the `allowed_origins` entry, so the imported
  scope cannot reach a sibling service on another port of the same host. A
  wildcard row must state its scheme (`https://*.example.com`); a scheme-less
  `*.example.com` is **skipped and reported**, because neither its scheme nor
  its port is in the source and Indago does not guess one.
- one **seed target** per concrete asset the scope permits: an exact host, or
  the concrete asset of a wildcard row. A wildcard with no concrete asset
  authorizes its subdomains but seeds nothing — add the host you are testing as
  a target, and it will be in scope;
- one **draft scan** for the first target the imported scope permits, profile
  `conservative` (2 requests/second, the quiet preset — the operator did not
  choose this program's rate), auth mode `anonymous`. It stays in `created`
  state until the operator starts it.

Assets of other scope types (api, mobile, …) are listed in `skipped`, not turned
into targets. An asset that is a **path**, not a host root (for example
`https://target.test/challenge/one`), becomes a seed on that path and adds
`include_path_prefixes: ["/challenge/one"]`.

Path prefixes belong to the **scope**, not to one host: the matcher applies
every stored prefix to every in-scope origin. A program that scopes different
paths to different hosts would therefore be flattened into a cross product —
`https://a.test/app` plus `https://b.test/api` would also permit
`https://a.test/api` and `https://b.test/app`, which the program never listed.
The importer refuses that program instead of storing the wider scope: **nothing
is created** (no project, no scope, no scan) and the reason is reported in
`skipped`, naming each origin and the path it is scoped to.

A program is imported with paths only when every origin it names authorizes the
**same** path set. Paths are compared the way the scope matcher compares them (a
prefix covers its own segment and everything below it: `/app` covers
`/app/admin`, not `/application`), and the stored list is the reduced set. The
one redundant shape the importer normalises away is an exact asset's path when
an **unrestricted** wildcard in the same program already authorizes that
subdomain on every path — dropping the narrower statement keeps the wildcard's
authority intact instead of narrowing it. Everything else is either imported
exactly or refused; the importer never picks one host's path and applies it to
another. Import one path-scoped asset per project, or declare the scope manually
when the program is not expressible.

An import always creates a **new** project and scope and never edits an existing
one, so exclusions and path prefixes you configured elsewhere are untouched. The
draft scan gives the operator a one-click next step; they still review the
targets, set the program's hunting User-Agent, and start it manually.
Rate/profile controls and scope enforcement stay where they already were.
Out-of-scope hosts never run because the scan's scope rejects them — not because
the importer remembered to filter.

## Hunting User-Agent

Some programs require the hunter to append a program-specific value to the
User-Agent, for example CyberGhost:

```
-BugBounty-CyberGhost--31337
```

The format is **not** universal: PIA uses `-BugBounty-PIA--31337`, Tencent
`-BugBounty-tencent-31337`, Moneybox `bugbounty-0421`, Paddle `BugBounty`,
Ooredoo `-BugBounty-ooredoo-portal`, and Infomaniak replaces the UA with
`Infomaniak-YWH-Bugbounty`. Always copy the exact value from the program's
**Hunting requirements**; the API's `rules` field does not always include that
section (CyberGhost is one example).

Indago stores the value on the project (**Project → Hunting User-Agent**). By
default it is appended to `Indago` (`Indago <value>`); enable **Replace the
default User-Agent** for programs that require a full replacement. Import tries
to read the value from the public page's **User agent** section automatically
(verified with Infomaniak, `Infomaniak-YWH-Bugbounty`, replace mode); if the
section is missing or ambiguous, set it by hand. The value is copied to new
scans, and `Start` re-reads the project so a draft scan created by an import
still picks up a value added afterwards. It is applied to raw HTTP, discovery
browser contexts, browser verification, DOM-XSS contexts, and the interactive
scan-login browser.

## Still to wire

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

## Submission report template (implemented)

`POST /api/scans/{id}/reports {"format":"markdown","template":"yeswehack","mode":"confirmed"}`
renders one Markdown section per confirmed finding using the platform's own
skeleton:

```
## Description
## Exploitation
## PoC
## Risk
## Remediation
```

Above the sections it prints the form fields as metadata: bug type (mapped from
Indago's class), scope, endpoint, vulnerable part, part name, payload, technical
environment, application fingerprint, CVE, impact, CVSS and IPs. Fields the
scanner genuinely does not know (fingerprint, egress IP, CVE) are marked `—`
with a hint, and CVSS is explicitly **not scored**: Indago has a severity
verdict, not a vector, so the operator assigns it in the form.

Rejected diagnostics are never included; only confirmed findings are rendered.

The UI exposes it as Reports → format `markdown` → template
`YesWeHack submission (markdown)` (choosing the template switches the format
automatically).

## Workflow with a model

1. Connect (session token) and import the program → project + scope + targets.
   Import also creates one draft scan per in-scope web target: the balanced/medium
   profile, depth 3, 200 pages, 500 endpoints, standard candidates (8 per
   injection point), anonymous auth. They are not started, so login/auth and
   tuning remain explicit actions.
2. Scan inside that scope; findings land as usual.
3. Generate the submission: `template=yeswehack`, `format=markdown`.
4. `POST /api/scans/{id}/ai/report-review` (or Reports → **Review with AI**)
   returns a triager verdict and the fixes. The reviewer reads exactly the
   Markdown from step 3.
5. Fix what it flags, regenerate, then submit on the platform. The review is
   advisory; YesWeHack's triage is the decision.

## Audit: what is covered, what is not

Covered: public program browse with `bug-bounty` + `web-application` filters and
an explicit cached Load, hunter session login (Bearer JWT) or manager PAT,
scope import from the API or the public page, one project + scope + seed target
per program, the YesWeHack Markdown template, and a triager review over the
exact submission bytes.

Known gaps:

- **Submission is manual by design.** Indago renders the submission, reviews it
  with the triager pass and prints the form fields; the hunter presses Submit
  on the platform. A submission spends credits, so it stays a human action.
  Auto-filling the platform draft (without submitting) is still unimplemented;
  it would need a stored credential and a live test against `reports/draft`.
- **Per-program report templates** (`/programs/{slug}/report-templates`) are
  readable with a credential but not yet surfaced in the UI; the platform's
  standard five-section skeleton is what the renderer emits.
- **Scope exclusions**: the importer builds the include list from
  `web-application` assets; a program that also publishes explicit exclusions in
  rules prose is not parsed into `exclude_hosts`.
- **Rules display**: the program page links to YesWeHack; the rules text is not
  rendered inside Indago.

## Scope is not platform-only

A project's scope is edited by hand on the project page (include/exclude hosts,
path prefixes, subdomains) whether or not any platform is connected. Import is
only a shortcut that fills the same fields from the program:

- **manual**: Projects → project → Scope → type hosts/paths → Save scope.
- **from YesWeHack**: Bug bounty → Load → **scope** (preview the program's
  assets and rules without importing) → Import selected. The project is created
  with those assets as `include_hosts` / `include_path_prefixes` and one seed
  target per asset.

The scan form shows the selected project's scope and warns when the chosen
target host is outside it; the server enforces the same scope fail-closed.

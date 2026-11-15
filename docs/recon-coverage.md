# Recon coverage

Reference curricula: HTB Academy **Information Gathering - Web Edition**
(module 144) and **Web Fuzzing** (module 280). This page maps their sections to
what Indago actually does, so a missing technique is a documented decision
rather than an accident.

## Information Gathering - Web Edition (144)

| Section | Indago | Where |
| --- | --- | --- |
| WHOIS | not covered | Network-level lookup; the scanner starts from a URL and has no registry client. Registrant data is also usually redacted. |
| DNS (records, zone transfer) | not covered | Same: a separate network-recon phase. The web scanner resolves only what the HTTP client needs. |
| Subdomain discovery | not covered | Would send requests to hosts outside the seed's scope; needs an explicit authorization model, not a silent crawler feature. |
| Web crawling | covered | `crawlSource` (depth/pages caps, forms, redirects, JS-rendered pages via the browser source) |
| Web archives | covered (aggressive) | `archiveSource`: one Wayback CDX query per origin, same-host URLs only, ≤200 results, status 200 only |
| Search engine discovery (dorking) | not covered | Needs a search-engine API/key and leaks the target to a third party; out of scope for an in-process scanner |
| Fingerprinting | partial | Response headers and cookies are captured as evidence; jQuery/Angular are identified by the DOM analysis paths. There is no separate tech-stack inventory. |

## Web Fuzzing (280)

| Section | Indago | Where |
| --- | --- | --- |
| Folder fuzzing | covered | `contentSource` + embedded path lists (162 safe/standard, 252 aggressive), soft-404 calibration, extension probes |
| Recursive fuzzing | covered (aggressive) | one level, depth ≤ 2, from discovered directories |
| Parameter fuzzing | covered (standard+) | differential parameter mining + 200-name list, GET and form/JSON bodies |
| Value fuzzing | not covered | Finding a *valid* value (`?x=OA_HTML`) is a guessing problem, not a vulnerability signal; the injection engine already sends values. |
| Subdomain fuzzing | not covered | See subdomain row above: scope and authorization. |
| Vhost fuzzing | not covered | Requires Host-header brute force against a resolved IP; a wrong guess can reach an unrelated vhost on shared infrastructure. Needs its own opt-in and scope rules. |
| API fuzzing | covered (paths) + partial (schemas) | JS/JSON literal extraction, `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/api-docs`, `/swagger/v1/swagger.json` in the path list, `wellKnownSource` expands the paths inside a discovered OpenAPI/Swagger document into endpoints, and the conventional GraphQL entry points (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`) are probed with a read-only `{__typename}` query |

## What changed in this pass

`internal/discovery/wellknown.go` (standard and above) reads the documents a
site publishes about itself:

- `/.well-known/security.txt` and `/security.txt` — `Policy`, `Canonical`,
  `Encryption`, `Hiring`, `Acknowledgments`, `CSAF` URLs;
- `/.well-known/openid-configuration` — issuer, authorization, token, userinfo,
  JWKS, registration and end-session endpoints (any absolute or root-relative
  URL value);
- `/swagger.json`, `/swagger/v1/swagger.json`, `/api/swagger.json`, `/openapi.json`,
  `/api-docs`, `/v3/api-docs` — every key under `paths`. OpenAPI 3 specs are
  resolved against their first `servers` URL; Swagger 2.0 specs against
  `schemes`/`host`/`basePath`. Templated paths (`/users/{id}`) are skipped:
  the braces declare a parameter, they are not a requestable URL.
- The conventional GraphQL entry points (`/graphql`, `/api/graphql`,
  `/v1/graphql`, `/query`) — each one is asked a single read-only
  `{__typename}` query over GET, and only a GraphQL-shaped answer registers the
  endpoint. A plain JSON API that happens to answer at `/query` is not
  registered.

Every URL taken from a document is untrusted: it is normalized, must stay on
the scanned host, must pass the scope check, and must pass the same
session-safety guard as any other fetch before it becomes an endpoint. mailto:
contacts and external policy URLs are ignored.

**Static resources are never test targets.** Crawled and browser-observed
CSS/images/fonts/media are dropped before an endpoint, parameter or job is
created (operator-supplied seeds excepted — scanning one is explicit intent).
JavaScript is filtered the same way *as a target*, but a crawl still fetches a
bounded number of script assets (≤12 per crawl, once each, ≤32 literals per
file) to mine the endpoint paths inside them; those paths are registered with
`script_literal` provenance. Before this cut the crawler followed every
referenced asset as a page, so the change also lowers request volume.

`internal/discovery/archive.go` (aggressive only) asks the Wayback CDX index for
historical URLs on the same host. It is the only source that contacts a third
party, which is why it is gated at the highest level and called out in the UI:
the target hostname is disclosed to archive.org.

Both sources emit new provenance values (`well_known`, `archive`) so the
endpoint list shows where a URL came from.

## Why this is the right cut for bug bounty

Bug-bounty platforms (YesWeHack, HackerOne, Bugcrowd, Intigriti) already hand the
hunter the registry and DNS layer: the program page lists in-scope domains and
IPs, and WHOIS/DNS/subdomain inventory is either shown by the platform or
trivially available from it. Re-implementing that inside the scanner duplicates
data the operator already has, and — worse — an enumeration feature that walks
DNS is the easiest way to send traffic to a host the program did not authorize.

Indago therefore starts where the platform stops: an in-scope URL (or a short
seed list), then depth on the web surface the platform does not inventory —
paths and files, parameters, self-describing documents (security.txt, OpenID,
OpenAPI), historical URLs from the public archive, and the injection points
behind them. That is also why the archive source filters to the exact scanned
host and the well-known source resolves every document URL against the same
origin: the platform's scope list stays the authority.

## Deliberately out of scope

DNS, WHOIS, subdomain and vhost enumeration are network-recon capabilities. They
target hosts the operator did not name, and on shared infrastructure a wrong
vhost guess reaches someone else's application. If they are added, they belong
in a separate, explicitly authorized phase with their own scope model — not in
the crawler's source list.

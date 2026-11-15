# Indago — Passive Tech-Stack Fingerprinting & Adaptive Payload Gating

One already-captured HTTP response in, one `Profile` out, plus four gate
functions that answer "is this class of probe worth a request here?".
Code: `internal/fingerprint/tech.go`.

**This package sends nothing.** It has no HTTP client, no browser, no socket: it
reads an `Observation{URL, Status, Header, Body}` that another layer already
fetched. Wiring it into the scan pipeline is a separate step; nothing in
`internal/scan` consumes it yet.

## Guarantees

| Property | How it is enforced |
|----------|--------------------|
| **Passive** — no extra request, ever | `TestFingerprintIsPure` parses the package's imports and fails on anything outside `bytes`, `encoding/json`, `mime`, `net/http` (types only), `net/url`, `path`, `strings`, and on `http.Get(`/`http.Do(`/`net.Dial`/`exec.Command`/`time.Now`/`math/rand` in the source |
| **Pure and deterministic** | no clock, no randomness, no goroutines, no map iteration in any output path — rule tables are ordered slices and results are emitted in fixed catalog order. `TestAnalyzeIsDeterministic` (20 runs) and `TestHeaderInsertionOrderDoesNotMatter` |
| **No secrets** | cookie **values** are dropped at the only place cookies are read (`cookieNames`); a cookie signal carries the cookie *name*. `TestCookieValuesNeverReachTheProfile` |
| **Bounded** | body hints only in the first 128 KiB, XXE request body only in the first 8 KiB, header values truncated to 200 bytes, at most 96 signals. `TestBodyScanIsBounded`, `TestHeaderValuesAreTruncated` |
| **Never panics on hostile input** | `TestAnalyzeNeverPanicsOnHostileInput` (malformed URLs, invalid UTF-8, NUL bytes, 1 MiB bodies, junk cookies) |
| **Descriptive, never a verdict** | a `Profile` says "this looks like PHP/WordPress"; it never says "vulnerable" (AGENTS.md §2.5, §6) |

## What is detected

**Languages** (`Languages`): php, python, ruby, java, node, dotnet, perl — from
`X-Powered-By`, `Server`, language-specific cookie names (`PHPSESSID`,
`JSESSIONID`, `ASP.NET_SessionId`, `connect.sid`, …), URL extensions (`.php`,
`.aspx`, `.jsp`, `.py`, `.rb`, `.cgi`, …) and, for Python/Java, the app server
(`Werkzeug`, `gunicorn`, `uvicorn`, `Apache-Coyote`, `Jetty`, `Undertow`, …). A
framework implies its language, so `wp-content/` alone yields `php` + `wordpress`.

**Frameworks** (`Frameworks`): laravel, symfony, codeigniter, wordpress, django,
flask, rails, spring, express, nextjs, nuxt, aspnet — from headers
(`X-Debug-Token`, `X-Application-Context`, `X-AspNet-Version`), cookies
(`laravel_session`, `csrftoken`, `ci_session`, `wordpress_*`) and body markers
(`wp-content/`, `csrfmiddlewaretoken`, `__NEXT_DATA__`, `/_next/static/`,
`__VIEWSTATE`, …). Client-side libraries are out of scope; DOM analysis has its
own paths.

**ContentKind** (`ContentType` + `ContentKind`): `html` (incl. XHTML and SVG),
`json` (incl. `+json`, ndjson), `xml` (incl. RSS/Atom/SOAP), `text`, `binary`,
and `unknown` when there is no usable evidence. The `Content-Type` header wins;
body sniffing is the fallback (leading `{`/`[`, `<?xml`, `<!doctype html`, a NUL
byte or a control-heavy prefix). `StaticAsset` additionally marks file downloads
(`Content-Disposition: attachment`, any binary body, CSS/JS bundles and known
asset extensions) — an HTML-labelled response is never an asset.

**TemplateHints** (`TemplateHints`, never empty): engines plausible for the
stack, most likely first — explicit engine evidence from an error page first
(`jinja2.exceptions`, `twig\error`, `freemarker.template`,
`org.apache.velocity`, `smarty error`, `mako.exceptions`, …), then engines
pinned by the framework (Laravel → blade; Symfony → twig; Django → django/jinja2;
Flask → jinja2; Rails → erb/haml; Spring → thymeleaf/freemarker/velocity/spel;
Express → ejs/handlebars/pug/nunjucks; ASP.NET → razor), then language defaults
(PHP → twig/smarty/blade; Python → jinja2/django/mako; Java →
freemarker/velocity/spel/thymeleaf; Node → ejs/handlebars/pug/nunjucks; Ruby →
erb/haml). When nothing is plausible it holds exactly `["none"]`.

**WAFVendor** (`WAFVendor`, `WAFConfidence`): cloudflare, akamai, imperva, aws,
f5, azure, sucuri, modsecurity, wordfence, fortiweb, barracuda — from
vendor-specific headers (`CF-Ray`, `X-Iinfo`, `Akamai-GRN`, `X-WA-Info`,
`X-Sucuri-ID`), cookies (`visid_incap*`, `ak_bmsc`, `BIGipServer*`) and
challenge/block bodies (`Mod_Security`, `Wordfence`, `Incapsula incident ID`).
The highest-confidence vendor wins; ties keep catalog order.

## Evidence

Every conclusion is also a `Signal` naming where it came from:
`{class, source, name, match, value, tech, confidence}` — e.g.
`{framework, body, body, "wp-content/", "", wordpress, high}` or
`{language, cookie, "JSESSIONID", "jsessionid", "", java, high}`. `value` is only
ever a truncated header value or a body needle; a cookie signal's `name` is the
cookie name, never its value. A report can therefore show why the scanner
believed something.

## Gates

| Gate | Probes when | Skips when |
|------|-------------|------------|
| `ShouldProbeXSS` | HTML, XML/SVG, text, JSON, unlabelled — anything a browser could render as markup or that is genuinely ambiguous | binary body, file download/asset, `304 Not Modified` |
| `ShouldProbeSSTI` | a template engine is plausible for the stack, and the response is a rendered document (HTML/text/XML/ambiguous) | binary/asset/`304`, unknown stack, JSON without explicit engine evidence, a Next.js/Nuxt shell with no other server-side language |
| `ShouldProbeXXE` | the **request** accepts or carries XML (`application/xml`, `text/xml`, `*+xml`, an `<?xml` declaration — also percent-encoded or inside a multipart field), or the response is XML | a JSON-only request/response pair with no XML anywhere |
| `ShouldProbeCommandInjection` | application code handles the request: a detected language/framework, a non-edge cookie, or a real document body | binary/download/asset/`304`, an empty response with no application evidence |

`ShouldProbeSSTI` returns `(bool, []string)`: the engine list is the profile's
hints in order, so a caller can prioritize the matching syntax instead of
spraying every engine (`PHP → twig/smarty/blade`, `Python → jinja2/django/mako`,
`Java → freemarker/velocity/spel/thymeleaf`). The list names engines, not payload
shapes — choosing a `{{7*7}}` vs `<%= %>` vs `${}` shape stays with the caller.

Every gate is advisory triage, not a scope decision and not a verdict. Gates
fail *open* on ambiguity (an unlabelled response may still be the vulnerable
one) and fail *closed* only on positive evidence that the class cannot apply (an
opaque download cannot reflect markup, and a static file server runs no shell).

## Known limits

- Heuristics, not proof. A marker means "this product is probably in the stack",
  not a version-accurate inventory; false positives cost one probe, which is why
  every signal carries a confidence.
- A `Server: nginx`, `Server: Passenger` or `Server: Caddy` value alone is *not*
  treated as a language marker (they serve PHP, Node and Python alike). Only
  language-specific server names count (`WEBrick`/`Puma` → ruby,
  `Werkzeug`/`gunicorn`/`uvicorn` → python, `Apache-Coyote`/`Jetty`/`Undertow`
  → java).
- `cloudflare` as a WAF vendor means a Cloudflare edge answered, not that a rule
  blocked anything; the same is true of the CDN-side markers for Akamai/Azure.
- Body markers are matched in the first 128 KiB only; a marker deeper in a large
  document is missed by design.
- No CDN/edge inventory beyond WAF vendors, no JS-library inventory, no version
  fingerprinting, no active probing — all deliberately out of this slice.
- Not wired into `internal/scan` yet: no scan behaviour changes with this package
  alone.

## Verification

```
go test -v ./internal/fingerprint/...
go vet ./internal/fingerprint/...
```

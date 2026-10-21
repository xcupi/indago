# What project scope decides, and what it does not

Scope is Indago's safety boundary: nothing outside it should be requested. This
page states exactly what the matcher compares, so an operator does not assume a
guarantee it does not give. Each statement is labelled with its basis:

- **measured**: pinned by `internal/domain/scope_semantics_test.go` (48 cases;
  change the matcher and these tests fail, which forces this page to be revisited)
- **code**: read from the source, no dedicated test
- **reasoned**: inferred, not demonstrated

## 1. The decision is made on the hostname

`Scope.Permits(url)` looks at the URL's **hostname** and path. It ignores:

| ignored | consequence | basis |
|---|---|---|
| port | `example.com` permits `:1`, `:8443` and `:65535` alike. An internal admin service on another port of an in-scope host is in scope | measured |
| scheme | `http`, `https` and `ftp` URLs to an in-scope host all pass | measured |
| query and fragment | `?next=/app` or `#/app` never helps a URL match a path rule | measured |
| the IP the name resolves to | see section 5 | code |

There is no way to say "only port 443". If a host runs something you are not
authorized to test on another port, the scope cannot separate them.

## 2. Include entries must be bare hostnames

Entries are trimmed of whitespace and compared as lowercase strings against the
URL's hostname, so anything that is not a bare hostname would match **nothing**
and the scope would silently deny the host the operator meant (measured).
`PUT /api/projects/{id}/scope` therefore **rejects such entries with a 400** that
names the field, the entry and how to write it, and stores nothing (the previous
scope stays). Measured by `internal/domain/scope_validate_test.go` and
`internal/web/scope_validation_test.go`; the form shows the rule beforehand
(`ui_scope_test.go`). The same checks apply to `exclude_hosts`:

| entry | result | write instead |
|---|---|---|
| `https://example.com` | never matches | `example.com` |
| `example.com:8443` | never matches (port is not part of the hostname) | `example.com` |
| `*.example.com` | never matches | `.example.com`, or `example.com` with allow subdomains |
| `example.com/` | never matches | `example.com` |
| `[::1]` | never matches | `::1` (IPv6 without brackets) |
| `bücher.example` | a Unicode URL host does not match the punycode entry (measured); Chromium reports punycode hosts, so enter the punycode form (reasoned) | `xn--bcher-kva.example` |

This fails closed, and since validation was added the operator is told at save
time instead of discovering "host not in scope" later. The validator rejects
exactly the shapes that cannot match; it does **not** reject entries that match
more or less than they read (port ignored, path prefixes with no segment
boundary, case-sensitive paths): those stay documented here. Path prefixes are
validated too: they must start with `/` and contain no `?`, `#`, whitespace,
`://` or dot-segment. Existing scopes saved before this check are not migrated;
a bad entry in one still just matches nothing until it is re-saved. Case does
not matter for hosts (measured).

Other spellings of the same machine are **not** recognized as that host, so they
are denied rather than allowed (measured): a trailing dot (`example.com.`),
decimal or hex IPv4 (`2130706433`, `0x7f.0.0.1`) and IPv4-mapped IPv6
(`[::ffff:127.0.0.1]`). Userinfo is handled by the real host: `user@127.0.0.1` is
`127.0.0.1`, and `127.0.0.1@evil.example` is `evil.example` (measured).

## 3. Subdomains

- Off by default: `a.example.com` is not covered by `example.com` (measured).
- With allow subdomains, or an entry written `.example.com`, the base host and
  every depth of subdomain match. The match needs a dot boundary, so
  `evilexample.com` and `example.com.evil.net` do not (measured).
- An excluded host always wins over an included one (measured).

## 4. Path prefixes are plain string prefixes

Include and exclude paths use `strings.HasPrefix` on the decoded path. That has
consequences in both directions (measured):

| rule | surprising result | safe direction? |
|---|---|---|
| include `/app` | also matches `/application`, `/app-admin` | **no**, wider than it reads |
| include `/app/` | does not match `/app` itself | yes, narrower |
| exclude `/admin` | also blocks `/administrator` | yes, over-blocks |
| exclude `/admin/` | does **not** block `/admin` | **no**, narrower than it reads |
| any path rule | case-sensitive: exclude `/admin` does not block `/Admin`; hosts are case-insensitive | **no** for exclusions |

Dot-segments are not collapsed by the matcher: `/app/../secret` passes an include
of `/app`, and so does `/app/%2e%2e/secret` (measured). The request that is
actually built is normally safe, because `discovery.Normalize` collapses
dot-segments before an endpoint is stored (code) and Chromium canonicalizes a
URL before the browser gate sees it (code, and the redirect work below). But a
server may decode `%2e%2e` itself (reasoned), so do not rely on a path prefix to
protect a sibling directory.

**Practical rules:** write include paths with a trailing slash when you mean a
directory; write exclusions both ways (`/admin` and `/admin/`) and in the case
variants the application serves; treat path rules as a convenience, not a
security boundary.

## 5. Scope is not an IP policy

The check is on the name, deliberately: an operator may legitimately scope an
internal or private target (comment in `internal/httpengine/client.go`). So a
host that is in scope is requested wherever its name points (code, reasoned):

- A name that resolves to loopback, a private (RFC1918) range, or a cloud
  metadata address is still requested. A DNS answer that changes between the
  check and the connection (rebinding) is not detected by the matcher.
- The one IP-level control is in the **raw HTTP engine** only: it refuses to
  connect to link-local addresses (`169.254.0.0/16`, `fe80::/10`, including
  `169.254.169.254`), at dial time after DNS, whatever hostname or redirect hop
  produced them (measured: `internal/httpengine/linklocal_test.go` checks
  literal link-local targets and a redirect hop, and sends no packet to them).
  A hostname that merely resolves to such an address goes through the same dial
  hook (code), but no test resolves a name to one. Other metadata addresses (for example `100.100.100.200`,
  `192.0.0.192`, `fd00:ec2::254`) and private ranges are not blocked.
- **The browser has no IP-level check at all** (code: the only link-local check
  in the tree is in `httpengine`). A page can make Chromium connect to a
  link-local address if its hostname is in scope.
- **The browser also connects to out-of-scope hosts for navigations.** The gate
  refuses the request, but Chromium preconnects to a navigation target first
  (TCP; for https a TLS ClientHello with the name in the SNI). Measured, with the
  causes and limits in [browser-scope-boundary.md](browser-scope-boundary.md)
  ("Known gap: connections").
- With a proxy, the dial goes to the proxy, so the IP check sees the proxy's
  address and DNS happens at the proxy (reasoned from the transport wiring).
- **Resource hints** (`<link rel=preconnect|dns-prefetch|prefetch>`, and the
  `Link:` response header) can contact a host without a request the gate sees:
  - `prefetch` is a real request. The gate stops it (measured: an ungated render
    opens a connection to the second host, a gated one opens none).
  - `preconnect` is **not** stopped by the gate. It is inert today because
    Indago's contexts are fresh and off-the-record and Chromium does not
    preconnect there. Measured: a plain Chrome loading the same page opens a
    connection for the tag and the `crossorigin` form; the
    Indago render opens none (`TestIntegrationResourceHint*`). The same Chrome
    with `--incognito` drops from 1 connection to 0 while `prefetch` stays at 1.
    This is an implicit browser property, not a control Indago enforces; the test
    is a canary for it.
  - `dns-prefetch` opens no connection, so the tests cannot see it. In a Chrome
    net-log, the hint made the browser resolve the host name in a normal profile
    and did not in an `--incognito` one (a plain `<img>` resolved it in both, so
    the instrument works). It was **not** measured through Indago's own launch,
    which has no hook to pass `--log-net-log`; that Indago's contexts behave like
    the incognito run is inferred from the preconnect result.
  - A future change to a persistent profile, a different Chromium build, or a
    different launch flag could change all of this without any Indago code
    changing; only the canary would notice, and only for the shapes it covers.

If your engagement needs "never touch private ranges", enforce it outside
Indago (network egress rules); the scope does not provide it.

## 6. Where the check is applied

| path | check | basis |
|---|---|---|
| scan creation | target base URL, every seed, and (for login modes) `login_url` | code, tested |
| raw HTTP requests | every request, and **every redirect hop** before it is sent; at most 10 hops | code (`internal/scan/scoped.go`) |
| browser requests | the scope gate on navigation, subresources, popups, forms, WebSockets (closed) and service workers (blocked); redirect hops via the CDP gate | tested, see `docs/browser-scope-boundary.md` |
| login | initial URL before the browser launches, then the same browser gate; an SSO host must be added to scope explicitly | tested |
| discovery output | each observation is checked again before it is stored or queued | code |

The browser gate decides on the URL Chromium reports for each request. For
redirects it compares the `Location` header itself, so forms where Go and
Chromium would parse a `Location` differently are rejected outright
(`docs/browser-scope-boundary.md`, "Redirect `Location` parsing").

## 7. Consequences for the operator

- Adding an SSO or identity-provider host **authorizes scanning it too**. Add
  only hosts you are permitted to test.
- A host in scope is in scope on **every port and scheme**.
- Use exact hostnames; add subdomains deliberately.
- Prefer excluding by host over excluding by path.
- Scope proves what Indago will not request by name; it does not prove what the
  name resolves to.

## Not verified

- The measured rows describe `Scope.Permits` in isolation. The server-side
  behaviour for `%2e%2e` and the effect of an unusual hostname on each target
  server were not tested.
- Rebinding and private-range behaviour are from reading the code; no test
  resolves a name to a private or link-local address, and the claim that private
  ranges are not blocked is untested.
- The link-local test covers literal addresses and a redirect hop in the raw
  engine. Its interaction with proxies is reasoned, not tested.
- The absence of an IP check in the browser is from searching the source; no
  test makes Chromium connect to a link-local address.
- Resource hints: only the shapes in `resource_hint_integration_test.go` are
  asserted (tag, `crossorigin`, `prefetch`), against Chrome 155 on loopback
  names. A preconnect sent as a `Link:` response header is **not** asserted: a
  plain Chrome opened a connection for it locally (155.0.8059.39, 4 of 4) but not
  on the CI runner (155.0.8059.84, 1 of 1), so its control was unreliable and the
  CI run caught it. Whether that is flakiness or a build difference was not
  established; treat the header form as unmeasured. The canary has not been mutation-tested,
  because losing the property needs a production change (a non-incognito
  context); the plain-Chrome control is what shows it can discriminate. Early
  Hints (103), `prerender`/speculation rules, and `<a ping>` were not tried.

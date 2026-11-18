# What project scope decides, and what it does not

Scope is Indago's safety boundary: nothing outside it should be requested. This
page states exactly what the matcher compares, so an operator does not assume a
guarantee it does not give. Each statement is labelled with its basis:

- **measured**: pinned by `internal/domain/scope_semantics_test.go` and
  `internal/domain/scope_wildcard_test.go` (change the matcher and these tests
  fail, which forces this page to be revisited)
- **code**: read from the source, no dedicated test
- **reasoned**: inferred, not demonstrated

> **Note on AGENTS.md.** AGENTS.md §2.1 still describes the historical
> hostname-only matcher ("a host in scope is in scope on every port and
> scheme"). Agent-instruction files are intentionally not edited by this
> change; the origin rules in §1a are the current behaviour, and this page plus
> the tests it names are authoritative where the two differ. New scopes must
> state a scheme/port policy; only a stored scope from before the feature gets
> the legacy any-scheme/any-port behaviour.

## 1. The decision is made on the hostname and path, plus an optional origin list

`Scope.Permits(url)` applies two layers:

1. the historical **hostname + path** decision (the table below); and
2. an **optional scheme/port requirement** (`allowed_origins`). A scope with an
   empty origin list is a *legacy* scope and layer 2 is not applied at all; see
   §1a for the rules, the compatibility promise and the write-surface defaults.

| ignored | consequence | basis |
|---|---|---|
| port (legacy scope, no `allowed_origins`) | `example.com` permits `:1`, `:8443` and `:65535` alike. An internal admin service on another port of an in-scope host is in scope | measured |
| scheme (legacy scope) | `http`, `https` and `ftp` URLs to an in-scope host all pass | measured |
| port/scheme (scope WITH `allowed_origins`) | **not ignored**: the URL must match an entry's scheme, effective port and host pattern, on top of the host/path rules | measured (`internal/domain/scope_origin_test.go`) |
| query and fragment | `?next=/app` or `#/app` never helps a URL match a path rule | measured |
| the IP the name resolves to | see section 5 | code |

A legacy scope cannot say "only port 443", so if a host runs something you are
not authorized to test on another port, save the scope with an explicit origin
list. Indago does not derive one from the hostname: the operator states the
scheme and port they are authorized to test.

### 1a. Origin rules (`allowed_origins`)

An entry is `scheme://host[:port]`:

- `scheme` is `http` or `https` — the only schemes Indago requests;
- an omitted port means the scheme default (`http` → 80, `https` → 443), and an
  explicit default port is normalised to the same entry (`https://a:443` is
  `https://a`);
- the host is a bare hostname/IP, or `*.example.com` for **strict subdomains**
  (never the apex; add an exact entry for the apex).

**One entry, one permission.** A URL is permitted only when its scheme, its
effective port AND its host all come from the **same** entry. The list is never
turned into a global "schemes" list times a "ports" list times a "hosts" list:

| stored entries | `https://a:8443` | `http://b:8080` | `https://b:8443` | `http://a:8080` |
|---|---|---|---|---|
| `https://a:8443`, `http://b:8080` | yes | yes | **no** (port from a, host from b) | **no** (scheme/port from b, host from a) |

That is measured by `TestScopeOriginNeverCrossesHostsOrAssets`,
`TestScopeOriginWildcardDoesNotBorrowSiblingOrigins` and the API-level
`TestScopeAPIOriginsDoNotCrossAssets`. A wildcard entry is bound to its own
base in the same way.

When the list is non-empty it is an **additional** requirement: a URL must pass
the host rules, the path rules and the origin match. It can only narrow a scope,
never widen it, and it does not change any path-prefix rule.

Precedence, deliberate and fail-closed:

| stored shape | behaviour |
|---|---|
| `allowed_origins` non-empty | enforced, even if `allow_any_scheme_ports` is also set by a hand-edited row |
| `allowed_origins` empty, `allow_any_scheme_ports` false | **legacy**: any scheme, any port of an in-scope host. This is what every scope saved before the feature has |
| `allowed_origins` empty, `allow_any_scheme_ports` true | legacy, explicitly chosen and recorded at save time |

`allow_any_scheme_ports` never widens a scope that has an origin list: it is a
write-surface annotation for "I knowingly chose the legacy behaviour".

**What a save does** (API `PUT /api/projects/{id}/scope`, CLI `scope set`, the
bundled UI and the bug-bounty importer):

- **Nothing is derived or guessed.** A new scope must name `allowed_origins` or
  set `allow_any_scheme_ports: true`; a host-only save is a 400 that names both
  choices and stores nothing. An explicit empty origin list without the opt-out
  is refused too: "empty" means every scheme and port, which is never chosen
  implicitly.
- The **importer** takes each asset's own scheme and port from the asset URL:
  `https://app.example.com` authorizes `https://app.example.com:443` and not
  `http`, not `:8443`. A wildcard asset **must state its scheme**
  (`https://*.example.com`); a scheme-less `*.example.com` is skipped and
  reported, because its scheme/port is not in the source. Import never sets
  `allow_any_scheme_ports`.
- A save that **omits** `allowed_origins` keeps the stored list (so a UI that
  does not render the field cannot erase a restriction). Editing a path prefix,
  an exclusion or any unrelated field never re-derives it.
- Adding a host without an origin for it is refused: every named host must be
  covered by a declared origin, so a host is never silently dead and never
  inherits a guessed scheme/port. Removing a host drops that host's entries
  (a narrowing) and the save succeeds without restating the list.
- A **legacy** scope keeps its stored behaviour on a save that changes nothing
  (or only narrows). Extending it to a new host requires a policy: the stored
  scope never authorized that host, so inheriting any-scheme/any-port would be
  a widening nobody asked for.
- `allowed_origins` and `allow_any_scheme_ports: true` are mutually exclusive in
  one request; the server refuses the combination.

Origin host patterns must be authorized by the scope's own host lists (an origin
for a host the scope never included is refused at save time).

**CONNECT boundary.** `Scope.PermitsHost` is used where only `host:port` is
visible (a proxy CONNECT): it applies the port half of the rule, and the port is
normalised the same way (an entry without a port has 80 or 443). It cannot see
the scheme, so a port declared for the host under *either* scheme is accepted
there — that is a documented blind spot of that boundary, not an origin match.
A port declared for a different host is never accepted, a bare authority with no
port is denied (fail closed), and the request that follows the tunnel is still
checked against the full `Permits`, scheme included.



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
| `https://example.com` | never matches as a host entry | `example.com`, plus `allowed_origins: ["https://example.com"]` |
| `example.com:8443` | never matches as a host entry (port is not part of the hostname) | `example.com`, plus `allowed_origins: ["https://example.com:8443"]` |
| `*.example.com` | never matches as an include entry | `.example.com`, or `example.com` with allow subdomains. (A program's `*.example.com` asset is imported into `subdomain_only_hosts` instead — see §3) |
| `example.com/` | never matches | `example.com` |
| `[::1]` | never matches | `::1` (IPv6 without brackets) |
| `bücher.example` | a Unicode URL host does not match the punycode entry (measured); Chromium reports punycode hosts, so enter the punycode form (reasoned) | `xn--bcher-kva.example` |

This fails closed, and since validation was added the operator is told at save
time instead of discovering "host not in scope" later. The validator rejects
exactly the shapes that cannot match; it does **not** reject entries that match
more or less than they read (path prefixes with no segment boundary,
case-sensitive paths): those stay documented here. A host entry never carries a
port or scheme; those are declared separately in `allowed_origins` (§1a). Path
prefixes are validated too: they must start with `/` and contain no `?`, `#`,
whitespace, `://` or dot-segment. Existing scopes saved before this check are not
migrated; a bad entry in one still just matches nothing until it is re-saved.
Case does not matter for hosts (measured).

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
- `subdomain_only_hosts` is the third shape and the only one that means
  "subdomains, **not** the host". Entries are bare hostnames: `example.com`
  there authorizes `a.example.com` and `a.b.example.com`, and denies
  `example.com` itself (measured). It exists because neither of the other
  shapes can express it: a leading dot in `include_hosts` always includes the
  base host, and an entry in `exclude_hosts` honours allow-subdomains, so it
  would drop the subdomains too. Path and exclude rules apply to it exactly as
  they do to an included host.
- Only the bug-bounty importer writes `subdomain_only_hosts` today. A scope PUT
  that omits the field keeps the stored list (the bundled UI does not render
  it); an explicit empty array clears it. Entries are validated like include
  hosts, and a leading dot or `*.` prefix is refused there rather than
  reinterpreted — this list already means "subdomains only", so writing the
  wildcard spelling would be ambiguous (measured:
  `internal/web/scope_subdomain_test.go`, `internal/domain/scope_wildcard_test.go`).

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

**Path prefixes are scope-wide, not per host.** `Permits` applies every stored
prefix to every in-scope origin, so a scope cannot express "host a only under
`/app`, host b only under `/api`". The bug-bounty importer enforces that: a
program whose paths are bound to different hosts, schemes/ports or wildcards is
**refused** (no project, no scope, nothing authorised) with a reason naming the
conflicting origins, instead of being flattened into a scope that authorises the
cross product (`https://a.test/app` + `https://b.test/api` would otherwise also
permit `https://a.test/api` and `https://b.test/app`). A manual `PUT` is not
refused for spanning hosts — the operator writes the one global list they mean
(a prefix that cannot be matched safely is still rejected at save time, see §2).

Scopes written before this check (or by an older import) are **not** rewritten:
the importer cannot tell a cross-product scope from a manually written one, and
silently narrowing a stored scope would break scans behind the operator's back.
Re-import the program into a fresh project, or narrow the prefix list by hand.
See `docs/bounty.md` for the importer's exact rule.

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

The scheme/port rule lives inside `Scope.Permits`, so every row above inherits it
without a separate check: raw HTTP requests and **every redirect hop**
(`internal/scan/scoped.go`), the browser gate (navigations, subresources,
popups, CDP redirect hops), login, scan creation and discovery output. The
host-only CONNECT boundary (`Scope.PermitsHost`) applies the port half of the
rule, because it never sees a scheme.

## 7. Consequences for the operator

- Adding an SSO or identity-provider host **authorizes scanning it too**. Add
  only hosts you are permitted to test.
- A legacy scope (no `allowed_origins`) is in scope on **every port and
  scheme**. A scope with an origin list is in scope only on the declared
  scheme/port: `https://app.example.com` does not authorize `http`, nor
  `:8443`. New scopes must declare their origins (or explicitly choose the
  legacy behaviour); the importer takes them from the asset URL.
- **Requests, not connections.** The origin rule is enforced on HTTP requests
  (including redirect hops) and on browser requests. It does **not** stop
  Chromium's TCP preconnect for a navigation target: the browser can open a
  connection (and send a TLS ClientHello carrying the SNI) before the request
  is refused. This is the known gap in
  [browser-scope-boundary.md](browser-scope-boundary.md) ("Known gap:
  connections"); no test in this feature measures or prevents it.
- Origins are declared separately from hosts. A host entry never contains a
  port or scheme; write those as `allowed_origins` entries.
- Use exact hostnames; add subdomains deliberately.
- An exact asset and a wildcard asset are not the same permission: the first
  authorizes that host only, the second authorizes its subdomains and not its
  apex. Importing a program keeps them apart; a manual scope save never turns
  one into the other.
- Prefer excluding by host over excluding by path.
- Scope proves what Indago will not request by name; it does not prove what the
  name resolves to.

## Not verified

- The measured rows describe `Scope.Permits` in isolation. The server-side
  behaviour for `%2e%2e` and the effect of an unusual hostname on each target
  server were not tested.
- Origin rules are unit-tested (`internal/domain/scope_origin_test.go`), tested
  at the scan redirect layer on loopback (`internal/scan/scoped_origin_test.go`),
  and covered by two real-browser tests that serve the page, the sibling port and
  the redirect on `127.0.0.1`
  (`internal/browser/origin_scope_integration_test.go`). Those tests count
  **HTTP requests** at the second origin; they do not observe TCP connections,
  so they do not prove the preconnect gap is closed (see §7). The browser tests
  lower Chromium's sandbox only when `INDAGO_TEST_BROWSER_NO_SANDBOX=1` is set
  for a restricted local test host; they were run that way here.
  `PermitsHost`/CONNECT has unit tests only — no proxy integration test.
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

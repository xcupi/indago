# Local scope proxy (egress primitive)

Status: **not wired into the browser yet.** This page documents a standalone
primitive (`internal/scopeproxy`) and the measurements behind it. The browser
integration (`ContextOptions.ProxyServer`, the launch flags in
`internal/browser`) and the domain origin/path work are deliberately untouched
so another in-flight change can land first; see §8 for the exact wiring.

## 1. What problem it solves

The browser scope gate refuses *requests* before network dispatch. It does not
prevent Chromium from opening a *connection*: for a navigation to an
out-of-scope URL, Chromium preconnects, so the host sees a TCP connection and,
for https, a TLS ClientHello carrying its own name in the SNI
([browser-scope-boundary.md](browser-scope-boundary.md), "Known gap:
connections"). A page with a third-party `<iframe>` therefore contacts that
third party even though no request, cookie or payload is sent.

`internal/scopeproxy` moves the decision one layer earlier. The browser is
configured to use a **loopback** HTTP proxy; it connects to `127.0.0.1`, states
the destination authority, and the proxy refuses anything the policy did not
permit — **before any DNS query or TCP connect for that destination**. The
browser cannot reach the destination directly: its implicit loopback bypass is
removed, so even a loopback address goes through the proxy, and its own
resolver is neutralised, so a named destination cannot be resolved without the
proxy (§4).

Measured baseline and result (real Chromium, loopback fixtures only):

| setup | out-of-scope listener | proxy decision |
|---|---|---|
| no proxy (the gap as documented) | **2 direct TCP connections** (the test asserts > 0, not the exact count) | — |
| proxy + `ChromiumArgs` | **0 connections** | `policy_denied` for the exact authority |

## 2. Scope of this slice

Implemented:

- `Server` (loopback-only listener), `Policy`, absolute-form forwarding,
  CONNECT tunnelling, strict authority parsing, audit `Event`s and counters.
- `ChromiumArgs`, the switches that point Chromium at the proxy and remove its
  two escape hatches. Pure function, no browser import.
- Loopback unit tests and real-Chromium tests (§9).

Not implemented, deliberately:

- Chaining to an operator-supplied proxy (refused, §6).
- TLS interception. https is tunnelled end to end; the proxy never sees
  plaintext, cookies or credentials.
- Any change to `internal/browser`, `internal/verification`,
  `internal/domain/core.go`, `scope_origin.go` or `scope_path.go`.
- An OS-wide firewall. Only processes configured to use this proxy are
  constrained.

## 3. What the proxy decides

Two request forms arrive at an HTTP proxy, and both are checked separately.

| input | accepted? | rule |
|---|---|---|
| `CONNECT host:port` | yes | authority-form only; **a port is mandatory** (there is no scheme to imply one); a missing port is refused, not defaulted |
| `CONNECT` with userinfo / path / scheme / fragment / escape / backslash | no | `parseAuthority` refuses every character that a second parser could read differently |
| `[::1]:8443`, `127.0.0.1:8080` | yes | canonical literals only; IPv4-mapped (`[::ffff:127.0.0.1]`) is refused because Go and WHATWG serialize it differently |
| `2130706433:80`, `0x7f.0.0.1:80`, `01.2.3.4:80` | no | non-canonical IPv4 spellings: `net.ParseIP` rejects them, libc resolvers and WHATWG accept them |
| `example.com.:443` | no | a trailing dot is a different spelling of the same name; the scope matcher denies it too |
| `GET http://host[:port]/path` | yes | absolute-form `http` only; the port defaults to 80 |
| `GET https://host/path` | no (501) | https is reached through CONNECT; a proxy that spoke TLS itself would be an interceptor |
| origin-form `GET /path` | no (400) | a scope proxy cannot know where that goes; only a transparent proxy would, and that is not this |
| `GET http://a/ HTTP/1.1` with `Host: b` | `Host` ignored | RFC 7230 §5.4: a proxy replaces the received Host with the request-target's authority. `net/http` does this before the handler; the origin therefore sees the **checked** authority (asserted) |
| malformed request-target | no (400) | refused before parsing a policy question |

The forwarded request-target is the **exact byte suffix** cut from the raw
request-target, cross-checked against what `net/url` would serialise; if those
two disagree, nothing is forwarded. Path and query encoding therefore reach the
origin unchanged, which matters for a tool that verifies reflections.

The policy receives `(host, port)` with the port already concretised, so a
host-only allowlist cannot accidentally authorise every port:

```go
proxy, err := scopeproxy.New(scopeproxy.Config{
    Policy: scopeproxy.PolicyFunc(func(host string, port int) bool {
        // Later wiring: scope.PermitsHost applies the host rules and the
        // allowed_origins port rules at this authority boundary.
        return scope.PermitsHost(net.JoinHostPort(host, strconv.Itoa(port)))
    }),
})
```

`PermitsHost` sees no path (docs/scope-semantics.md §1a), so this layer is a
*host/port* boundary, never a replacement for the per-request scope gate. It is
narrower than that gate, never wider: an authority it refuses cannot be reached
even if some later request would have had an in-scope path.

## 4. Chromium wiring and the two escapes

`ChromiumArgs(proxyURL)` returns exactly four switches:

```
--proxy-server=http://127.0.0.1:PORT
--proxy-bypass-list=<-loopback>
--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ::1
--dns-prefetch-disable
```

Why each exists, and what was measured:

- **Proxy server.** Only loopback literals with an explicit port are accepted; a
  name, credentials, a path or any non-`http` scheme is refused, so the browser
  never needs DNS to find the proxy.
- **`<-loopback>`.** Chromium's implicit proxy bypass list always contains
  localhost/loopback. Without this switch a target on `127.0.0.1` is reached
  **directly** and the proxy sees nothing — measured: the control test reaches
  the out-of-scope listener and the proxy records **zero** loopback events.
  With it, the same request arrives as `http://127.0.0.1:PORT/` and is allowed
  or denied by the policy.
- **Host resolver rules.** Every *name* lookup inside Chromium fails, so a
  preconnect/dns-prefetch/browser background lookup cannot leak a name, and a
  proxied navigation does not need an answer (the proxy resolves it).
  **The `EXCLUDE`s are required and were measured, not assumed:** Chromium
  applies these rules to address literals too, so `MAP * ~NOTFOUND` alone made
  `http://127.0.0.1:PORT/` fail with `ERR_NAME_NOT_RESOLVED` and an
  IPv6-loopback proxy fail with `ERR_PROXY_CONNECTION_FAILED`. `EXCLUDE ::1` is
  what makes `[::1]` work.
- **`--dns-prefetch-disable`.** Removes the hint-driven resolver path.

The sandbox is untouched: `ChromiumArgs` never emits `--no-sandbox` (a unit
test asserts it), and this package has no way to launch a browser.

Side effect worth recording: with the proxy in place, Chromium's own background
traffic (`clients2.google.com`, `accounts.google.com`, `www.google.com` in the
measured run) arrives at the proxy and is **denied before dialling**. Those
requests are browser-initiated rather than page-attributed, which is why they are
worth containing at the socket layer as well as at the request gate.

## 5. DNS

- A literal address is never resolved.
- A name is resolved **once**, **after** the policy allows the authority, by
  the injected `Resolver`; the proxy then dials the **literal address it
  resolved**. `Transport` never resolves on its own (a `DialContext` is
  installed), so a second resolution cannot redirect the connection between the
  check and the dial.
- `PermitAddress` (optional) filters every resolved address before dialling; the
  intended use is an IP-level policy (private/link-local ranges). It is a hook,
  not a default policy: the default is whatever the host's resolver returns,
  which is the same "scope is not an IP policy" position as
  [scope-semantics.md](scope-semantics.md) §5.
- A name that cannot be resolved, or whose addresses are all refused, denies the
  request (502) with `resolve_failed` / `no_permitted_address`.
- Denied authorities never reach the resolver at all — measured with a recording
  resolver: an out-of-scope name produced **zero** lookups, and the in-scope name
  produced exactly one.

What is **not** guaranteed: the host resolver itself, the OS hosts file, and any
egress that bypasses this proxy. Chromium's hard-coded bootstrap lookups are
prevented by §4's rules, but a different browser build or a future flag change is
not covered by any test here except the ones in §9.

## 6. Operator-proxy chaining: refused

`Config.UpstreamProxy` exists only so the combination is an explicit error
(`ErrUpstreamProxyUnsupported`), not a silently ignored field. The scope decision
would still be made locally (the CONNECT authority or absolute-form target is
checked first), but the **destination name would be resolved by the operator's
proxy**, on the operator's host, outside this process. At that point:

- the "only the allowed name is ever looked up" property is unverifiable here;
- `PermitAddress` cannot be applied to the answer;
- a SOCKS5 upstream would move the authority format and DNS mode entirely.

A mode whose DNS guarantee cannot be demonstrated is not shipped as if it had
one. Chaining therefore fails closed until a separate, measured design exists
(and, per AGENTS.md §2.2, that decision belongs to the operator-facing policy,
not to this package).

## 7. Failure modes are denials

`New` refuses: a nil policy, a non-loopback listener, an upstream proxy.
The request path denies (403/400/501/502/503) on: malformed authority,
origin-form, https absolute-form, a policy that panics (recovered, recorded as
`policy_panic`), an over-limit connection count, a resolver error, an address
refused by `PermitAddress`, a failed dial, and a transport dial that does not
match the validated authority (`dial_target_mismatch`). Denials are counted and
audited with a stable `Reason`; nothing is retried through another path.

Tunnels are bounded: `TunnelTimeout` (default 10m) closes a tunnel even if it is
active, and `MaxConnections` (default 64) refuses rather than queues beyond it.
Listener binding is verified loopback **after** the bind (`0.0.0.0:0` is
refused), so a misconfigured address cannot expose the proxy to the network.

## 8. Wiring (for the next slice, not done here)

1. Create the proxy with a policy derived from the project scope
   (`Scope.PermitsHost` at the authority boundary), and one proxy per scan or
   per browser context.
2. Pass `proxy.ProxyURL()` as `ContextOptions.ProxyServer` and add
   `ChromiumArgs(proxy.ProxyURL())` to the launch args (the driver currently
   passes only `--disable-blink-features=SharedWorker`).
3. Map `Event`s into the scan's log/evidence so a refusal is visible.
4. Keep the existing request gate. The proxy constrains *where a socket may
   go*; the gate still enforces *which request* (path, method, redirect hop).
5. Do not enable chaining: `Config.UpstreamProxy` must stay empty, or scan
   creation must reject the combination explicitly (§6).

## 9. Validation

Unit and loopback tests (`internal/scopeproxy/proxy_test.go`,
`chromium_test.go`) — no browser, milliseconds:

| test | what it pins |
|---|---|
| `TestParseAuthorityRejectsMalformedShapes` | 30 malformed/ambiguous authority shapes (userinfo, escapes, backslash, IPv4 aliases, bracketed non-IP, bare v6, IPv4-mapped) |
| `TestParseAuthorityAcceptsBareAndCanonicalForms` | the shapes that must keep working |
| `TestSameTargetMatchesOnlyTheValidatedAuthority` | a transport dial may not leave the checked destination (other host/port/no-port/non-numeric) |
| `TestAuditAuthorityIsBoundedAndStripped` | an audited authority cannot carry CR/LF or exceed 512 bytes |
| `TestSplitAbsoluteTarget` | absolute-form parsing, https/origin-form/fragment refusal, byte-exact suffix |
| `TestNewRequiresPolicy` / `RefusesNonLoopbackListener` / `RefusesOperatorProxyChain` | construction fails closed |
| `TestForwardAllowedReachesOriginWithExactTarget` | forwarding works and the origin sees `%2F`, `%20` unchanged |
| `TestForwardDeniedOnWrongPortIsNeverDialled` | host+port allowlist; zero connections to the denied listener |
| `TestForwardDeniedHostIsNeverResolved` | denied name → zero resolver calls |
| `TestForwardOriginFormAndHTTPSAbsoluteFormFailClosed` | origin-form, https absolute-form, and Host-header substitution |
| `TestForwardPolicyPanicDeniesWithoutDialling` | a panicking policy denies |
| `TestForwardDialFailureIsRecordedAndDenied`, `ResolveFailureDenies`, `PermitAddressRefusesResolvedAddress` | failures are denials, never forwards |
| `TestConnectAllowedTunnelsToOrigin` | CONNECT tunnel end to end |
| `TestConnectDeniedOnPortNeverConnects` | denied CONNECT: no connection, no DNS |
| `TestConnectMalformedAuthoritiesFailClosed` | 15 malformed CONNECT targets, no connection, no DNS |
| `TestConnectionLimitRefusesInsteadOfQueueing` | 503 instead of queueing |

Real Chromium (run with `-count=1`):

| test | measured result |
|---|---|
| `TestChromiumWithoutProxyReachesOutOfScopeLoopback` | baseline: **2** direct connections |
| `TestChromiumScopeProxyRefusesOutOfScopeLoopback` | proxied: **0** connections, `policy_denied` for the exact authority, in-scope page loaded |
| `TestChromiumLoopbackBypassIsLoadBearing` | without `<-loopback>`: direct connection, **zero** loopback events at the proxy |
| `TestChromiumHostResolverRulesBlockBrowserDNS` | name → `ERR_NAME_NOT_RESOLVED`, literal still loads, **0** connections behind the name |
| `TestChromiumProxyCarriesNamesWithoutBrowserDNS` | unresolvable-in-browser name loads through the proxy; only `in-scope.test` was resolved; out-of-scope name never looked up; **0** connections |
| `TestChromiumIPv6LoopbackProxyWork` | an `[::1]` proxy and origin work with the full rule set (pins `EXCLUDE ::1`) |

Environment for those runs, stated so it is not over-read: Chromium build
`chromium-1234` via Playwright driver 1.62.1, loopback only (no external
network was used by any fixture), and **`INDAGO_TEST_BROWSER_NO_SANDBOX=1`** was
required on the development host — a sandboxed launch aborts there with
`SIGABRT` before any page loads. The proxy and its switches do not depend on the
sandbox state, and `ChromiumArgs` never disables it; the production default
(sandbox on) is unchanged, and a sandboxed run of these same tests has not been
performed on this host.

## 10. Limits (what this does not claim)

- **Not an OS firewall.** A process that ignores `--proxy-server` (or a
  different browser binary/flags) is not constrained.
- **No path or method authority.** The proxy authorises host/port only; the
  request gate remains the authority for path, method and redirect hops.
- **No TLS inspection**, by design; https destinations are identified only by
  the CONNECT authority and SNI is inside the tunnel.
- Chromium's own traffic that does not use the proxy (crash reporting, updates,
  external handlers, WebRTC/STUN, any future non-proxied path) is outside this
  primitive's reach; §4 reduces it but does not audit it.
- The rules were measured on one Chromium build. A different build could change
  the implicit bypass or the resolver-rule matching; the control tests in §9 are
  what would notice.
- Chaining to an operator proxy, SOCKS, and any DNS guarantee beyond this
  process are not provided (§5, §6).

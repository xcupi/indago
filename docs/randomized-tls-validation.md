# Randomized outbound TLS: key share, ALPN and cipher compatibility

These fixes affect only scans that explicitly opt into
`-randomize-tls-fingerprint`. API/listener TLS, scope checks, scan pacing,
proxy exclusivity and the browser's own TLS stack are unchanged.

## 1. Hybrid-group retry failure

uTLS v1.8.2's randomized spec can advertise `X25519MLKEM768` without
sending its key share. A server preferring that group sends a
HelloRetryRequest; this uTLS version cannot generate the hybrid key in the
retry path and returns `tls: CurvePreferences includes unsupported curve`.
The spec is now generated explicitly and given the missing hybrid share
before `HelloCustom` / `ApplyPreset` generate key material.

The initial measurements were 45 failed runs out of 300 for
`TestRandomizeTLSFingerprint_RealHandshake`, and 57 failed handshakes out
of 400 in the new regression. A final approved mutation check temporarily
disabled `ensureHybridKeyShare`, observed **57/400 failures with the exact
retry error**, then restored the original file byte-for-byte in a `finally`
block. This proves that the regression's precise assertion still detects
the bug. The restored source passed full `make check` before the local
curve-fix commit was amended (unpublished history only).

Pure tests also cover adding the share, preserving an existing share,
preserving specs without that group or without a key-share extension,
and consistency across 1,000 freshly randomized specs.

## 2. HTTP/2 ALPN mismatch

The old comment claiming that h2 only affected connection efficiency was
incorrect. The dialer returns `*utls.UConn`, whereas `net/http.Transport`
discovers negotiated ALPN only from a stdlib `*tls.Conn`. A randomized
hello offering h2 can make the server select HTTP/2 while Transport still
sends an HTTP/1.1 request. The server logs a bogus HTTP/2 preface and the
client reports a malformed HTTP response containing HTTP/2 SETTINGS bytes.

The fix restricts any ALPN extension to `http/1.1` and removes ALPS
application-settings extensions (both codepoints). Specs without ALPN stay
without it; other extensions retain their order and identity. Randomization
remains opt-in. This path is intentionally **HTTP/1.1-only**, not a new
HTTP/2 implementation. Targets requiring h2-only are not supported in this
mode; the default stdlib path and Chromium are not changed.

### RED / GREEN

Before the ALPN fix:

- The generated-spec assertion failed with `ALPN = [h2 http/1.1]`.
- Actual round trips against an h2-enabled `httptest` server failed with
  malformed HTTP responses, both with default TLS versions and TLS 1.2-only.
  Unlike `httptest.NewTLSServer`, these fixtures explicitly enable HTTP/2.

After the fix:

- Those tests pass (100 fresh connections per server/version).
- Tests preserve unrelated extensions, no-ALPN behavior and idempotence,
  and verify that an untrusted certificate is still rejected before HTTP.
- `go test ./internal/httpengine -count=40 -json`: exit 0, 1,280 test pass
  events, no failed events, no other handshake rejections logged. This
  includes 400 direct handshakes and 200 h2-capable-server round trips per
  repetition; it is not a cached single run.
- Full `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check` passed after
  implementation, followed by an uncached `go test -race -p 1 -count=1 ./...`
  with the same Chromium environment; every package passed. Final push/CI
  status must be checked on its exact HEAD, not inferred from this local gate.

## 3. Real CLI differential validation

A disposable Go HTTPS loopback server enabled its normal HTTP/2 support,
used the default hybrid-group preference and a one-day IP-SAN certificate.
HTTP/1.1 responses sent `Connection: close` to force fresh handshakes.
All runs used strict certificate verification (`SSL_CERT_FILE` pointed at
that scratch certificate), without insecure-skip flags. Identical CLI
project/scope/target/scan flows used fast profile, depth 2 and minimal
candidates. No real targets or production database were used.

| Binary / option | Served requests | h2 bad prefaces | TLS handshake errors | Jobs succeeded / dead | Test cases completed / failed / skipped |
|---|---:|---:|---:|---:|---:|
| Curve fix only (`f24235d`), randomization on | 3 | 11 | 0 | 1 / 3 | 1 / 9 / 0 |
| Curve + ALPN fix, randomization on | 65 (HTTP/1.1) | 0 | 0 | 39 / 0 | 34 / 0 / 5 |
| Same fixed binary, randomization off | 65 (HTTP/2) | 0 | 0 | 39 / 0 | 34 / 0 / 5 |

The randomized fixed run offered h2 zero times. The stdlib control really
served 65 requests as HTTP/2, proving the fixture supported it and that
ordinary TLS was not globally pinned to HTTP/1.1. Both clean runs discovered
six endpoints, versus one in the broken baseline. All scan state labels
were `completed`; **that label alone did not mean error-free**.

Both clean runs had five Pending findings and five skipped browser
verifications because no browser was enabled. The lab escapes reflected
HTML and no Confirmed findings were produced. This validates transport and
request delivery, not browser XSS verdict accuracy.

Exact scratch database readback confirmed the test-case status totals and
dead-job counts after shutdown. All three owned Indago processes exited 0;
the lab processes were stopped and their exact listener ports were closed.
Nonsecret results are retained at
`$HOME/.hermes/cache/scratch/indago-tls-final-results.json`; repeated-test
JSON is `indago-tls-repeat.jsonl` in the same parent directory. The exact
`tlsfix` fixture directory (certificates, private keys, lab binaries, scripts
and databases) was removed after verifying owned process exit and closed
ports. Safe RED logs remain under `indago-tls-evidence/` in the same scratch
parent, outside the removed fixture. No dummy material is committed.

## 4. Rare handshake alert: certificate-family cipher gap (resolved)

The earlier stress run observed `remote error: tls: handshake failure` once
in roughly 16,000 handshakes; a later 60,000-handshake probe saw none. At
that point the cause was unknown and the hybrid regression temporarily
allowed four unrelated rejections per 400 attempts. **That tolerance has now
been removed.** A successful random run was not the proof of resolution;
deterministic seed replays identified the following failure.

### Root cause and deterministic RED

uTLS randomly removes cipher suites without guaranteeing overlap for both
certificate families. Rare TLS1.2-only hellos lose every ECDHE-RSA suite
accepted by a default modern Go server; other seeds do the same to ECDSA.
The remaining legacy RSA key exchange / disabled suites and wrong-family
ECDHE suites do not help. The server reports
`tls: no cipher suite supported by both client and server`; the client only
receives the generic handshake-failure alert.

Enumerating SHA256 seeds of `indago-tls-investigation-N` found RSA failures
at N=57744, 126896, 128509, and ECDSA failures at N=118781, 253463. These
public PRNG seeds (not cryptographic keys) are fixed regression fixtures in
`tls_cipher_test.go`. The first RSA seed reproduced the precise client
alert and server rejection **5/5 times**. Before the fix all five seed-based
HTTP round trips failed, including two ECDSA certificate cases. No races,
network loss or signature-algorithm guesses were needed to reproduce it.

### Fix and strict tests

`ensureTLS12AEADCiphers` retains at least one TLS1.2 ECDHE+AEAD suite for
RSA and one for ECDSA. It recognizes AES-128-GCM, AES-256-GCM and ChaCha20
for each family, and appends AES-128-GCM only when a family has no such
suite. Existing order and choices are retained; already compatible hellos
remain unchanged. The floor applies to TLS1.3-capable hellos too because
they may connect to a TLS1.2 server. TLS1.3-only specs are unchanged.

No legacy RSA key exchange, CBC, SHA-1 or 3DES suite is added; no protocol
version, trust policy, scope, pacing or proxy behavior is changed. There is
no retry/fallback on rejection. Production still creates a fresh PRNG seed
per connection. The internal spec function accepts a ClientHelloID solely
to let tests replay seeds without changing globals or exposing a user flag.

- All five known-bad seed replays now pass with trusted-CA verification
  enabled, including actual request/response delivery and h2-enabled servers.
- Unit controls preserve existing AES-256/ChaCha choices, suite order,
  idempotence and TLS versions, including TLS1.3-only specs.
- The 400-handshake randomized regression now fails on **any** handshake
  error, without tolerance or an ignored error category.
- `go test ./internal/httpengine -count=100 -json`: exit 0, 4,600 passing
  test events, zero failed events. Parsed test events verify 40,000 strict
  direct handshakes, 20,000 h2-server HTTP round trips and 500 deterministic
  bad-seed round trips in that run. No cache-only inference.
- Full `INDAGO_CHROMIUM_PATH=/usr/bin/google-chrome make check` passed.

### Real CLI validation (RSA and ECDSA)

Separate loopback targets used RSA-2048 and P-256 ECDSA IP-SAN certificates
and default server cipher policy, with TLS1.2 minimum and maximum to keep
the case discriminative. HTTP/1.1 responses closed the connection to force
fresh handshakes. All scans enabled randomized TLS, used fast profile,
minimal candidates and depth 2; server trust came from `SSL_CERT_FILE`,
never an insecure-skip option. Data directories were scratch-only.

For reproducibility, **test-only Go build overlays** made the CLI use one
known-bad seed per family. The baseline overlay omitted just the cipher-floor
call; the fixed overlay kept it. Neither overlay edited repository source,
and these are explicitly not historical/release binaries. Two additional
scans used the normal, unmodified/unseeded production build.

| Certificate / build | Served requests | No-common-cipher rejections | Succeeded / dead jobs | Completed / failed / skipped tests |
|---|---:|---:|---:|---:|
| RSA, seeded baseline | 0 | 18 | 0 / 5 | 0 / 15 / 0 |
| RSA, seeded fixed | 46 | 0 | 28 / 0 | 24 / 0 / 4 |
| RSA, normal unseeded fixed | 46 | 0 | 28 / 0 | 24 / 0 / 4 |
| ECDSA, seeded baseline | 0 | 18 | 0 / 5 | 0 / 15 / 0 |
| ECDSA, seeded fixed | 46 | 0 | 28 / 0 | 24 / 0 / 4 |
| ECDSA, normal unseeded fixed | 46 | 0 | 28 / 0 | 24 / 0 / 4 |

The five dead jobs in each baseline recorded the exact remote handshake
alert. Every fixed run had zero handshake errors, zero failed test cases
and four discovered endpoints. Independent read-only queries of the exact
scratch databases verified the stored job and test-case totals. All owned
Indago processes exited 0 and the lab/API listener ports closed.

Each clean scan had four Pending findings/four skipped verifications
because browser verification was off. The target HTML-escaped reflection
and generated no Confirmed findings. This is transport coverage, not a new
browser/XSS accuracy claim. Safe results and stress logs are retained as
`indago-tls-residual-live.json`, `indago-tls-residual-stress.jsonl` and
`indago-tls-residual-stress-counts.json` under `$HOME/.hermes/cache/scratch/`.
The exact `tlsres` fixture directory (overlay builds, scripts, dummy keys,
certificates and databases) was removed after process shutdown; a separate
readback confirmed the directory absent and all 12 recorded listener ports
closed. No fixture/private-key material is committed.

## Remaining limits

`remote error: tls: handshake failure` is a generic peer alert, not a unique
bug identifier. This fix closes the reproducible randomized cipher-family
gap; it cannot make incompatible server policies, missing client certificates,
unsupported protocols or genuine remote rejections disappear. A new alert
must still be diagnosed rather than blindly retried. Randomized mode remains
HTTP/1.1-only. No dependency upgrade, TLS-version downgrade, certificate
bypass, new network path or Chromium sandbox change was introduced; no PR
was merged.

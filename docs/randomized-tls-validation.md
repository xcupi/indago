# Randomized outbound TLS: hybrid key share and ALPN fixes

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

## Limits and remaining investigation

An earlier strict stress run observed one different
`remote error: tls: handshake failure` in roughly 16,000 handshakes; a
subsequent 60,000-handshake probe did not reproduce it. Its cause is not
established, and neither this ALPN fix nor a successful CI run proves it
fixed. The hybrid-retry regression has zero tolerance for the precise
unsupported-curve error, but explicitly logs/tolerates at most four other
rejections in 400 attempts. The h2 round-trip tests remain strict and do
not retry or ignore request failures. This distinction is intentional and
must not be described as universal TLS compatibility or zero flakiness.

No dependency upgrade, TLS-version downgrade, certificate bypass, new
network path or Chromium sandbox change was introduced. No PR was merged.

# Chromium process sandbox

Indago's browser features (`serve -browser`) load pages from the targets you are
testing, which may be hostile. Chromium's **process sandbox** limits what a
compromised renderer can do to the machine running the scanner. It is a
different control from the `sandbox=""` iframe used when *viewing* captured
evidence (see `finding-correlation.md`).

## Policy

- The sandbox is **ON by default**. `browser.Config.DisableSandbox` is `false`
  unless set, and `serve` sets it only from the explicit `-browser-no-sandbox`
  flag.
- There is **no automatic fallback**. If the sandboxed browser cannot start, the
  launch fails with the Chromium error plus a pointer to the opt-out; Indago
  never retries without isolation on its own.
- Opting out logs a `WARN` at startup naming the consequence, and the
  `browser manager started` line records `sandbox=true|false`.
- `-browser-no-sandbox` without `-browser` is refused (exit 1) so it can never
  look accepted while doing nothing.

## What was wrong before

The Playwright launch added `--no-sandbox` because its `chromiumSandbox` option
must be exactly `true` to keep the sandbox (`if (options.chromiumSandbox !==
true) chromeArguments.push('--no-sandbox')` in the driver). Indago never set
the option, so every Chromium process ran without a sandbox.

Measured on the real binary, loopback lab, Chrome 155, Linux 7.0 (kernel):

| Renderer property | Before (Indago) | Same Chrome, sandbox on | After (Indago, default) |
|---|---|---|---|
| `--no-sandbox` flag | yes | no | no |
| `/proc/PID/status` `Seccomp` | `0` (no filter) | `2` (BPF filter) | `2` |
| user / pid / net namespaces | same as scanner | separate | separate |
| UID | scanner's (1000) | scanner's (1000) | scanner's (1000) |

With the explicit opt-out the renderer is back to `--no-sandbox` / `Seccomp: 0`
and the WARN is logged. The same measurement reads differently in each mode, so
the probe discriminates; it reads the kernel's view, not only the command line.

## Regression tests

- `TestIntegrationDefaultConfigRendererIsSandboxed`: real Chromium, every
  renderer must lack `--no-sandbox`, have `Seccomp: 2`, and sit in a different
  **pid and net namespace** from the scanner process. Failed (renderers
  unsandboxed) before the fix.
- `TestIntegrationDisableSandboxIsExplicitOptOut`: the opt-out really disables
  it: `--no-sandbox`, the same pid/net namespaces as the scanner, and no seccomp
  filter beyond what the test process already inherited (proves the probe can
  tell the difference).
- The namespace checks exist because `Seccomp` alone is not discriminating when
  an ambient filter is inherited by every child (Docker default, systemd, a
  wrapped CI runner). The user namespace is deliberately not required: the
  setuid sandbox does not create one.
- Unit tests for the launch-failure hint (and that no retry happens), the WARN,
  and the CLI flag rules.
- Both real-browser tests are **required** by `scripts/ci-browser-check.py`; a
  missing, skipped or failed one fails CI (covered for both tests by
  `deploy/ci_runtime_test.go`), so the sandbox cannot silently degrade into a
  skipped test. Other browser tests also start sandboxed by default, so a host
  that cannot provide the sandbox surfaces as a failed/skipped required test.

## Docker

Measured with an image built from this tree (non-root UID 10001):

| Container setup | Result |
|---|---|
| Docker default seccomp, sandbox on | Fails closed: `No usable sandbox!`, exit 1, with the opt-out hint |
| Docker default seccomp, `-browser-no-sandbox` | Starts, `sandbox=false` |
| `--security-opt seccomp=unconfined`, sandbox on | Browser launches, `sandbox=true` |

So Docker's default syscall filter blocks what Chromium's sandbox needs. The
shipped image therefore passes `-browser-no-sandbox` **explicitly** in its
default command (a visible, documented choice, not a hidden default). To run
sandboxed in a container, remove that flag and relax the container's seccomp
profile; this trades container syscall filtering for Chromium's own sandbox,
and you should prefer a purpose-built profile over `unconfined`. For the third
row only successful launch was measured, not the renderers' seccomp state inside
the container.

## Not established

- Only this host (Ubuntu, kernel 7.0, vendor Google Chrome 155, AppArmor
  `apparmor_restrict_unprivileged_userns=1`) was measured. Other distributions,
  Playwright-bundled Chromium builds, and macOS/Windows were not.
- No exploit was attempted: this shows the sandbox is configured and effective
  (filter and namespaces present), not that an escape is impossible.
- Hosts that cannot provide the sandbox still need the opt-out, which lowers
  isolation; a dedicated disposable VM and restricted egress remain advisable for
  untrusted targets.
- No benchmark of the sandbox's performance cost was made.

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
- The Docker image is covered separately by the CI job `docker-sandbox`
  (`scripts/ci-docker-sandbox-check.py`, see `docs/deployment.md`): fails closed
  under Docker's default seccomp, sandboxed under the recipe below, and an
  unsandboxed control. Its verdict logic is unit-tested with synthetic
  measurements (`deploy/ci_docker_sandbox_test.go`, including that a probe which
  cannot read renderers or reads an unreadable namespace never counts as
  evidence), and deliberately breaking the recipe (dropping `chroot`) was shown
  locally to fail the check, with Chromium's own `sys_chroot` error as the reason.

## Docker

Measured with the image built from `main` (Debian bookworm `chromium`
155.0.8059.79, non-root UID 10001, **no** setuid `chrome-sandbox`, so only the
user-namespace sandbox is possible), run with the hardened flags from
`docs/deployment.md` (`--read-only --cap-drop=ALL
--security-opt=no-new-privileges:true`, AppArmor `docker-default` left on).
"Renderers" are real renderer processes measured from inside the container while
a scan ran; a renderer counts as sandboxed only if it lacks `--no-sandbox` **and**
its net, pid and user namespaces all differ from the scanner's. Seccomp alone is
not used as evidence here: Docker's own filter is inherited by every process, so
`Seccomp: 2` appears even with `--no-sandbox`.

| Container setup | Result |
|---|---|
| Docker built-in default seccomp, sandbox on | Fails closed, exit 1: Chromium reports `No usable sandbox!`; Indago adds the opt-out hint |
| Same, with the upstream moby `default.json` passed explicitly | Identical failure (the file behaves like the built-in profile) |
| Docker default seccomp, `-browser-no-sandbox` | Starts, `sandbox=false`; 10 renderers, all `--no-sandbox`, none isolated |
| `--security-opt seccomp=unconfined`, sandbox on | Starts, `sandbox=true`; 6 renderers, all sandboxed |
| default + `unshare`, `clone` | Fails closed: `Check failed: sys_chroot("/proc/self/fdinfo/")` (Chromium got past namespace creation and needs `chroot`) |
| default + `unshare`, `clone`, `chroot` | Starts, `sandbox=true`; 6 renderers, all sandboxed |
| default + `clone`, `chroot` (no `unshare`) | Fails closed: `No usable sandbox!` |
| default + `unshare`, `chroot` (no `clone`) | Fails closed: `No usable sandbox!` |

So the Docker default blocks the sandbox because `unshare`, `clone` with
namespace flags and `chroot` need `CAP_SYS_ADMIN` / `CAP_SYS_CHROOT` there, and
in this image **each of those three is required** (removing any one fails
closed). `AppArmor docker-default`, `--cap-drop=ALL` and `no-new-privileges` did
not prevent the sandbox once those syscalls were allowed. The shipped image
still passes `-browser-no-sandbox` **explicitly** in its default command, so it
starts anywhere, but with no process sandbox.

### Running the image sandboxed

Derive the profile from **your own Docker version's** default profile (the one
used above is the upstream `moby/profiles` `default.json`; the controls show it
matched this daemon's built-in, but a different Docker may differ) and add only
the three syscalls:

```sh
curl -fsSL https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json -o default.json
python3 - <<'EOF'
import json
d = json.load(open('default.json'))
d['syscalls'].append({'names': ['clone', 'unshare', 'chroot'], 'action': 'SCMP_ACT_ALLOW'})
json.dump(d, open('indago-chromium-seccomp.json', 'w'))
EOF
```

Then run the normal hardened command from `docs/deployment.md`, add
`--security-opt seccomp=$PWD/indago-chromium-seccomp.json`, and override the
command so it does **not** contain `-browser-no-sandbox`:

```sh
... indago:TAG serve -data /var/lib/indago -addr 0.0.0.0:8750 -allow-remote \
    -tls-cert /tls/server.crt -tls-key /tls/server.key -browser
```

Measured with exactly that configuration (strict TLS, bearer token,
`--read-only`, `--cap-drop=ALL`): startup log `sandbox=true` with no DISABLED
warning, 27 renderers measured and all sandboxed, healthcheck `healthy`, the
vulnerable fixture Confirmed (marker-specific browser error) and the safe one
Rejected, project persisted across a restart, graceful stop exit 0, and no token
or key material in the logs.

Prefer this over `seccomp=unconfined`. It is still a **trade-off**: the three
added rules let *every* process in the container create user namespaces, which
enlarges the kernel attack surface available to a compromised process in the
container, and it needs a host where unprivileged user namespaces are allowed
(`user.max_user_namespaces > 0`, and no policy that forbids them). Without the
profile the image fails closed rather than falling back.

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
- Docker: one host, one daemon (Docker 29.9) and one image were measured. The
  added `clone` rule is unconditional; a narrower rule that only admits the
  `CLONE_NEW*` flags Chromium uses was not tried. Rootless Docker, user-namespace
  remapping, Kubernetes seccomp/PodSecurity settings and other distributions
  were not measured. The first Docker experiments used host networking only to
  reach a loopback lab target; the final configuration run used the normal
  published-port setup. Measurements were taken as UID 10001 inside the
  container, the same user as the scanner, so a sandboxed renderer still shares
  the scanner's OS user.

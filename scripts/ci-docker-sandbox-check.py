#!/usr/bin/env python3
"""CI gate: Chromium's process sandbox must work in the shipped Docker image.

Why this exists: the sandbox claims for the image (docs/browser-sandbox.md) were
measured by hand. Nothing in CI built the image or ran it sandboxed, so the
seccomp recipe, the image, or Chromium could regress without anyone noticing.

Two modes:

  --judge sandboxed|unsandboxed FILE
      Pure verdict logic over `docker exec` measurement output. No Docker needed;
      unit-tested from deploy/ci_docker_sandbox_test.go with synthetic input.

  --image IMAGE [--out DIR]
      Full run (needs Docker and network access to fetch the pinned profile):
        A. Docker's default seccomp must refuse a sandboxed PDF export.
        B. The documented seccomp profile must allow PDF export with a
           measured sandboxed renderer.
        C. The explicit opt-out must be distinguishable in process samples.

A renderer counts as sandboxed only if it lacks --no-sandbox AND its net, pid and
user namespaces all differ from the scanner's. Seccomp alone is not evidence:
Docker's own filter is inherited by every process in the container.

Nothing is retried until green. Every failure is reported with its reason.
Loopback only: the lab target and the API live inside the container.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

# Upstream Docker default seccomp profile, pinned to a commit AND a hash so a
# change upstream cannot silently alter what CI measures.
MOBY_COMMIT = "6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef"
MOBY_SHA256 = "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6"
MOBY_URL = f"https://raw.githubusercontent.com/moby/profiles/{MOBY_COMMIT}/seccomp/default.json"
# The documented recipe (docs/browser-sandbox.md): exactly these three syscalls.
RECIPE_SYSCALLS = ["clone", "unshare", "chroot"]

UID = "10001:10001"
API_PORT = 18801

# Runs inside the container as the scanner's UID (readlink on another process's
# namespaces needs the same UID). Prints one ROOT line and one P line per
# Chromium process. An unreadable value is reported as ERR, never guessed.
MEASURE = r'''
root=""
for p in /proc/[0-9]*; do
  c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
  case "$c" in */usr/local/bin/indago*serve*) root=${p#/proc/}; break;; esac
done
[ -z "$root" ] && { echo "NOROOT"; exit 0; }
echo "ROOT net=$(readlink /proc/$root/ns/net 2>/dev/null || echo ERR) pid=$(readlink /proc/$root/ns/pid 2>/dev/null || echo ERR) user=$(readlink /proc/$root/ns/user 2>/dev/null || echo ERR)"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
  case "$c" in *chromium*) ;; *) continue;; esac
  t=browser
  case "$c" in *--type=*) t=$(echo "$c" | sed 's/.*--type=\([^ ]*\).*/\1/');; esac
  ns=0; case "$c" in *--no-sandbox*) ns=1;; esac
  sc=$(sed -n 's/^Seccomp:[[:space:]]*//p' $p/status 2>/dev/null)
  nn=$(sed -n 's/^NoNewPrivs:[[:space:]]*//p' $p/status 2>/dev/null)
  echo "P $pid $t nosandbox=$ns seccomp=$sc nnp=$nn net=$(readlink $p/ns/net 2>/dev/null || echo ERR) pidns=$(readlink $p/ns/pid 2>/dev/null || echo ERR) user=$(readlink $p/ns/user 2>/dev/null || echo ERR)"
done
'''

# In-container lab target: one vulnerable and one escaping page (loopback only).
def parse(text):
    """Return (root, saw_root_line, rows). Latest definite row for a pid wins."""
    root = None
    saw_root = False
    rows = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("ROOT "):
            saw_root = True
            root = dict(x.split("=", 1) for x in line.split()[1:])
        elif line.startswith("P "):
            f = line.split()
            row = {"pid": f[1], "type": f[2]}
            row.update(dict(x.split("=", 1) for x in f[3:]))
            row["definite"] = "ERR" not in (row.get("net"), row.get("pidns"), row.get("user"))
            # An unreadable sample must not overwrite an earlier definite one.
            if row["definite"] or f[1] not in rows or not rows[f[1]]["definite"]:
                rows[f[1]] = row
    return root, saw_root, rows


def judge(mode, text):
    """Return (ok, problems). mode is 'sandboxed' or 'unsandboxed' (the control)."""
    root, saw_root, rows = parse(text)
    if not saw_root:
        return False, ["scanner process not found in the container: nothing was measured"]
    if root is None or "ERR" in root.values():
        return False, ["scanner namespaces unreadable: cannot compare renderers against them"]
    renderers = [r for r in rows.values() if r["type"] == "renderer"]
    definite = [r for r in renderers if r["definite"]]
    problems = []
    ns_keys = (("net", "net", "net"), ("pidns", "pid", "pid"), ("user", "user", "user"))
    if mode == "sandboxed":
        # The flag comes from the command line, so an unreadable namespace
        # cannot hide an unsandboxed renderer.
        for r in renderers:
            if r.get("nosandbox") == "1":
                problems.append(f"renderer {r['pid']} started with --no-sandbox")
        if not definite:
            problems.append("no definite renderer measured: sandbox state NOT established")
        for r in definite:
            for key, name, rootkey in ns_keys:
                if r[key] == root[rootkey]:
                    problems.append(f"renderer {r['pid']} shares the scanner's {name} namespace")
    elif mode == "unsandboxed":
        if not definite:
            problems.append("no definite renderer measured: the control proved nothing")
        for r in definite:
            isolated = [name for key, name, rootkey in ns_keys if r[key] != root[rootkey]]
            if r.get("nosandbox") != "1" or isolated:
                problems.append(
                    f"control did not read as unsandboxed: renderer {r['pid']} "
                    f"nosandbox={r.get('nosandbox')} isolated={isolated}")
    else:
        raise SystemExit(f"unknown mode {mode!r}")
    return (not problems), problems


SANDBOX_WARNING = "Chromium process sandbox is DISABLED"


def judge_log(mode, text):
    """Check the startup log. Only the sandbox warning and the sandbox= field
    count: other messages may legitimately contain the word DISABLED (for
    example the API rate limit)."""
    warned = SANDBOX_WARNING in text
    problems = []
    if mode == "log-sandboxed":
        if "sandbox=true" not in text:
            problems.append("startup log does not say sandbox=true")
        if warned:
            problems.append("startup log carries the sandbox-disabled warning")
    elif mode == "log-optout":
        if "sandbox=false" not in text:
            problems.append("opt-out startup log does not say sandbox=false")
        if "sandbox=true" in text:
            problems.append("opt-out startup log also says sandbox=true")
        if not warned:
            problems.append("opt-out did not log the sandbox-disabled warning")
    else:
        raise SystemExit(f"unknown log mode {mode!r}")
    return (not problems), problems


# ---------------------------------------------------------------------------
# Full run (needs Docker)
# ---------------------------------------------------------------------------

DOCKER_TIMEOUT = 120


def sh(*args, **kw):
    """Run a command; a hung docker call becomes a failed one, not a stalled job."""
    kw.setdefault("timeout", DOCKER_TIMEOUT)
    try:
        return subprocess.run(list(args), capture_output=True, text=True, **kw)
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(list(args), 124, "", f"timed out after {kw['timeout']}s: {e.cmd[:3]}")


def fetch_profile(extra):
    last = None
    for attempt in range(3):  # network only; the hash check is what makes it safe
        try:
            with urllib.request.urlopen(MOBY_URL, timeout=30) as r:
                data = r.read()
            got = hashlib.sha256(data).hexdigest()
            if got != MOBY_SHA256:
                raise SystemExit(f"pinned seccomp profile hash mismatch: got {got}, want {MOBY_SHA256}")
            profile = json.loads(data)
            profile["syscalls"].append({"names": list(extra), "action": "SCMP_ACT_ALLOW"})
            return profile
        except SystemExit:
            raise
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (attempt + 1))
    raise SystemExit(f"could not fetch the pinned seccomp profile: {last}")


class Lab:
    def __init__(self, image, outdir):
        self.image = image
        self.out = outdir
        self.names = []
        self.results = []
        self.suffix = secrets.token_hex(3)

    def run_container(self, scenario, seccomp_path, serve_extra):
        name = f"indago-ci-sbx-{scenario}-{self.suffix}"
        self.names.append(name)
        cmd = ["docker", "run", "-d", "--name", name,
               "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
               "--memory=2g", "--shm-size=256m",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
               "--tmpfs", "/var/cache/indago:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0750",
               "--tmpfs", "/var/lib/indago:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0750"]
        if seccomp_path:
            cmd += ["--security-opt", f"seccomp={seccomp_path}"]
        cmd += [self.image, "serve", "-data", "/var/lib/indago", "-addr", f"127.0.0.1:{API_PORT}"] + serve_extra
        r = sh(*cmd)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed: {r.stderr.strip()[-300:]}")
        return name

    def logs(self, name):
        r = sh("docker", "logs", name)
        text = r.stdout + r.stderr
        (self.out / f"{name}.log").write_text(text)
        return text

    def state(self, name):
        r = sh("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name).stdout.split()
        return (r[0], int(r[1])) if len(r) == 2 else ("unknown", -1)

    def wait_listening(self, name, timeout=90):
        end = time.time() + timeout
        while time.time() < end:
            status, code = self.state(name)
            text = sh("docker", "logs", name)
            joined = text.stdout + text.stderr
            if "web server listening" in joined:
                return True, joined
            if status == "exited":
                return False, joined
            time.sleep(0.5)
        return False, sh("docker", "logs", name).stdout

    def cli(self, name, *args):
        return sh("docker", "exec", "-u", UID, "-e", f"INDAGO_SERVER_URL=http://127.0.0.1:{API_PORT}",
                  name, "indago", *args).stdout

    def report_fixture(self, name):
        origin = "https://fixture.invalid"
        project = re.search(r"project ([0-9a-f-]{36})", self.cli(
            name, "project", "create", "ci-sandbox")).group(1)
        self.cli(name, "scope", "set", "-project", project, "-include", "fixture.invalid", "-origins", origin)
        target = re.search(r"target ([0-9a-f-]{36})", self.cli(
            name, "target", "add", "-project", project, "-name", "Report fixture",
            "-url", origin)).group(1)
        return re.search(r"scan ([0-9a-f-]{36})", self.cli(
            name, "scan", "create", "-project", project, "-target", target,
            "-name", "PDF fixture (draft only)")).group(1)

    def export_pdf(self, name, scan, index):
        path = f"/tmp/indago-ci-report-{index}.pdf"
        request = sh("docker", "exec", "-u", UID, "-e", f"INDAGO_SERVER_URL=http://127.0.0.1:{API_PORT}",
                     name, "indago", "report", "create", "-scan", scan, "-format", "pdf", "-out", path)
        header = sh("docker", "exec", "-u", UID, name, "head", "-c", "5", path)
        return request.returncode, header.stdout, request.stderr

    def sample_during(self, name, work):
        """Poll the in-container measurement while `work()` runs; return all output."""
        chunks = []
        stop = threading.Event()

        def sampler():
            try:
                while not stop.is_set():
                    r = sh("docker", "exec", "-i", "-u", UID, name, "sh", "-s", input=MEASURE)
                    chunks.append(r.stdout)
                    time.sleep(0.08)
            except Exception as e:  # noqa: BLE001 - make the cause visible in the artifact
                chunks.append(f"SAMPLER-ERROR {e!r}")

        t = threading.Thread(target=sampler, daemon=True)
        t.start()
        try:
            result = work()
        finally:
            stop.set()
            t.join(timeout=20)
        return result, "\n".join(chunks)

    def record(self, scenario, ok, problems, **extra):
        self.results.append({"scenario": scenario, "ok": ok, "problems": problems, **extra})
        print(f"[{'PASS' if ok else 'FAIL'}] {scenario}" + ("" if ok else ": " + "; ".join(problems)), flush=True)

    # -- scenarios ----------------------------------------------------------

    def scenario_default_fails_closed(self):
        name = self.run_container("a-default", None, [])
        ok, _ = self.wait_listening(name)
        if not ok:
            self.logs(name)
            self.record("A default seccomp + sandbox on fails closed", False, ["server did not start"])
            return
        code, header, stderr = self.export_pdf(name, self.report_fixture(name), 0)
        log = self.logs(name)
        problems = []
        if code == 0 or header == "%PDF-":
            problems.append("sandboxed export succeeded under default seccomp")
        if "No usable sandbox" not in (log + stderr):
            problems.append("Chromium's 'No usable sandbox' message not found")
        self.record("A default seccomp + sandbox on fails closed", not problems, problems, exit=code)

    def _pdf_scenario(self, name, mode):
        ok, _ = self.wait_listening(name)
        if not ok:
            self.logs(name)
            return ["server did not start"]
        scan = self.report_fixture(name)
        # Chromium is short-lived for a PDF. Repeated local exports give the
        # sampler time to observe a real renderer without contacting a target.
        results, measure = self.sample_during(name, lambda: [self.export_pdf(name, scan, n) for n in range(3)])
        (self.out / f"measure-{mode}.txt").write_text(measure)
        self.logs(name)
        problems = [f"PDF export failed: {stderr[-350:]}" for code, header, stderr in results
                    if code != 0 or header != "%PDF-"]
        _, why = judge(mode, measure)
        return problems + why

    def scenario_profile_sandboxed(self, profile_path):
        name = self.run_container("b-profile", profile_path, [])
        problems = self._pdf_scenario(name, "sandboxed")
        self.record("B recipe profile exports a PDF sandboxed", not problems, problems)

    def scenario_control_unsandboxed(self):
        name = self.run_container("c-optout", None, ["-browser-no-sandbox"])
        problems = self._pdf_scenario(name, "unsandboxed")
        self.record("C opt-out control reads as unsandboxed", not problems, problems)

    def cleanup(self):
        leftovers = []
        for name in self.names:
            sh("docker", "rm", "-f", "-v", name)
            if sh("docker", "inspect", name).returncode == 0:
                leftovers.append(name)
        return leftovers


def environment_report():
    """Facts that decide whether a user namespace sandbox can work here, printed
    first so a red run on a new runner is diagnosable without guessing."""
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return "n/a"
    sec = sh("docker", "info", "--format", "{{json .SecurityOptions}}").stdout.strip()
    return "\n".join([
        f"kernel: {read('/proc/sys/kernel/osrelease')}",
        f"unprivileged_userns_clone: {read('/proc/sys/kernel/unprivileged_userns_clone')}",
        f"apparmor_restrict_unprivileged_userns: {read('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')}",
        f"max_user_namespaces: {read('/proc/sys/user/max_user_namespaces')}",
        f"docker security options: {sec}",
    ])


def run_full(args):
    if sh("docker", "version", "--format", "{{.Server.Version}}").returncode != 0:
        raise SystemExit("docker is not available")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(environment_report(), flush=True)
    extra = [s for s in args.profile_syscalls.split(",") if s]
    tmp = Path(tempfile.mkdtemp(prefix="indago-ci-seccomp-"))
    lab = Lab(args.image, out)
    try:
        profile_path = tmp / "indago-chromium-seccomp.json"
        profile_path.write_text(json.dumps(fetch_profile(extra)))
        print(f"seccomp profile: moby/profiles@{MOBY_COMMIT[:12]} + {extra}", flush=True)
        for step in (lab.scenario_default_fails_closed,
                     lambda: lab.scenario_profile_sandboxed(str(profile_path)),
                     lab.scenario_control_unsandboxed):
            try:
                step()
            except Exception as e:  # noqa: BLE001 - a crashed scenario is a failed scenario
                lab.record(getattr(step, "__name__", "scenario"), False, [f"crashed: {e!r}"])
    finally:
        try:
            leftovers = lab.cleanup()
        except Exception as e:  # noqa: BLE001
            leftovers = [f"cleanup crashed: {e!r}"]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if leftovers:
        lab.record("cleanup", False, [f"containers still present: {leftovers}"])
    ok = all(r["ok"] for r in lab.results) and len(lab.results) >= 3
    (out / "results.json").write_text(json.dumps({"ok": ok, "results": lab.results}, indent=1))
    print("RESULT:", "PASS" if ok else "FAIL", flush=True)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--judge", choices=["sandboxed", "unsandboxed", "log-sandboxed", "log-optout"],
                    help="verdict logic only (no Docker)")
    ap.add_argument("file", nargs="?", help="measurement output for --judge")
    ap.add_argument("--image", help="image to test (full run)")
    ap.add_argument("--out", default="docker-sandbox-ci", help="directory for logs and results.json")
    ap.add_argument("--profile-syscalls", default=",".join(RECIPE_SYSCALLS),
                    help="syscalls added to the default profile; only change this to prove the gate catches a bad recipe")
    args = ap.parse_args()
    if args.judge:
        if not args.file:
            ap.error("--judge needs a FILE")
        fn = judge_log if args.judge.startswith("log-") else judge
        ok, problems = fn(args.judge, Path(args.file).read_text())
        print("OK" if ok else "FAIL: " + "; ".join(problems))
        return 0 if ok else 1
    if not args.image:
        ap.error("give --image (full run) or --judge MODE FILE")
    return run_full(args)


if __name__ == "__main__":
    sys.exit(main())

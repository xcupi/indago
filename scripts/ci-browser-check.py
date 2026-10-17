#!/usr/bin/env python3
"""Required real-runtime smoke: a skipped/missing test is a CI failure.

Keep developer-friendly skips in the main suite, but never confuse those with
CI browser coverage. No external Python dependencies; run from repository root.
"""
import json
import os
import shutil
import subprocess

required = {
    "TestIntegrationRenderRealBrowser",
    "TestIntegrationVerifyExecutableCandidateIsConfirmed",
    "TestIntegrationVerifyReflectionOnlyIsRejected",
    "TestE2E_FullPipelineAgainstCorpus",
    "TestUINavigation",
    "TestUICooldownClock",
}
if not shutil.which("node"):
    raise SystemExit("required Node.js unavailable")
chrome = os.environ.get("INDAGO_CHROMIUM_PATH", "")
if not chrome or not os.access(chrome, os.X_OK):
    raise SystemExit("required INDAGO_CHROMIUM_PATH is not executable")
command = [
    "go", "test", "-race", "-p", "1", "-count=1", "-json",
    "./internal/browser", "./internal/verification", "./internal/scan", "./internal/web",
    "-run", "^(" + "|".join(sorted(required)) + ")$",
]
proc = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
passed = set()
failed = False
for line in proc.stdout:
    event = json.loads(line)
    if event.get("Output"):
        print(event["Output"], end="", flush=True)
    name = event.get("Test")
    if name in required:
        if event["Action"] == "pass":
            passed.add(name)
        if event["Action"] in ("skip", "fail"):
            failed = True
code = proc.wait()
if code or failed or passed != required:
    raise SystemExit("required runtime checks failed/skipped/missing: " + ", ".join(sorted(required - passed)))
print("Required Node/browser tests: all 6 passed; no skips")

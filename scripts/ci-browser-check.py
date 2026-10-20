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
    "TestIntegrationCreateScanLoginScope",
    "TestIntegrationLoginScopeBoundary",
    "TestUILoginCarriesProjectScope",
    "TestIntegrationRenderRealBrowser",
    "TestIntegrationRenderCapturesJSONPostDataForDiscovery",
    "TestIntegrationRequestObserverDoesNotWaitForResponse",
    "TestIntegrationNetworkJSONBodyDiscovery",
    "TestIntegrationVerifyExecutableCandidateIsConfirmed",
    "TestIntegrationVerifyReflectionOnlyIsRejected",
    "TestE2E_FullPipelineAgainstCorpus",
    "TestUINavigation",
    "TestUICooldownClock",
    "TestUICoverageBrowserlessScanIsNotShownAsClean",
    "TestUIScanHeaderFollowsStateChange",
    "TestUINewScanActionsStayReachableOnShortViewport",
    "TestUIEndpointsTabShowsFoundButUntestedParameters",
    "TestUIEndpointsLiveRefreshKeepsKeyboardFocus",
    "TestUIFailedScanOverviewWarnsEvenThoughEverythingRecordedPassed",
    "TestDOMHTMLSourceMatrix",
    "TestDOMStringTimerSourceMatrix",
    "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms",
    "TestDOMXSSFragmentRouteCapturesPostLoadSink",
    "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource",
    "TestIntegrationDefaultConfigRendererIsSandboxed",
    "TestIntegrationDisableSandboxIsExplicitOptOut",
    "TestIntegrationScopeGateAllowsInScopeRedirect",
    "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect",
    "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect",
    "TestIntegrationScopeGateBlocksBackslashPathRedirect",
    "TestIntegrationScopeGateBlocksWebSocketTraffic",
    "TestIntegrationScopeGateBlocksServiceWorkerTraffic",
    "TestIntegrationScopeGateBlocksPopupRedirect",
    "TestIntegrationScopeGateRejectsUnmanagedTargets",
    "TestIntegrationScopeGateManagedFramesAndSubresources",
    "TestIntegrationScopeGatePreservesBodyReplay",
    "TestIntegrationRejectFabricatedMarkerException",
    "TestIntegrationRejectConsoleOnlyMarker",
    "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed",
    "TestDOMXSSForgedSignalsAreNotConfirmed",
    "TestDOMXSSStorageKeysAreIsolatedPerAttempt",
    "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings",
    "TestIntegrationRejectCarriageReturnLineMappingForgery",
    "TestIntegrationConfirmsDespiteErrorAndScriptFlood",
    "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON",
    "TestDOMXSSStringTimerThrowingEveryTickStillConfirms",
}
if not shutil.which("node"):
    raise SystemExit("required Node.js unavailable")
chrome = os.environ.get("INDAGO_CHROMIUM_PATH", "")
if not chrome or not os.access(chrome, os.X_OK):
    raise SystemExit("required INDAGO_CHROMIUM_PATH is not executable")
command = [
    "go", "test", "-tags", "browser_integration", "-race", "-p", "1", "-count=1", "-json",
    "./internal/browser", "./internal/discovery", "./internal/verification", "./internal/scan", "./internal/web",
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
    if name in required and event["Action"] == "pass":
        passed.add(name)
    if (name or "").split("/", 1)[0] in required:
        if event["Action"] in ("skip", "fail"):
            failed = True
code = proc.wait()
if code or failed or passed != required:
    raise SystemExit("required runtime checks failed/skipped/missing: " + ", ".join(sorted(required - passed)))
print(f"Required Node/browser tests: all {len(required)} passed; no skips")

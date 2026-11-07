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
    "TestReflectedJSStringContexts",
    "TestE2E_FullPipelineAgainstCorpus",
    "TestUINavigation",
    "TestUICooldownClock",
    "TestUICoverageBrowserlessScanIsNotShownAsClean",
    "TestUIScanHeaderFollowsStateChange",
    "TestUINewScanActionsStayReachableOnShortViewport",
    "TestUIEndpointsTabShowsFoundButUntestedParameters",
    "TestUIScopeFormRefusesEntriesThatCanNeverMatch",
    "TestIntegrationResourceHintControlsOpenConnectionsWhereExpected",
    "TestIntegrationResourceHintsDoNotReachAnOutOfScopeHost",
    "TestIntegrationRedirectSurfacesControlReachesTheSecondHost",
    "TestIntegrationScopeGateStopsRedirectSurfaces",
    "TestUIEndpointsLiveRefreshKeepsKeyboardFocus",
    "TestUIFailedScanOverviewWarnsEvenThoughEverythingRecordedPassed",
    "TestDOMHTMLSourceMatrix",
    "TestDOMStringTimerSourceMatrix",
    # jQuery sink coverage: attribute-write activation and hashchange-delivered
    # selector markup, with safe/forged controls and the native API contract.
    "TestDOMJQueryAnchorHrefSinkIsActivated",
    "TestDOMJQuerySelectorHashchangeSinkIsActivated",
    "TestDOMJQuerySinkNativeContract",
    "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms",
    "TestDOMXSSFragmentRouteCapturesPostLoadSink",
    "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource",
    "TestIntegrationDefaultConfigRendererIsSandboxed",
    "TestIntegrationDisableSandboxIsExplicitOptOut",
    "TestIntegrationScopeGateAllowsInScopeRedirect",
    "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect",
    "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect",
    "TestIntegrationScopeGateBlocksBackslashPathRedirect",
    "TestIntegrationScopeGateBlocksParserDifferentialRedirects",
    "TestIntegrationParserDifferentialControlReachesTheSecondHost",
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
    "TestDOMXSSMarkerWindowRetention",
    "TestDOMXSSMarkerWindowSinkPaths",
    "TestDOMXSSHarnessMarkerSnippetBounded",
    "TestDOMXSSMarkerWindowExcerptNatives",
    "TestDOMXSSWorkerRetriesTransientVerificationFailure",
    "TestDOMXSSWorkerCancellationAndConfirmedDurability",
    # DOM coverage-gap regressions: an attribute-context injection must confirm
    # through a real breakout execution, and a body-less/non-HTML response must
    # be recorded as not applicable rather than as a dead/erroring probe.
    "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed",
    "TestDOMBodylessDocumentIsNotApplicable",
    # Measured coverage records (no new payload shapes): document.write inside a
    # <select> is already confirmed by the existing shapes under Chromium's
    # customizable-select parser, and the canonical-link attribute-only vector is
    # planned and sent, with the passive verifier honestly rejecting it.
    "TestDOMDocumentWriteInsideSelectIsAlreadyConfirmed",
    "TestReflectedCanonicalLinkVectorIsPlannedButNeedsActivation",
    # Variation packs across six reflection contexts: a filtered route must still
    # confirm with the surviving later variant, and the url route confirms ONLY
    # through the one bounded click for an interaction-shaped javascript: URL.
    # Required because its url assertion went stale unnoticed while unlisted.
    "TestReflectedVariationPacksConfirmAfterFirstVariantIsBlocked",
    # The four filter-allow-list labs (8-11) must confirm through the
    # AUTOMATIC escalation with EnableEvasion false: canonical shapes are all
    # rejected, so this is the guarantee that the fallback reaches them.
    "TestAutomaticEvasionConfirmsFilterAllowListLabs",
    # Eval attribution: scanner automation is never a target eval sink, target
    # eval (incl. a computed argument) is reachable, and direct eval keeps its
    # lexical scope. The external-script ES5 positive must really Confirm.
    "TestDOMXSSHarnessEvalAttribution",
    "TestDOMXSSExternalScriptES5StaticAnalysis",
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

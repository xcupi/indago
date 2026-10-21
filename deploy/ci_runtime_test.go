package deploy_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic event streams test the preflight parser, not browser coverage.
// The real preflight is separately exercised with Go and Chromium.
func TestCIRuntimeRejectsMissingSkippedFailedRootsAndDescendants(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{"TestIntegrationCreateScanLoginScope", "TestIntegrationLoginScopeBoundary", "TestUILoginCarriesProjectScope", "TestIntegrationRenderRealBrowser", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "TestIntegrationRequestObserverDoesNotWaitForResponse", "TestIntegrationNetworkJSONBodyDiscovery", "TestIntegrationVerifyExecutableCandidateIsConfirmed", "TestIntegrationVerifyReflectionOnlyIsRejected", "TestE2E_FullPipelineAgainstCorpus", "TestUINavigation", "TestUICooldownClock", "TestUICoverageBrowserlessScanIsNotShownAsClean", "TestUIScanHeaderFollowsStateChange", "TestUINewScanActionsStayReachableOnShortViewport", "TestUIEndpointsTabShowsFoundButUntestedParameters", "TestUIScopeFormRefusesEntriesThatCanNeverMatch", "TestIntegrationResourceHintControlsOpenConnectionsWhereExpected", "TestIntegrationResourceHintsDoNotReachAnOutOfScopeHost", "TestUIEndpointsLiveRefreshKeepsKeyboardFocus", "TestUIFailedScanOverviewWarnsEvenThoughEverythingRecordedPassed", "TestDOMHTMLSourceMatrix", "TestDOMStringTimerSourceMatrix", "TestIntegrationDefaultConfigRendererIsSandboxed", "TestIntegrationDisableSandboxIsExplicitOptOut", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "TestIntegrationScopeGateAllowsInScopeRedirect", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "TestIntegrationScopeGateBlocksBackslashPathRedirect", "TestIntegrationScopeGateBlocksParserDifferentialRedirects", "TestIntegrationParserDifferentialControlReachesTheSecondHost", "TestIntegrationScopeGateBlocksWebSocketTraffic", "TestIntegrationScopeGateBlocksServiceWorkerTraffic", "TestIntegrationScopeGateBlocksPopupRedirect", "TestIntegrationScopeGateRejectsUnmanagedTargets", "TestIntegrationScopeGateManagedFramesAndSubresources", "TestIntegrationScopeGatePreservesBodyReplay", "TestIntegrationRejectFabricatedMarkerException", "TestIntegrationRejectConsoleOnlyMarker", "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed", "TestDOMXSSForgedSignalsAreNotConfirmed", "TestDOMXSSStorageKeysAreIsolatedPerAttempt", "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings", "TestIntegrationRejectCarriageReturnLineMappingForgery", "TestIntegrationConfirmsDespiteErrorAndScriptFlood", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms"}
	for _, tc := range []struct {
		name, root, action, child string
		wantPass                  bool
	}{
		{"all-pass", "", "", "", true},
		{"login-controller-missing", "TestIntegrationCreateScanLoginScope", "missing", "", false},
		{"login-controller-skip", "TestIntegrationCreateScanLoginScope", "skip", "", false},
		{"login-controller-fail", "TestIntegrationCreateScanLoginScope", "fail", "", false},
		{"login-missing", "TestIntegrationLoginScopeBoundary", "missing", "", false},
		{"login-skip", "TestIntegrationLoginScopeBoundary", "skip", "", false},
		{"login-fail", "TestIntegrationLoginScopeBoundary", "fail", "", false},
		{"login-child-skip", "TestIntegrationLoginScopeBoundary", "skip", "/form", false},
		{"login-child-fail", "TestIntegrationLoginScopeBoundary", "fail", "/redirect", false},
		{"login-ui-missing", "TestUILoginCarriesProjectScope", "missing", "", false},
		{"login-ui-skip", "TestUILoginCarriesProjectScope", "skip", "", false},
		{"login-ui-fail", "TestUILoginCarriesProjectScope", "fail", "", false},
		{"parser-diff-missing", "TestIntegrationScopeGateBlocksParserDifferentialRedirects", "missing", "", false},
		{"parser-diff-skip", "TestIntegrationScopeGateBlocksParserDifferentialRedirects", "skip", "", false},
		{"parser-diff-fail", "TestIntegrationScopeGateBlocksParserDifferentialRedirects", "fail", "", false},
		{"parser-control-missing", "TestIntegrationParserDifferentialControlReachesTheSecondHost", "missing", "", false},
		{"parser-control-skip", "TestIntegrationParserDifferentialControlReachesTheSecondHost", "skip", "", false},
		{"parser-control-fail", "TestIntegrationParserDifferentialControlReachesTheSecondHost", "fail", "", false},
		{"json-capture-missing", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "missing", "", false},
		{"json-capture-skip", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "skip", "", false},
		{"json-capture-fail", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "fail", "", false},
		{"json-no-response-missing", "TestIntegrationRequestObserverDoesNotWaitForResponse", "missing", "", false},
		{"json-no-response-skip", "TestIntegrationRequestObserverDoesNotWaitForResponse", "skip", "", false},
		{"json-no-response-fail", "TestIntegrationRequestObserverDoesNotWaitForResponse", "fail", "", false},
		{"json-discovery-missing", "TestIntegrationNetworkJSONBodyDiscovery", "missing", "", false},
		{"json-discovery-skip", "TestIntegrationNetworkJSONBodyDiscovery", "skip", "", false},
		{"json-discovery-fail", "TestIntegrationNetworkJSONBodyDiscovery", "fail", "", false},
		{"timer-missing", "TestDOMStringTimerSourceMatrix", "missing", "", false},
		{"timer-root-skip", "TestDOMStringTimerSourceMatrix", "skip", "", false},
		{"timer-root-fail", "TestDOMStringTimerSourceMatrix", "fail", "", false},
		{"timer-child-skip", "TestDOMStringTimerSourceMatrix", "skip", "/setTimeout/location.hash/safe", false},
		{"timer-child-fail", "TestDOMStringTimerSourceMatrix", "fail", "/setInterval/postMessage/positive", false},
		{"html-missing", "TestDOMHTMLSourceMatrix", "missing", "", false},
		{"html-child-skip", "TestDOMHTMLSourceMatrix", "skip", "/insertAdjacentHTML/location.hash/positive", false},
		{"html-child-fail", "TestDOMHTMLSourceMatrix", "fail", "/Range.createContextualFragment/localStorage/forged", false},
		// A sandbox that silently degrades to "skipped" would hide a disabled
		// process sandbox, so each sandbox test is required to actually pass.
		{"sandbox-default-missing", "TestIntegrationDefaultConfigRendererIsSandboxed", "missing", "", false},
		{"sandbox-default-skip", "TestIntegrationDefaultConfigRendererIsSandboxed", "skip", "", false},
		{"sandbox-default-fail", "TestIntegrationDefaultConfigRendererIsSandboxed", "fail", "", false},
		{"sandbox-optout-skip", "TestIntegrationDisableSandboxIsExplicitOptOut", "skip", "", false},
		{"sandbox-optout-missing", "TestIntegrationDisableSandboxIsExplicitOptOut", "missing", "", false},
		{"sandbox-optout-fail", "TestIntegrationDisableSandboxIsExplicitOptOut", "fail", "", false},
		{"scope-allow-redirect-missing", "TestIntegrationScopeGateAllowsInScopeRedirect", "missing", "", false},
		{"scope-allow-redirect-skip", "TestIntegrationScopeGateAllowsInScopeRedirect", "skip", "", false},
		{"scope-allow-redirect-fail", "TestIntegrationScopeGateAllowsInScopeRedirect", "fail", "", false},
		{"scope-navigation-redirect-missing", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "missing", "", false},
		{"scope-navigation-redirect-skip", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "skip", "", false},
		{"scope-navigation-redirect-fail", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "fail", "", false},
		{"scope-subresource-redirect-missing", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "missing", "", false},
		{"scope-subresource-redirect-skip", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "skip", "", false},
		{"scope-subresource-redirect-fail", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "fail", "", false},
		{"scope-backslash-redirect-missing", "TestIntegrationScopeGateBlocksBackslashPathRedirect", "missing", "", false},
		{"scope-backslash-redirect-skip", "TestIntegrationScopeGateBlocksBackslashPathRedirect", "skip", "", false},
		{"scope-backslash-redirect-fail", "TestIntegrationScopeGateBlocksBackslashPathRedirect", "fail", "", false},
		{"scope-websocket-missing", "TestIntegrationScopeGateBlocksWebSocketTraffic", "missing", "", false},
		{"scope-websocket-skip", "TestIntegrationScopeGateBlocksWebSocketTraffic", "skip", "", false},
		{"scope-websocket-fail", "TestIntegrationScopeGateBlocksWebSocketTraffic", "fail", "", false},
		{"scope-serviceworker-missing", "TestIntegrationScopeGateBlocksServiceWorkerTraffic", "missing", "", false},
		{"scope-serviceworker-skip", "TestIntegrationScopeGateBlocksServiceWorkerTraffic", "skip", "", false},
		{"scope-serviceworker-fail", "TestIntegrationScopeGateBlocksServiceWorkerTraffic", "fail", "", false},
		{"scope-unmanaged-missing", "TestIntegrationScopeGateRejectsUnmanagedTargets", "missing", "", false},
		{"scope-unmanaged-skip", "TestIntegrationScopeGateRejectsUnmanagedTargets", "skip", "", false},
		{"scope-unmanaged-fail", "TestIntegrationScopeGateRejectsUnmanagedTargets", "fail", "", false},
		{"scope-unmanaged-child-skip", "TestIntegrationScopeGateRejectsUnmanagedTargets", "skip", "/late-anchor-target", false},
		{"scope-unmanaged-child-fail", "TestIntegrationScopeGateRejectsUnmanagedTargets", "fail", "/closed-shadow-anchor", false},
		{"scope-frames-missing", "TestIntegrationScopeGateManagedFramesAndSubresources", "missing", "", false},
		{"scope-frames-skip", "TestIntegrationScopeGateManagedFramesAndSubresources", "skip", "", false},
		{"scope-frames-fail", "TestIntegrationScopeGateManagedFramesAndSubresources", "fail", "", false},
		{"scope-replay-missing", "TestIntegrationScopeGatePreservesBodyReplay", "missing", "", false},
		{"scope-replay-skip", "TestIntegrationScopeGatePreservesBodyReplay", "skip", "", false},
		{"scope-replay-fail", "TestIntegrationScopeGatePreservesBodyReplay", "fail", "", false},
		{"scope-replay-child-skip", "TestIntegrationScopeGatePreservesBodyReplay", "skip", "/form", false},
		{"scope-replay-child-fail", "TestIntegrationScopeGatePreservesBodyReplay", "fail", "/json", false},
		{"scope-popup-missing", "TestIntegrationScopeGateBlocksPopupRedirect", "missing", "", false},
		{"scope-popup-skip", "TestIntegrationScopeGateBlocksPopupRedirect", "skip", "", false},
		{"scope-popup-fail", "TestIntegrationScopeGateBlocksPopupRedirect", "fail", "", false},
		{"fragment-route-missing", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "missing", "", false},
		{"fragment-route-skip", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "skip", "", false},
		{"fragment-route-fail", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "fail", "", false},
		{"fragment-postload-missing", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "missing", "", false},
		{"fragment-postload-skip", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "skip", "", false},
		{"fragment-postload-fail", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "fail", "", false},
		{"script-literal-missing", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "missing", "", false},
		{"script-literal-skip", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "skip", "", false},
		{"script-literal-fail", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "fail", "", false},
		{"reflected-forged-exception-missing", "TestIntegrationRejectFabricatedMarkerException", "missing", "", false},
		{"reflected-forged-exception-skip", "TestIntegrationRejectFabricatedMarkerException", "skip", "", false},
		{"reflected-forged-exception-fail", "TestIntegrationRejectFabricatedMarkerException", "fail", "", false},
		{"reflected-forged-console-missing", "TestIntegrationRejectConsoleOnlyMarker", "missing", "", false},
		{"reflected-forged-console-skip", "TestIntegrationRejectConsoleOnlyMarker", "skip", "", false},
		{"reflected-forged-console-fail", "TestIntegrationRejectConsoleOnlyMarker", "fail", "", false},
		{"dom-positive-control-missing", "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed", "missing", "", false},
		{"dom-positive-control-skip", "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed", "skip", "", false},
		{"dom-positive-control-fail", "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed", "fail", "", false},
		{"dom-forged-signals-missing", "TestDOMXSSForgedSignalsAreNotConfirmed", "missing", "", false},
		{"dom-forged-signals-skip", "TestDOMXSSForgedSignalsAreNotConfirmed", "skip", "", false},
		{"dom-forged-signals-fail", "TestDOMXSSForgedSignalsAreNotConfirmed", "fail", "", false},
		{"dom-storage-isolation-missing", "TestDOMXSSStorageKeysAreIsolatedPerAttempt", "missing", "", false},
		{"dom-storage-isolation-skip", "TestDOMXSSStorageKeysAreIsolatedPerAttempt", "skip", "", false},
		{"dom-storage-isolation-fail", "TestDOMXSSStorageKeysAreIsolatedPerAttempt", "fail", "", false},
		{"dom-fragment-selectors-missing", "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings", "missing", "", false},
		{"dom-fragment-selectors-skip", "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings", "skip", "", false},
		{"dom-fragment-selectors-fail", "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings", "fail", "", false},
		{"dom-forged-signals-child-skip", "TestDOMXSSForgedSignalsAreNotConfirmed", "skip", "/thrown_ReferenceError_naming_the_marker_on_a_safe_sink", false},
		{"dom-forged-signals-child-fail", "TestDOMXSSForgedSignalsAreNotConfirmed", "fail", "/execution_inside_a_child_frame_on_a_safe_top-level_sink", false},
		{"reflected-cr-forgery-missing", "TestIntegrationRejectCarriageReturnLineMappingForgery", "missing", "", false},
		{"reflected-cr-forgery-skip", "TestIntegrationRejectCarriageReturnLineMappingForgery", "skip", "", false},
		{"reflected-cr-forgery-fail", "TestIntegrationRejectCarriageReturnLineMappingForgery", "fail", "", false},
		{"reflected-flood-missing", "TestIntegrationConfirmsDespiteErrorAndScriptFlood", "missing", "", false},
		{"reflected-flood-skip", "TestIntegrationConfirmsDespiteErrorAndScriptFlood", "skip", "", false},
		{"reflected-flood-fail", "TestIntegrationConfirmsDespiteErrorAndScriptFlood", "fail", "", false},
		{"dom-neutralized-console-missing", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "missing", "", false},
		{"dom-neutralized-console-skip", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "skip", "", false},
		{"dom-neutralized-console-fail", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "fail", "", false},
		{"dom-timer-every-tick-missing", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "missing", "", false},
		{"dom-timer-every-tick-skip", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "skip", "", false},
		{"dom-timer-every-tick-fail", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "fail", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var events strings.Builder
			emit := func(name, action string) {
				b, _ := json.Marshal(map[string]string{"Test": name, "Action": action})
				events.Write(b)
				events.WriteByte('\n')
			}
			for _, root := range roots {
				if root == tc.root && tc.child == "" {
					if tc.action != "missing" {
						emit(root, tc.action)
					}
				} else {
					emit(root, "pass")
				}
			}
			if tc.child != "" {
				emit(tc.root+tc.child, tc.action)
			}
			data := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(data, []byte(events.String()), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n/bin/cat \"$INDAGO_CI_EVENTS\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/bin/true", filepath.Join(dir, "node")); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(python, "../scripts/ci-browser-check.py")
			cmd.Env = append(os.Environ(), "PATH="+dir, "INDAGO_CHROMIUM_PATH=/bin/true", "INDAGO_CI_EVENTS="+data)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantPass {
				t.Fatalf("expected pass=%v, error=%v output=%s", tc.wantPass, err, output)
			}
		})
	}
}

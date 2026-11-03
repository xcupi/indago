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
	roots := []string{"TestIntegrationCreateScanLoginScope", "TestIntegrationLoginScopeBoundary", "TestUILoginCarriesProjectScope", "TestIntegrationRenderRealBrowser", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "TestIntegrationRequestObserverDoesNotWaitForResponse", "TestIntegrationNetworkJSONBodyDiscovery", "TestIntegrationVerifyExecutableCandidateIsConfirmed", "TestIntegrationVerifyReflectionOnlyIsRejected", "TestE2E_FullPipelineAgainstCorpus", "TestUINavigation", "TestUICooldownClock", "TestUICoverageBrowserlessScanIsNotShownAsClean", "TestUIScanHeaderFollowsStateChange", "TestUINewScanActionsStayReachableOnShortViewport", "TestUIEndpointsTabShowsFoundButUntestedParameters", "TestUIScopeFormRefusesEntriesThatCanNeverMatch", "TestIntegrationResourceHintControlsOpenConnectionsWhereExpected", "TestIntegrationResourceHintsDoNotReachAnOutOfScopeHost", "TestIntegrationRedirectSurfacesControlReachesTheSecondHost", "TestIntegrationScopeGateStopsRedirectSurfaces", "TestUIEndpointsLiveRefreshKeepsKeyboardFocus", "TestUIFailedScanOverviewWarnsEvenThoughEverythingRecordedPassed", "TestDOMHTMLSourceMatrix", "TestDOMStringTimerSourceMatrix", "TestIntegrationDefaultConfigRendererIsSandboxed", "TestIntegrationDisableSandboxIsExplicitOptOut", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "TestIntegrationScopeGateAllowsInScopeRedirect", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "TestIntegrationScopeGateBlocksBackslashPathRedirect", "TestIntegrationScopeGateBlocksParserDifferentialRedirects", "TestIntegrationParserDifferentialControlReachesTheSecondHost", "TestIntegrationScopeGateBlocksWebSocketTraffic", "TestIntegrationScopeGateBlocksServiceWorkerTraffic", "TestIntegrationScopeGateBlocksPopupRedirect", "TestIntegrationScopeGateRejectsUnmanagedTargets", "TestIntegrationScopeGateManagedFramesAndSubresources", "TestIntegrationScopeGatePreservesBodyReplay", "TestIntegrationRejectFabricatedMarkerException", "TestIntegrationRejectConsoleOnlyMarker", "TestDOMXSSGenuineInnerHTMLExecutionIsStillConfirmed", "TestDOMXSSForgedSignalsAreNotConfirmed", "TestDOMXSSStorageKeysAreIsolatedPerAttempt", "TestDOMXSSFragmentRouteSelectorsAreSeparateFindings", "TestIntegrationRejectCarriageReturnLineMappingForgery", "TestIntegrationConfirmsDespiteErrorAndScriptFlood", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "TestDOMXSSMarkerWindowRetention", "TestDOMXSSMarkerWindowSinkPaths", "TestDOMXSSHarnessMarkerSnippetBounded", "TestDOMXSSMarkerWindowExcerptNatives", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "TestDOMXSSWorkerCancellationAndConfirmedDurability", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "TestDOMBodylessDocumentIsNotApplicable", "TestReflectedJSStringContexts", "TestDOMJQueryAnchorHrefSinkIsActivated", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "TestDOMJQuerySinkNativeContract"}
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
		{"js-string-contexts-missing", "TestReflectedJSStringContexts", "missing", "", false},
		{"js-string-contexts-skip", "TestReflectedJSStringContexts", "skip", "", false},
		{"js-string-contexts-fail", "TestReflectedJSStringContexts", "fail", "", false},
		{"dom-neutralized-console-missing", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "missing", "", false},
		{"dom-neutralized-console-skip", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "skip", "", false},
		{"dom-neutralized-console-fail", "TestDOMXSSSurvivesPageNeutralizingConsoleAndJSON", "fail", "", false},
		{"dom-timer-every-tick-missing", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "missing", "", false},
		{"dom-timer-every-tick-skip", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "skip", "", false},
		{"dom-timer-every-tick-fail", "TestDOMXSSStringTimerThrowingEveryTickStillConfirms", "fail", "", false},
		// Marker-window retention: a bounded excerpt must keep the real marker,
		// so these roots are required to actually pass (never skip).
		{"dom-marker-window-missing", "TestDOMXSSMarkerWindowRetention", "missing", "", false},
		{"dom-marker-window-skip", "TestDOMXSSMarkerWindowRetention", "skip", "", false},
		{"dom-marker-window-fail", "TestDOMXSSMarkerWindowRetention", "fail", "", false},
		{"dom-marker-window-child-fail", "TestDOMXSSMarkerWindowRetention", "fail", "/long-prefix-600", false},
		{"dom-marker-window-sink-paths-missing", "TestDOMXSSMarkerWindowSinkPaths", "missing", "", false},
		{"dom-marker-window-sink-paths-skip", "TestDOMXSSMarkerWindowSinkPaths", "skip", "", false},
		{"dom-marker-window-sink-paths-fail", "TestDOMXSSMarkerWindowSinkPaths", "fail", "", false},
		{"dom-marker-window-sink-paths-child-skip", "TestDOMXSSMarkerWindowSinkPaths", "skip", "/range-connected-long-prefix", false},
		{"dom-marker-window-snippet-missing", "TestDOMXSSHarnessMarkerSnippetBounded", "missing", "", false},
		{"dom-marker-window-snippet-skip", "TestDOMXSSHarnessMarkerSnippetBounded", "skip", "", false},
		{"dom-marker-window-snippet-fail", "TestDOMXSSHarnessMarkerSnippetBounded", "fail", "", false},
		{"dom-marker-window-snippet-child-fail", "TestDOMXSSHarnessMarkerSnippetBounded", "fail", "/surrogate-prefix", false},
		{"dom-marker-window-excerpt-natives-missing", "TestDOMXSSMarkerWindowExcerptNatives", "missing", "", false},
		{"dom-marker-window-excerpt-natives-skip", "TestDOMXSSMarkerWindowExcerptNatives", "skip", "", false},
		{"dom-marker-window-excerpt-natives-fail", "TestDOMXSSMarkerWindowExcerptNatives", "fail", "", false},
		{"dom-marker-window-excerpt-natives-child-fail", "TestDOMXSSMarkerWindowExcerptNatives", "fail", "/math-floor-override", false},
		// DOM verification error propagation → existing worker retry path. A
		// missing/skipped/failed root or subtest must fail the required preflight.
		{"dom-retry-missing", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "missing", "", false},
		{"dom-retry-skip", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "skip", "", false},
		{"dom-retry-fail", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "fail", "", false},
		{"dom-retry-child-skip", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "skip", "/transient-recovers", false},
		{"dom-retry-child-fail", "TestDOMXSSWorkerRetriesTransientVerificationFailure", "fail", "/persistent-exhausted", false},
		{"dom-retry-cancel-missing", "TestDOMXSSWorkerCancellationAndConfirmedDurability", "missing", "", false},
		{"dom-retry-cancel-skip", "TestDOMXSSWorkerCancellationAndConfirmedDurability", "skip", "", false},
		{"dom-retry-cancel-fail", "TestDOMXSSWorkerCancellationAndConfirmedDurability", "fail", "", false},
		// Coverage-gap regressions: a skipped/missing/failed root or subtest must
		// fail the required preflight, exactly like the other DOM roots.
		{"dom-attr-breakout-missing", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "missing", "", false},
		{"dom-attr-breakout-skip", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "skip", "", false},
		{"dom-attr-breakout-fail", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "fail", "", false},
		{"dom-attr-breakout-child-skip", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "skip", "/document.write_quoted_attribute", false},
		{"dom-attr-breakout-child-fail", "TestDOMAttributeBreakoutInQuotedAttributeIsConfirmed", "fail", "/forged_console_stays_Rejected", false},
		{"dom-bodyless-missing", "TestDOMBodylessDocumentIsNotApplicable", "missing", "", false},
		{"dom-bodyless-skip", "TestDOMBodylessDocumentIsNotApplicable", "skip", "", false},
		{"dom-bodyless-fail", "TestDOMBodylessDocumentIsNotApplicable", "fail", "", false},
		{"dom-bodyless-child-skip", "TestDOMBodylessDocumentIsNotApplicable", "skip", "/html_document_without_an_attachable_root_is_not_applicable", false},
		{"dom-bodyless-child-fail", "TestDOMBodylessDocumentIsNotApplicable", "fail", "/attachment_failure_on_a_real_document_still_errors", false},
		// jQuery sinks: a skipped/missing/failed root or subtest must fail the
		// required preflight. The attribute write needs its one activation
		// click; the selector call needs its one bounded hash change.
		{"dom-jquery-attr-missing", "TestDOMJQueryAnchorHrefSinkIsActivated", "missing", "", false},
		{"dom-jquery-attr-skip", "TestDOMJQueryAnchorHrefSinkIsActivated", "skip", "", false},
		{"dom-jquery-attr-fail", "TestDOMJQueryAnchorHrefSinkIsActivated", "fail", "", false},
		{"dom-jquery-attr-child-skip", "TestDOMJQueryAnchorHrefSinkIsActivated", "skip", "/safe_hash_href_stays_Rejected", false},
		{"dom-jquery-attr-child-fail", "TestDOMJQueryAnchorHrefSinkIsActivated", "fail", "/forged_console_stays_Rejected", false},
		{"dom-jquery-selector-missing", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "missing", "", false},
		{"dom-jquery-selector-skip", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "skip", "", false},
		{"dom-jquery-selector-fail", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "fail", "", false},
		{"dom-jquery-selector-child-skip", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "skip", "/escaped_selector_value_stays_Rejected", false},
		{"dom-jquery-selector-child-fail", "TestDOMJQuerySelectorHashchangeSinkIsActivated", "fail", "/forged_console_stays_Rejected", false},
		{"dom-jquery-contract-missing", "TestDOMJQuerySinkNativeContract", "missing", "", false},
		{"dom-jquery-contract-skip", "TestDOMJQuerySinkNativeContract", "skip", "", false},
		{"dom-jquery-contract-fail", "TestDOMJQuerySinkNativeContract", "fail", "", false},
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

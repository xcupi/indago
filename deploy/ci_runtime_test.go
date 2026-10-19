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
	roots := []string{"TestIntegrationRenderRealBrowser", "TestIntegrationRenderCapturesJSONPostDataForDiscovery", "TestIntegrationRequestObserverDoesNotWaitForResponse", "TestIntegrationNetworkJSONBodyDiscovery", "TestIntegrationVerifyExecutableCandidateIsConfirmed", "TestIntegrationVerifyReflectionOnlyIsRejected", "TestE2E_FullPipelineAgainstCorpus", "TestUINavigation", "TestUICooldownClock", "TestDOMHTMLSourceMatrix", "TestDOMStringTimerSourceMatrix", "TestIntegrationDefaultConfigRendererIsSandboxed", "TestIntegrationDisableSandboxIsExplicitOptOut", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "TestIntegrationScopeGateAllowsInScopeRedirect", "TestIntegrationScopeGateBlocksOutOfScopeNavigationRedirect", "TestIntegrationScopeGateBlocksOutOfScopeSubresourceRedirect", "TestIntegrationScopeGateBlocksBackslashPathRedirect"}
	for _, tc := range []struct {
		name, root, action, child string
		wantPass                  bool
	}{
		{"all-pass", "", "", "", true},
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
		{"fragment-route-missing", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "missing", "", false},
		{"fragment-route-skip", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "skip", "", false},
		{"fragment-route-fail", "TestDOMXSSFragmentRouteTestsRouteParameterAndConfirms", "fail", "", false},
		{"fragment-postload-missing", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "missing", "", false},
		{"fragment-postload-skip", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "skip", "", false},
		{"fragment-postload-fail", "TestDOMXSSFragmentRouteCapturesPostLoadSink", "fail", "", false},
		{"script-literal-missing", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "missing", "", false},
		{"script-literal-skip", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "skip", "", false},
		{"script-literal-fail", "TestDOMXSSScriptLiteralParameterConfirmsOnQuerySource", "fail", "", false},
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

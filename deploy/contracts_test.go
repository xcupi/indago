package deploy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func requireText(t *testing.T, path string, required ...string) string {
	t.Helper()
	b, err := os.ReadFile("../" + path)
	if err != nil {
		t.Fatalf("deployment artifact %s: %v", path, err)
	}
	s := string(b)
	for _, want := range required {
		if !strings.Contains(s, want) {
			t.Errorf("%s missing contract %q", path, want)
		}
	}
	return s
}

func TestCIContract(t *testing.T) {
	s := requireText(t, ".github/workflows/ci.yml", "push:", "pull_request:", "workflow_dispatch:", "contents: read", "cancel-in-progress: true", "timeout-minutes:", "go-version-file: go.mod", "node-version: '24'", "PLAYWRIGHT_NODEJS_PATH", "--version", "go mod verify", "go clean -testcache", "make check", "make build", "python3 scripts/ci-browser-check.py")
	pins := regexp.MustCompile(`uses: ([^\s@]+)@([^\s]+)`).FindAllStringSubmatch(s, -1)
	if len(pins) < 3 {
		t.Fatal("expected checkout, Go and Node setup actions")
	}
	for _, pin := range pins {
		if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(pin[2]) {
			t.Errorf("action not SHA-pinned: %s", pin[0])
		}
	}
	requireText(t, "scripts/ci-browser-check.py", "TestIntegrationRenderRealBrowser", "TestIntegrationVerifyExecutableCandidateIsConfirmed", "TestUINavigation", "TestUICooldownClock", "TestE2E_FullPipelineAgainstCorpus", "skip", "raise SystemExit", "INDAGO_CHROMIUM_PATH")
}

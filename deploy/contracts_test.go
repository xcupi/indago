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

func TestDockerContract(t *testing.T) {
	s := requireText(t, "Dockerfile", "AS build", "go mod verify", "make build", "PLAYWRIGHT_DRIVER_PATH=/opt/playwright", "--version", "chromium", "ca-certificates", "USER 10001:10001", "VOLUME [\"/var/lib/indago\"]", "HEALTHCHECK", "STOPSIGNAL SIGTERM", "-allow-remote", "-tls-cert", "-tls-key")
	if strings.Contains(s, "allow-plaintext-remote") {
		t.Error("image must not downgrade remote TLS")
	}
	requireText(t, ".dockerignore", "data/", ".git", ".env", "sessions/", "*.key", "bin/", "*.log")
	requireText(t, "deploy/docker/healthcheck.sh", "--cacert", "INDAGO_HEALTH_CA", "https://127.0.0.1:8750/healthz")
}

func TestSystemdContract(t *testing.T) {
	s := requireText(t, "deploy/systemd/indago.service", "User=indago", "Group=indago", "StateDirectory=indago", "WorkingDirectory=/var/lib/indago", "CacheDirectory=indago", "RuntimeDirectory=indago", "EnvironmentFile=/etc/indago/indago.env", "Restart=on-failure", "TimeoutStopSec=60", "KillSignal=SIGTERM", "NoNewPrivileges=yes", "ProtectSystem=strict", "-addr 127.0.0.1:8750")
	for _, forbidden := range []string{"allow-remote", "allow-plaintext", "User=root", "MemoryDenyWriteExecute=yes", "RestrictNamespaces=yes"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("unsafe/unvalidated default unit option %q", forbidden)
		}
	}
	env := requireText(t, "deploy/systemd/indago.env.example", "INDAGO_API_TOKEN=", "600")
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "INDAGO_API_TOKEN=") && line != "INDAGO_API_TOKEN=" {
			t.Error("environment example must contain no live/dummy secret")
		}
	}
	requireText(t, "deploy/systemd/browser.conf", "ExecStart=\n", "-browser", "PLAYWRIGHT_DRIVER_PATH", "INDAGO_CHROMIUM_PATH")
}

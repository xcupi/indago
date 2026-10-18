package browser

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// A failed launch with the sandbox on must tell the operator how to opt out,
// but must NOT silently retry without the sandbox.
func TestNewManagerSandboxLaunchFailureNamesExplicitOptOut(t *testing.T) {
	d := &fakeDriver{failAfter: 1}
	_, err := newManager(Config{Headless: true, PoolSize: 2}, nil, fakeFactory(d))
	if err == nil {
		t.Fatal("launch failure must be reported")
	}
	if !strings.Contains(err.Error(), "-browser-no-sandbox") {
		t.Fatalf("error should name the explicit opt-out flag: %v", err)
	}
	if d.launched != 1 {
		t.Fatalf("a failed sandboxed launch must not be retried or degraded; launched = %d", d.launched)
	}
}

func TestNewManagerLaunchFailureOmitsOptOutHintWhenAlreadyDisabled(t *testing.T) {
	d := &fakeDriver{failAfter: 1}
	_, err := newManager(Config{Headless: true, PoolSize: 2, DisableSandbox: true}, nil, fakeFactory(d))
	if err == nil {
		t.Fatal("launch failure must be reported")
	}
	if strings.Contains(err.Error(), "-browser-no-sandbox") {
		t.Fatalf("hint is misleading when the sandbox is already off: %v", err)
	}
}

func TestNewManagerWarnsLoudlyWhenSandboxDisabled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	m, err := newManager(Config{Headless: true, DisableSandbox: true}, log, fakeFactory(&fakeDriver{}))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(strings.ToLower(out), "sandbox") {
		t.Fatalf("disabling the sandbox must log a WARN naming the sandbox; log: %s", out)
	}
}

func TestNewManagerDoesNotWarnWhenSandboxEnabled(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	m, err := newManager(Config{Headless: true}, log, fakeFactory(&fakeDriver{}))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("no warning expected with the sandbox on; log: %s", buf.String())
	}
}

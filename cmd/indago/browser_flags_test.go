package main

import (
	"strings"
	"testing"
)

func TestBrowserConfigKeepsSandboxOnByDefault(t *testing.T) {
	cfg, err := browserConfigFromFlags(true, false, "/usr/bin/chromium")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DisableSandbox {
		t.Fatal("the Chromium process sandbox must stay ON unless explicitly disabled")
	}
	if !cfg.Headless || cfg.ExecutablePath != "/usr/bin/chromium" {
		t.Fatalf("unrelated settings must be preserved: %+v", cfg)
	}
}

func TestBrowserConfigExplicitOptOutDisablesSandbox(t *testing.T) {
	cfg, err := browserConfigFromFlags(true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableSandbox {
		t.Fatal("-browser-no-sandbox must disable the sandbox")
	}
}

// A sandbox opt-out without a browser would silently do nothing; refuse it so
// an operator never believes a setting took effect when it did not.
func TestBrowserConfigRefusesNoSandboxWithoutBrowser(t *testing.T) {
	_, err := browserConfigFromFlags(false, true, "")
	if err == nil {
		t.Fatal("-browser-no-sandbox without -browser must be rejected")
	}
	if !strings.Contains(err.Error(), "-browser") {
		t.Fatalf("error should name the missing -browser flag: %v", err)
	}
}

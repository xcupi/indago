package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const cliLLMKey = "sk-cli-test-0123456789abcdefQRST"

func newLLMCli(t *testing.T) (*cli, *bytes.Buffer) {
	t.Helper()
	t.Setenv(llmAPIKeyEnv, "") // a developer's ambient key must not affect the test
	out := &bytes.Buffer{}
	return newCLI(defaultServer(), out), out
}

func mustConfig(t *testing.T, c *cli, args ...string) {
	t.Helper()
	if err := c.config("llm", args); err != nil {
		t.Fatalf("indago config llm %v: %v", args, err)
	}
}

func TestCLIConfigLLMSetShowTestClear(t *testing.T) {
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer upstream.Close()

	c, out := newLLMCli(t)
	dir := t.TempDir()

	mustConfig(t, c, "set", "-data", dir, "-provider", "custom", "-base-url", upstream.URL,
		"-model", "test-model", "-api-key", cliLLMKey)
	setOut := out.String()
	if strings.Contains(setOut, cliLLMKey) {
		t.Fatalf("set output contains the literal key:\n%s", setOut)
	}
	if !strings.Contains(setOut, "****"+cliLLMKey[len(cliLLMKey)-4:]) {
		t.Fatalf("set output is missing the masked hint:\n%s", setOut)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("config set contacted the provider %d time(s)", got)
	}

	// The stored layout: 0700 directory, 0600 files, key absent from config.
	llmDir := filepath.Join(dir, "llm")
	if fi, err := os.Stat(llmDir); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("directory mode = %04o, want 0700", got)
	}
	if fi, err := os.Stat(filepath.Join(llmDir, "config.json")); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("config mode = %04o, want 0600", got)
	}
	keyPath := filepath.Join(llmDir, "api_key")
	if fi, err := os.Stat(keyPath); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", got)
	}
	rawConfig, err := os.ReadFile(filepath.Join(llmDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawConfig), cliLLMKey) {
		t.Fatalf("config.json contains the literal key:\n%s", rawConfig)
	}

	out.Reset()
	mustConfig(t, c, "show", "-data", dir)
	showOut := out.String()
	if strings.Contains(showOut, cliLLMKey) {
		t.Fatalf("show output contains the key:\n%s", showOut)
	}
	for _, want := range []string{"provider: custom", "model:    test-model", "base URL: " + upstream.URL, "****" + cliLLMKey[len(cliLLMKey)-4:], "mode 0600"} {
		if !strings.Contains(showOut, want) {
			t.Errorf("show output missing %q:\n%s", want, showOut)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("config show contacted the provider %d time(s)", got)
	}

	out.Reset()
	mustConfig(t, c, "test", "-data", dir)
	testOut := out.String()
	if strings.Contains(testOut, cliLLMKey) {
		t.Fatalf("test output contains the key:\n%s", testOut)
	}
	for _, want := range []string{"provider: custom", "model:    test-model", "latency:", "result:   OK"} {
		if !strings.Contains(testOut, want) {
			t.Errorf("test output missing %q:\n%s", want, testOut)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("test made %d provider requests, want exactly 1", got)
	}

	out.Reset()
	mustConfig(t, c, "clear", "-data", dir)
	if !strings.Contains(out.String(), "cleared") {
		t.Fatalf("clear output: %q", out.String())
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("key file still exists after clear: %v", err)
	}
	out.Reset()
	mustConfig(t, c, "show", "-data", dir)
	if !strings.Contains(out.String(), "not configured") {
		t.Fatalf("show after clear: %q", out.String())
	}
}

func TestCLIConfigLLMTestFailureRedactsKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"401 invalid key `+cliLLMKey+`"}}`)
	}))
	defer upstream.Close()

	c, out := newLLMCli(t)
	dir := t.TempDir()
	mustConfig(t, c, "set", "-data", dir, "-provider", "custom", "-base-url", upstream.URL,
		"-model", "m", "-api-key", cliLLMKey)

	out.Reset()
	err := c.config("llm", []string{"test", "-data", dir})
	if err == nil {
		t.Fatal("a 401 provider test returned no error")
	}
	if strings.Contains(err.Error(), cliLLMKey) {
		t.Fatalf("error contains the literal key: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("error is not redacted: %v", err)
	}
	if strings.Contains(out.String(), cliLLMKey) {
		t.Fatalf("test output contains the key:\n%s", out.String())
	}
}

func TestCLIConfigLLMUnreachableFailsFast(t *testing.T) {
	c, _ := newLLMCli(t)
	dir := t.TempDir()
	mustConfig(t, c, "set", "-data", dir, "-provider", "custom", "-base-url", "http://127.0.0.1:1",
		"-model", "m", "-api-key", cliLLMKey)

	start := time.Now()
	err := c.config("llm", []string{"test", "-data", dir})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("an unreachable endpoint returned no error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("unreachable test took %v, want a fast failure", elapsed)
	}
	if strings.Contains(err.Error(), cliLLMKey) {
		t.Fatalf("error contains the key: %v", err)
	}
}

func TestCLIConfigLLMRequiresAKeyForHostedProviders(t *testing.T) {
	c, _ := newLLMCli(t)
	dir := t.TempDir()
	err := c.config("llm", []string{"set", "-data", dir, "-provider", "deepseek"})
	if err == nil {
		t.Fatal("deepseek without a key was accepted")
	}
	if strings.Contains(err.Error(), cliLLMKey) {
		t.Fatalf("error contains a key: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "llm")); !os.IsNotExist(statErr) {
		t.Fatalf("a rejected configuration created a directory: %v", statErr)
	}

	// A local custom endpoint needs no key.
	mustConfig(t, c, "set", "-data", dir, "-provider", "custom", "-base-url", "http://127.0.0.1:11434/v1", "-model", "llama3")
}

func TestCLIConfigLLMUsesEnvKeyAndKeepsItOnUpdate(t *testing.T) {
	c, out := newLLMCli(t)
	dir := t.TempDir()
	t.Setenv(llmAPIKeyEnv, cliLLMKey)
	mustConfig(t, c, "set", "-data", dir, "-provider", "deepseek", "-model", "deepseek-chat")
	if strings.Contains(out.String(), cliLLMKey) {
		t.Fatalf("set output contains the env key:\n%s", out.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "llm", "api_key"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != cliLLMKey {
		t.Fatal("the env key was not stored")
	}

	// An update without a key must keep the stored one.
	mustConfig(t, c, "set", "-data", dir, "-provider", "deepseek", "-model", "deepseek-reasoner")
	raw, err = os.ReadFile(filepath.Join(dir, "llm", "api_key"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != cliLLMKey {
		t.Fatal("an update without a key lost the stored key")
	}
	out.Reset()
	mustConfig(t, c, "show", "-data", dir)
	if !strings.Contains(out.String(), "deepseek-reasoner") {
		t.Fatalf("show does not reflect the updated model:\n%s", out.String())
	}
}

func TestCLIConfigLLMUnknownSubcommand(t *testing.T) {
	c, _ := newLLMCli(t)
	if err := c.config("llm", []string{"frobnicate"}); err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	if err := c.config("oauth", []string{"login"}); err == nil {
		t.Fatal("an unknown section was accepted")
	}
}

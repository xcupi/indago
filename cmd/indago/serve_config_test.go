package main

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/indago/indago/internal/config"
)

// An occupied loopback listener lets the real startup path finish without
// installing test-wide signal handlers or leaving a server behind.
func occupiedServeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l.Addr().String()
}

func TestServeOverridePreservesExistingConfigBytes(t *testing.T) {
	t.Setenv(apiTokenEnv, "")
	dir := t.TempDir()
	original := []byte("{\n  \"server\": {\"addr\": \"127.0.0.1:9876\", \"api_rate\": 7, \"api_burst\": 9},\n  \"operator_extension\": true\n}\n")
	path := cfgPath(dir)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdServe([]string{"-data", dir, "-addr", occupiedServeAddr(t), "-api-rate", "0"}); err == nil {
		t.Fatal("expected bind failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("runtime startup modified stored config: %s", got)
	}
	cfg, err := config.Load(path)
	if err != nil || cfg.Server.Addr != "127.0.0.1:9876" || cfg.Server.APIRate != 7 {
		t.Fatalf("restart settings = %+v, %v", cfg.Server, err)
	}
}

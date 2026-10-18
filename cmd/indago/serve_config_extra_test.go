package main

import (
	"bytes"
	"github.com/indago/indago/internal/config"
	"os"
	"testing"
)

func TestServeFirstTemplateExcludesRuntimeOverrides(t *testing.T) {
	t.Setenv(apiTokenEnv, "dummy-startup-token-at-least-32-characters")
	dir := t.TempDir()
	cert, key := writeTestTLSPair(t, t.TempDir(), "runtime")
	if err := cmdServe([]string{"-data", dir, "-addr", occupiedServeAddr(t), "-api-rate", "0", "-api-burst", "3", "-tls-cert", cert, "-tls-key", key}); err == nil {
		t.Fatal("expected bind failure")
	}
	cfg, err := config.Load(cfgPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != config.Default().Server {
		t.Fatalf("template retained runtime overrides: %+v", cfg.Server)
	}
	b, err := os.ReadFile(cfgPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cert, key, os.Getenv(apiTokenEnv)} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("runtime TLS/token persisted")
		}
	}
}

func TestServeInvalidFlagsDoNotModifyConfig(t *testing.T) {
	t.Setenv(apiTokenEnv, "")
	for _, flags := range [][]string{{"-api-rate", "-1"}, {"-api-burst", "0"}, {"-tls-cert", "missing"}, {"-addr", "0.0.0.0:9999"}} {
		t.Run(flags[0]+flags[1], func(t *testing.T) {
			dir := t.TempDir()
			original := []byte(`{"server":{"addr":"127.0.0.1:9876"}}`)
			if err := os.WriteFile(cfgPath(dir), original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := cmdServe(append([]string{"-data", dir}, flags...)); err == nil {
				t.Fatal("invalid flags accepted")
			}
			b, err := os.ReadFile(cfgPath(dir))
			if err != nil || !bytes.Equal(b, original) {
				t.Fatal("invalid startup modified config", err)
			}
		})
	}
}

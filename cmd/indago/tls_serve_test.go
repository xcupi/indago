package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyLines returns the non-header lines of a PEM key file: its base64 body.
// Used to assert that no part of the key material appears in an error.
func keyLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "-----") {
			out = append(out, l)
		}
	}
	return out
}

func TestValidateTLSFlagsRequiresCertAndKeyTogether(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestTLSPair(t, dir, "pair")

	if err := validateTLSFlags("", ""); err != nil {
		t.Errorf("neither flag: want nil, got %v", err)
	}
	if err := validateTLSFlags(cert, key); err != nil {
		t.Errorf("both flags: want nil, got %v", err)
	}
	err := validateTLSFlags(cert, "")
	if err == nil || !strings.Contains(err.Error(), "-tls-key") {
		t.Errorf("cert without key: want an error naming -tls-key, got %v", err)
	}
	err = validateTLSFlags("", key)
	if err == nil || !strings.Contains(err.Error(), "-tls-cert") {
		t.Errorf("key without cert: want an error naming -tls-cert, got %v", err)
	}
}

func TestCheckRemoteBindTLSPolicy(t *testing.T) {
	const tok = "indago-test-token-9f2c7d41a8e6b305c1d9e2f7a4b8c6d0" // dummy
	cases := []struct {
		name        string
		addr        string
		allowRemote bool
		token       string
		tlsOn       bool
		allowPlain  bool
		wantErr     bool
		wantWarn    bool
	}{
		{"loopback, plain HTTP, no token", "127.0.0.1:8750", false, "", false, false, false, false},
		{"loopback, plain HTTP, token, no opt-in", "127.0.0.1:8750", false, tok, false, false, false, false},
		{"remote, opted in, token, NO TLS: refused", "0.0.0.0:8750", true, tok, false, false, true, false},
		{"remote, opted in, token, TLS: allowed, no warning", "0.0.0.0:8750", true, tok, true, false, false, false},
		{"remote, opted in, token, NO TLS, allow-plaintext: allowed with warning", "0.0.0.0:8750", true, tok, false, true, false, true},
		{"remote, opted in, token, TLS + allow-plaintext: allowed, no warning", "0.0.0.0:8750", true, tok, true, true, false, false},
		{"remote, opted in, NO token, TLS: refused", "0.0.0.0:8750", true, "", true, false, true, false},
		{"remote, NOT opted in, token, TLS: refused", "0.0.0.0:8750", false, tok, true, false, true, false},
		{"remote, NOT opted in, token, NO TLS, allow-plaintext: refused", "0.0.0.0:8750", false, tok, false, true, true, false},
	}
	for _, c := range cases {
		warn, err := checkRemoteBindAllowed(c.addr, c.allowRemote, c.token, c.tlsOn, c.allowPlain)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
		if (warn != "") != c.wantWarn {
			t.Errorf("%s: warning = %q, wantWarn %v", c.name, warn, c.wantWarn)
		}
		if c.wantWarn && !strings.Contains(warn, "unencrypted") {
			t.Errorf("%s: the plaintext warning must say the token travels unencrypted, got %q", c.name, warn)
		}
		if strings.Contains(warn, tok) || (err != nil && strings.Contains(err.Error(), tok)) {
			t.Errorf("%s: warning or error text contains the token", c.name)
		}
	}
	// The refusal for a remote bind without TLS names the flags that fix it.
	_, err := checkRemoteBindAllowed("0.0.0.0:8750", true, tok, false, false)
	if err == nil || !strings.Contains(err.Error(), "-tls-cert") || !strings.Contains(err.Error(), "-tls-key") ||
		!strings.Contains(err.Error(), "-allow-plaintext-remote") {
		t.Errorf("remote bind without TLS: error should name -tls-cert, -tls-key and -allow-plaintext-remote, got %v", err)
	}
}

func TestNewServeTLSConfigLoadsPairAndRequiresTLS12(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestTLSPair(t, dir, "good")

	cfg, err := newServeTLSConfig(cert, key)
	if err != nil {
		t.Fatalf("valid pair: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("want exactly one certificate loaded, got %d", len(cfg.Certificates))
	}
}

func TestNewServeTLSConfigErrorsNeverShowKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	cert, _ := writeTestTLSPair(t, dir, "good")
	_, otherKey := writeTestTLSPair(t, dir, "other")

	// Mismatched pair: the certificate of one key, the key of another.
	_, err := newServeTLSConfig(cert, otherKey)
	assertNoKeyMaterial(t, "mismatched key", err, otherKey, keyLines(t, otherKey))

	// Malformed key file whose body is a recognisable marker.
	const marker = "MARKER-KEY-MATERIAL-7d3e-do-not-print"
	bad := filepath.Join(dir, "bad-key.pem")
	if err := os.WriteFile(bad, []byte("-----BEGIN PRIVATE KEY-----\n"+marker+"\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = newServeTLSConfig(cert, bad)
	assertNoKeyMaterial(t, "malformed key", err, bad, []string{marker})

	// Missing key file: the error names the path and nothing else sensitive.
	missing := filepath.Join(dir, "does-not-exist.pem")
	_, err = newServeTLSConfig(cert, missing)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing key: want an error naming %s, got %v", missing, err)
	}
}

func assertNoKeyMaterial(t *testing.T, what string, err error, keyPath string, secrets []string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want an error, got nil", what)
	}
	if !strings.Contains(err.Error(), keyPath) {
		t.Errorf("%s: error should name the key file %s, got %v", what, keyPath, err)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("%s: error text contains key material: %v", what, err)
		}
	}
}

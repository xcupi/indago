package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testKey = "sk-test-0123456789abcdefghijWXYZ"

func TestProviderDefaults(t *testing.T) {
	def, ok := LookupProvider(ProviderDeepSeek)
	if !ok {
		t.Fatal("deepseek is not a known provider")
	}
	if def.DefaultBaseURL != "https://api.deepseek.com" || def.DefaultModel != "deepseek-chat" || !def.RequiresKey {
		t.Fatalf("deepseek definition = %+v", def)
	}
	if !def.Default {
		t.Fatal("deepseek must be the default provider")
	}
	oai, ok := LookupProvider("OpenAI") // case-insensitive
	if !ok || oai.ID != ProviderOpenAI || oai.DefaultBaseURL != "https://api.openai.com/v1" || !oai.RequiresKey {
		t.Fatalf("openai definition = %+v, ok=%v", oai, ok)
	}
	custom, ok := LookupProvider(ProviderCustom)
	if !ok || custom.RequiresKey || custom.DefaultBaseURL != "" || custom.DefaultModel != "" {
		t.Fatalf("custom definition = %+v, ok=%v", custom, ok)
	}
	n := 0
	for _, p := range Providers() {
		if p.Default {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d providers marked default, want exactly 1", n)
	}
	if _, ok := LookupProvider("chatgpt-oauth"); ok {
		t.Fatal("an imaginary provider was accepted")
	}
}

func TestStoreSeparatesSecretAndSetsRestrictiveModes(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "llm"))
	cfg, err := s.Set(SetRequest{Provider: ProviderDeepSeek, APIKey: testKey})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if cfg.Provider != ProviderDeepSeek || cfg.Model != "deepseek-chat" || cfg.BaseURL != "https://api.deepseek.com" {
		t.Fatalf("normalized config = %+v", cfg)
	}
	if !cfg.HasKey() || cfg.apiKey != testKey {
		t.Fatal("the key was not stored")
	}
	if cfg.MaskedKey() == testKey || !strings.HasSuffix(cfg.MaskedKey(), testKey[len(testKey)-4:]) {
		t.Fatalf("masked key = %q, want only the last 4 characters", cfg.MaskedKey())
	}

	// Directory 0700, both files 0600.
	di, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("config directory mode = %04o, want 0700", got)
	}
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("config file mode = %04o, want 0600", got)
	}
	ki, err := os.Stat(savedKeyPath(t, s, ProviderDeepSeek))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := ki.Mode().Perm(); got != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", got)
	}

	// The non-secret config file must not contain the literal key.
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testKey) {
		t.Fatalf("config.json contains the literal API key:\n%s", raw)
	}
	keyRaw, err := os.ReadFile(savedKeyPath(t, s, ProviderDeepSeek))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(keyRaw)) != testKey {
		t.Fatal("the key file does not hold the stored key")
	}

	// Every public representation of Config and Status must omit the key.
	for name, v := range map[string]any{"Config": cfg, "Status": cfg.Status()} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		if strings.Contains(string(b), testKey) {
			t.Errorf("%s JSON contains the key: %s", name, b)
		}
	}
	for _, format := range []string{"%v", "%+v", "%s"} {
		if got := fmt.Sprintf(format, cfg); strings.Contains(got, testKey) {
			t.Errorf("fmt %q on Config leaked the key: %s", format, got)
		}
	}
}

func TestStoreTightensExistingPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "llm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A stale, world-readable config and key file from an older/hand-made setup.
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("old-key-value"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, keyFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if _, err := s.Set(SetRequest{Provider: ProviderCustom, BaseURL: "http://127.0.0.1:11434/v1", Model: "llama3", APIKey: "new-key-value"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := mustPerm(t, dir); got != 0o700 {
		t.Errorf("directory mode after save = %04o, want 0700", got)
	}
	if got := mustPerm(t, s.Path()); got != 0o600 {
		t.Errorf("config file mode after save = %04o, want 0600", got)
	}
	if got := mustPerm(t, savedKeyPath(t, s, ProviderCustom)); got != 0o600 {
		t.Errorf("key file mode after save = %04o, want 0600", got)
	}
}

func mustPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestStoreEmptyKeyOnUpdateKeepsTheStoredKey(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "llm"))
	if _, err := s.Set(SetRequest{Provider: ProviderDeepSeek, APIKey: testKey}); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Set(SetRequest{Provider: ProviderDeepSeek, Model: "deepseek-reasoner"})
	if err != nil {
		t.Fatalf("update without a key: %v", err)
	}
	if cfg.apiKey != testKey {
		t.Fatal("an update with an empty key did not keep the stored key")
	}
	if cfg.Model != "deepseek-reasoner" {
		t.Fatalf("model = %q, want the updated value", cfg.Model)
	}
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.apiKey != testKey || loaded.Model != "deepseek-reasoner" {
		t.Fatalf("reloaded config = %v", loaded)
	}
	// An explicit new key replaces the old one.
	if _, err := s.Set(SetRequest{Provider: ProviderDeepSeek, APIKey: "sk-new-key-000000000000"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.apiKey != "sk-new-key-000000000000" {
		t.Fatal("an explicit key did not replace the stored key")
	}
}

func TestStoreValidation(t *testing.T) {
	cases := []struct {
		name string
		req  SetRequest
	}{
		{"unknown provider", SetRequest{Provider: "chatgpt-oauth", APIKey: testKey}},
		{"deepseek without a key", SetRequest{Provider: ProviderDeepSeek}},
		{"openai without a key", SetRequest{Provider: ProviderOpenAI}},
		{"custom without a base url", SetRequest{Provider: ProviderCustom, Model: "m"}},
		{"custom without a model", SetRequest{Provider: ProviderCustom, BaseURL: "http://127.0.0.1:11434/v1"}},
		{"ftp base url", SetRequest{Provider: ProviderCustom, BaseURL: "ftp://example.com/v1", Model: "m"}},
		{"relative base url", SetRequest{Provider: ProviderCustom, BaseURL: "example.com/v1", Model: "m"}},
		{"credentials in base url", SetRequest{Provider: ProviderCustom, BaseURL: "https://user:pass@example.com/v1", Model: "m"}},
		{"query in base url", SetRequest{Provider: ProviderCustom, BaseURL: "https://example.com/v1?token=abc", Model: "m"}},
		{"control char in key", SetRequest{Provider: ProviderCustom, BaseURL: "http://127.0.0.1:11434/v1", Model: "m", APIKey: "abc\ndef"}},
		{"space in key", SetRequest{Provider: ProviderCustom, BaseURL: "http://127.0.0.1:11434/v1", Model: "m", APIKey: "abc def"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewStore(filepath.Join(t.TempDir(), "llm"))
			_, err := s.Set(c.req)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Set error = %v, want ErrInvalid", err)
			}
			if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("a rejected configuration was persisted: %v", err)
			}
			// A validation error must never echo a submitted value: a secret
			// pasted into provider/base_url would otherwise reach the API
			// response and the server log.
			if c.req.APIKey != "" && strings.Contains(err.Error(), c.req.APIKey) {
				t.Fatalf("validation error echoes the submitted key: %v", err)
			}
		})
	}
}

func TestStoreCustomWithoutKeyIsAllowed(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "llm"))
	cfg, err := s.Set(SetRequest{Provider: ProviderCustom, BaseURL: "http://127.0.0.1:11434/v1/", Model: "llama3"})
	if err != nil {
		t.Fatalf("custom local endpoint without a key: %v", err)
	}
	if cfg.HasKey() {
		t.Fatal("a key appeared from nowhere")
	}
	if cfg.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("base url = %q, want the trailing slash trimmed", cfg.BaseURL)
	}
	assertNoCredentialFiles(t, s)
}

func TestStoreClearIsIdempotentAndRemovesTheSecret(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "llm"))
	if _, err := s.Set(SetRequest{Provider: ProviderDeepSeek, APIKey: testKey}); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := s.Load(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Load after Clear = %v, want ErrNotConfigured", err)
	}
	assertNoCredentialFiles(t, s)
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Errorf("config still exists after Clear: %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}

func TestStoreRejectsCorruptOrFutureConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "llm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if err := os.WriteFile(s.Path(), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Fatalf("corrupt config Load = %v, want a parse error", err)
	}
	if err := os.WriteFile(s.Path(), []byte(`{"version":99,"provider":"deepseek","model":"m","base_url":"https://example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("future config Load = %v, want an unsupported-version error", err)
	}
}

func TestMaskKeyNeverRevealsAShortKey(t *testing.T) {
	for _, k := range []string{"", "a", "short", "12345678901"} {
		if got := maskKey(k); got != "" && got != "****" {
			t.Errorf("maskKey(%q) = %q", k, got)
		}
		if strings.Contains(maskKey(k), k) && k != "" && len(k) <= 4 {
			t.Errorf("maskKey(%q) contains the key", k)
		}
	}
	long := "sk-abcdefghijklmnop"
	if got := maskKey(long); got != "****mnop" {
		t.Errorf("maskKey(long) = %q, want ****mnop", got)
	}
}

func TestLegacyChatGPTOAuthConfigRequiresNewOpenAIKey(t *testing.T) {
	s := NewStore(t.TempDir())
	const previous = `{"version":1,"provider":"chatgpt","model":"oauth-model","base_url":"https://chatgpt.com/backend-api/codex","max_attempts":7,"enabled":false}`
	if err := os.WriteFile(s.Path(), []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), keyFileName), []byte("legacy-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != ProviderOpenAI || cfg.BaseURL != "https://api.openai.com/v1" ||
		cfg.HasKey() || cfg.Model == "oauth-model" || cfg.AIEnabled() || cfg.AttemptBudget() != 7 {
		t.Fatalf("unexpected migrated configuration: %+v", cfg)
	}
	raw, err := os.ReadFile(s.Path())
	if err != nil || string(raw) != previous {
		t.Fatal("reading legacy settings must not change the stored configuration")
	}
	if _, err := s.Set(SetRequest{Provider: ProviderOpenAI, Model: "fixture-api-model"}); err == nil {
		t.Fatal("saving the migrated provider must require a new API key")
	}
	if _, err := s.Set(SetRequest{Provider: ProviderOpenAI, Model: "fixture-api-model", APIKey: "new-api-key"}); err != nil {
		t.Fatal(err)
	}
}

func savedKeyPath(t *testing.T, s *Store, provider string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(s.Dir(), keyPrefix(provider)+"*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one saved key for %s, files=%v, error=%v", provider, matches, err)
	}
	return matches[0]
}

func assertNoCredentialFiles(t *testing.T, s *Store) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(s.Dir(), "api_key*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("expected no saved key files, files=%v, error=%v", matches, err)
	}
}

func TestStoreProfilesSurviveSwitchAndV1Migration(t *testing.T) {
	s := NewStore(t.TempDir())
	legacy := `{"version":1,"provider":"deepseek","model":"legacy-model","base_url":"https://legacy.example/v1","max_attempts":8,"enabled":false}`
	if err := os.WriteFile(s.Path(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), keyFileName), []byte(testKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Load()
	if err != nil || cfg.Model != "legacy-model" || cfg.apiKey != testKey || cfg.AIEnabled() {
		t.Fatalf("legacy config=%+v, error=%v", cfg, err)
	}
	secondKey := "fixture-second-key-0002"
	if _, err := s.Set(SetRequest{Provider: ProviderGoogle, APIKey: secondKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), keyFileName)); !os.IsNotExist(err) {
		t.Fatalf("legacy key still present after migration: %v", err)
	}
	registry := NewRegistry(NewStore(s.Dir()))
	first, err := registry.Resolve(ProviderDeepSeek, "")
	if err != nil || first.APIKey() != testKey || first.Model != "legacy-model" || first.BaseURL != "https://legacy.example/v1" {
		t.Fatalf("migrated credential=%+v, error=%v", first, err)
	}
	cfg, err = s.Set(SetRequest{Provider: ProviderDeepSeek})
	if err != nil || cfg.apiKey != testKey || cfg.Model != "legacy-model" || cfg.BaseURL != "https://legacy.example/v1" || cfg.AIEnabled() || cfg.AttemptBudget() != 8 {
		t.Fatalf("selected config=%+v, error=%v", cfg, err)
	}
	second, err := registry.Resolve(ProviderGoogle, "")
	if err != nil || second.APIKey() != secondKey {
		t.Fatalf("second credential=%+v, error=%v", second, err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	assertNoCredentialFiles(t, s)
}

func TestStoreInterruptedKeyWriteDoesNotChangeSelection(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Set(SetRequest{Provider: ProviderOpenRouter, APIKey: testKey, Model: "fixture/original"}); err != nil {
		t.Fatal(err)
	}
	// Crash-equivalent state: a new key was staged and the manifest was not replaced.
	pending, err := s.writeKey(ProviderOpenRouter, "fixture-uncommitted-key")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewStore(s.Dir()).Load()
	if err != nil || cfg.apiKey != testKey || cfg.Model != "fixture/original" {
		t.Fatalf("reloaded config=%+v, error=%v", cfg, err)
	}
	if _, err := s.Set(SetRequest{Provider: ProviderOpenRouter, Model: "fixture/updated"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), pending)); !os.IsNotExist(err) {
		t.Fatalf("unreferenced credential survived collection: %v", err)
	}
}

func TestStoreRejectsCrossProviderKeyReference(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.Set(SetRequest{Provider: ProviderGoogle, APIKey: testKey}); err != nil {
		t.Fatal(err)
	}
	googleKey := filepath.Base(savedKeyPath(t, s, ProviderGoogle))
	disk := diskConfig{Version: configVersion, Provider: ProviderOpenRouter, Profiles: map[string]diskProfile{
		ProviderOpenRouter: {Model: "fixture/text", BaseURL: "https://example.test/v1", KeyFile: googleKey},
	}}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("loaded key belonging to a different provider")
	}
}

func TestStoreConcurrentSavesKeepBothProfiles(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	requests := []SetRequest{
		{Provider: ProviderOpenRouter, APIKey: testKey},
		{Provider: ProviderGoogle, APIKey: "fixture-concurrent-key"},
	}
	for _, req := range requests {
		wg.Go(func() {
			if _, err := NewStore(dir).Set(req); err != nil {
				t.Errorf("save %s: %v", req.Provider, err)
			}
		})
	}
	wg.Wait()
	registry := NewRegistry(NewStore(dir))
	for _, req := range requests {
		cred, err := registry.Resolve(req.Provider, "")
		if err != nil || cred.APIKey() != req.APIKey {
			t.Errorf("credential for %s: %v, error=%v", req.Provider, cred, err)
		}
	}
}

func TestStoreUsesEnvironmentCredentialWithoutPersistingIt(t *testing.T) {
	t.Setenv(KeyEnvName(ProviderClaude), testKey)
	t.Setenv("INDAGO_LLM_MODEL_CLAUDE", "env-fallback-model")
	t.Setenv("INDAGO_LLM_BASE_URL_CLAUDE", "https://env.example/v1/")
	s := NewStore(t.TempDir())
	cfg, err := s.Set(SetRequest{Provider: ProviderClaude, Model: "operator-model"})
	if err != nil || cfg.HasKey() || cfg.Model != "operator-model" {
		t.Fatalf("saved config=%+v, error=%v", cfg, err)
	}
	assertNoCredentialFiles(t, s)
	r := NewRegistry(s)
	cred, err := r.Resolve("", "")
	if err != nil || cred.APIKey() != testKey || cred.Model != "operator-model" || cred.BaseURL != "https://env.example/v1" {
		t.Fatalf("resolved credential=%+v, error=%v", cred, err)
	}
	av, selected, err := r.List()
	if err != nil || selected != ProviderClaude {
		t.Fatalf("availability=%v, selected=%q, error=%v", av, selected, err)
	}
	for _, p := range av {
		if p.Provider == selected {
			if !p.Configured || !p.Saved || p.Source != "environment" || p.KeyHint != "" {
				t.Fatalf("availability=%+v", p)
			}
			return
		}
	}
	t.Fatal("saved provider not listed")
}

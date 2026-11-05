package web_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/llm"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"github.com/indago/indago/internal/web"
)

const llmTestKey = "sk-test-llm-0123456789ABCDEFghij"

// newLLMServer builds the web handler with a real llm.Store in a temp dir,
// plus the buffer its logger writes to (debug level, so every line is kept).
func newLLMServer(t *testing.T) (http.Handler, *bytes.Buffer, *llm.Store) {
	t.Helper()
	return newLLMServerWithToken(t, "")
}

// newLLMServerWithToken is newLLMServer with the bearer token required when
// token is non-empty.
func newLLMServerWithToken(t *testing.T, token string) (http.Handler, *bytes.Buffer, *llm.Store) {
	t.Helper()
	st := memory.New()
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctrl := scan.NewController(st, queue.NewMemory(), log, "test", scan.Options{})
	t.Cleanup(ctrl.Shutdown)
	evStore, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(st, ctrl, "test", log, evStore, t.TempDir())
	store := llm.NewStore(t.TempDir())
	srv.SetLLMStore(store)
	if token != "" {
		if err := srv.SetAPIToken(token); err != nil {
			t.Fatalf("SetAPIToken: %v", err)
		}
	}
	return srv.Handler(), &logBuf, store
}

// llmRequest sends one request with the CSRF header every mutating request
// needs (harmless on GET).
func llmRequest(t *testing.T, h http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeLLMStatus(t *testing.T, rec *httptest.ResponseRecorder) llm.Status {
	t.Helper()
	var st llm.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status %q: %v", rec.Body.String(), err)
	}
	return st
}

func putLLMConfig(t *testing.T, h http.Handler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := llmRequest(t, h, "PUT", "/api/llm/config", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/llm/config = %d: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func TestLLMConfigKeyIsNeverReturned(t *testing.T) {
	h, logs, store := newLLMServer(t)
	rec := putLLMConfig(t, h, map[string]any{
		"provider": "deepseek", "model": "deepseek-chat", "api_key": llmTestKey,
	})
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatalf("PUT response contains the literal key: %s", rec.Body.String())
	}
	st := decodeLLMStatus(t, rec)
	if !st.Configured || st.Provider != "deepseek" || st.Model != "deepseek-chat" {
		t.Fatalf("status = %+v", st)
	}
	if !st.KeySet {
		t.Fatal("key_set is false after saving a key")
	}
	if want := "****" + llmTestKey[len(llmTestKey)-4:]; st.KeyHint != want {
		t.Fatalf("key hint = %q, want %q", st.KeyHint, want)
	}
	if len(st.Providers) != 3 {
		t.Fatalf("%d provider definitions returned, want 3", len(st.Providers))
	}

	rec = llmRequest(t, h, "GET", "/api/llm/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatalf("GET response contains the literal key: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), st.KeyHint) {
		t.Fatalf("GET response lost the masked hint: %s", rec.Body.String())
	}

	// The non-secret config file must not contain the key; the dedicated key
	// file must (it is the credential store, mode 0600).
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), llmTestKey) {
		t.Fatalf("config.json contains the literal key:\n%s", raw)
	}
	keyRaw, err := os.ReadFile(store.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(keyRaw)) != llmTestKey {
		t.Fatal("the key was not stored in the dedicated key file")
	}

	if strings.Contains(logs.String(), llmTestKey) {
		t.Fatalf("server log contains the key:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "LLM provider configured") {
		t.Fatalf("no audit line for the configuration change:\n%s", logs.String())
	}
}

func TestLLMConfigEmptyKeyKeepsTheStoredKey(t *testing.T) {
	h, logs, store := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{
		"provider": "deepseek", "model": "deepseek-chat", "api_key": llmTestKey,
	})
	rec := putLLMConfig(t, h, map[string]any{
		"provider": "deepseek", "model": "deepseek-reasoner", "api_key": "",
	})
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatal("update response contains the key")
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasKey() {
		t.Fatal("an empty api_key on update cleared the stored key")
	}
	if cfg.Model != "deepseek-reasoner" {
		t.Fatalf("model = %q, want the updated value", cfg.Model)
	}
	if strings.Contains(logs.String(), llmTestKey) {
		t.Fatal("server log contains the key")
	}
}

func TestLLMConfigDeleteClearsEverything(t *testing.T) {
	h, _, store := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{"provider": "deepseek", "api_key": llmTestKey})

	rec := llmRequest(t, h, "DELETE", "/api/llm/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatal("DELETE response contains the key")
	}
	if st := decodeLLMStatus(t, rec); st.Configured || st.KeySet || st.KeyHint != "" {
		t.Fatalf("status after delete = %+v", st)
	}
	if _, err := store.Load(); !errors.Is(err, llm.ErrNotConfigured) {
		t.Fatalf("Load after DELETE = %v, want ErrNotConfigured", err)
	}
	for _, p := range []string{store.Path(), store.KeyPath()} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after DELETE", p)
		}
	}
}

func TestLLMTestRedactsKeyFromResponseAndLogs(t *testing.T) {
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"401 invalid key `+llmTestKey+` for model"}}`)
	}))
	defer upstream.Close()

	h, logs, _ := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{
		"provider": "custom", "model": "test-model", "base_url": upstream.URL, "api_key": llmTestKey,
	})

	rec := llmRequest(t, h, "POST", "/api/llm/test", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/llm/test = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, llmTestKey) {
		t.Fatalf("test response contains the literal key: %s", body)
	}
	if !strings.Contains(body, llm.Redacted) {
		t.Fatalf("test response is not redacted: %s", body)
	}
	var res llm.ProbeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode probe result: %v", err)
	}
	if res.OK {
		t.Fatal("a 401 probe was reported as ok")
	}
	if res.Error == "" || !strings.Contains(res.Error, "401") {
		t.Fatalf("probe error = %q", res.Error)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("probe made %d upstream requests, want exactly 1", got)
	}

	logText := logs.String()
	if strings.Contains(logText, llmTestKey) {
		t.Fatalf("server log contains the key:\n%s", logText)
	}
	if !strings.Contains(logText, "LLM connection test failed") {
		t.Fatalf("no failed-test audit line:\n%s", logText)
	}
}

func TestLLMNoProviderCallWithoutAnExplicitTest(t *testing.T) {
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
	}))
	defer upstream.Close()

	h, _, _ := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{
		"provider": "custom", "model": "test-model", "base_url": upstream.URL, "api_key": llmTestKey,
	})
	// Reading the configuration, opening the settings page, and unrelated
	// control-API traffic must not contact the provider.
	for _, req := range []struct{ method, path string }{
		{"GET", "/api/llm/config"},
		{"GET", "/"},
		{"GET", "/api/version"},
		{"GET", "/api/projects"},
	} {
		llmRequest(t, h, req.method, req.path, nil)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("%d provider request(s) happened without an explicit Test", got)
	}

	rec := llmRequest(t, h, "POST", "/api/llm/test", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("explicit Test made %d provider requests, want exactly 1", got)
	}
}

func TestLLMTestUnreachableFailsFast(t *testing.T) {
	h, _, _ := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{
		"provider": "custom", "model": "test-model", "base_url": "http://127.0.0.1:1", "api_key": llmTestKey,
	})

	start := time.Now()
	rec := llmRequest(t, h, "POST", "/api/llm/test", map[string]any{})
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("an unreachable base URL took %v to fail", elapsed)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body.String())
	}
	var res llm.ProbeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatal("an unreachable endpoint was reported as reachable")
	}
	if res.Error == "" {
		t.Fatal("no error returned for an unreachable endpoint")
	}
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatal("unreachable-test response contains the key")
	}
}

func TestLLMModelsDegradesGracefully(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	h, _, _ := newLLMServer(t)
	putLLMConfig(t, h, map[string]any{
		"provider": "custom", "model": "test-model", "base_url": upstream.URL, "api_key": llmTestKey,
	})
	rec := llmRequest(t, h, "POST", "/api/llm/models", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("models = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Models []string `json:"models"`
		Error  string   `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Models == nil || len(out.Models) != 0 {
		t.Fatalf("models = %v, want an empty (not missing) list", out.Models)
	}
	if !strings.Contains(out.Error, "404") {
		t.Fatalf("error = %q, want the upstream status so the operator can see /models is unsupported", out.Error)
	}
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatal("models response contains the key")
	}
}

func TestLLMConfigValidation(t *testing.T) {
	h, _, _ := newLLMServer(t)
	cases := map[string]map[string]any{
		"unknown provider":     {"provider": "chatgpt-oauth", "api_key": llmTestKey},
		"deepseek needs a key": {"provider": "deepseek"},
		"custom needs a base":  {"provider": "custom", "model": "m"},
		"bad base scheme":      {"provider": "custom", "model": "m", "base_url": "ftp://example.com/v1"},
		"credentials in base":  {"provider": "custom", "model": "m", "base_url": "https://user:pass@example.com/v1"},
	}
	for name, body := range cases {
		rec := llmRequest(t, h, "PUT", "/api/llm/config", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), llmTestKey) {
			t.Errorf("%s: validation error echoes the key: %s", name, rec.Body.String())
		}
	}
	// Unknown JSON fields are rejected rather than silently ignored.
	req := httptest.NewRequest(http.MethodPut, "/api/llm/config", strings.NewReader(`{"provider":"deepseek","api_key":"sk-x-0123456789","surprise":true}`))
	req.Header.Set(web.ClientHeader, "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: status %d, want 400", rec.Code)
	}
}

func TestLLMConfigNotConfiguredState(t *testing.T) {
	h, _, _ := newLLMServer(t)
	rec := llmRequest(t, h, "GET", "/api/llm/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	st := decodeLLMStatus(t, rec)
	if st.Configured || st.KeySet || st.Provider != "" || st.Model != "" || st.BaseURL != "" || st.KeyHint != "" {
		t.Fatalf("fresh status = %+v, want an explicit not-configured state", st)
	}
	if len(st.Providers) != 3 {
		t.Fatalf("providers = %+v", st.Providers)
	}
}

func TestLLMRoutesRequireTheSameBearerTokenAsOtherProtectedRoutes(t *testing.T) {
	h, _, _ := newLLMServerWithToken(t, testAPIToken)

	// The reference behaviour: an existing protected route.
	base := do(h, "GET", "/api/projects", nil)
	if base.Code != http.StatusUnauthorized {
		t.Fatalf("reference GET /api/projects = %d, want 401", base.Code)
	}
	getRoutes := []string{"/api/llm/config"}
	for _, path := range getRoutes {
		rec := do(h, "GET", path, nil)
		if rec.Code != base.Code || rec.Body.String() != base.Body.String() {
			t.Errorf("GET %s = %d %q, want the same rejection as /api/projects (%d %q)",
				path, rec.Code, rec.Body.String(), base.Code, base.Body.String())
		}
	}

	// Mutating routes: the CSRF guard still applies first, so present the
	// client header exactly as the real UI/CLI does. The token is missing.
	baseMut := do(h, "POST", "/api/projects", map[string]string{web.ClientHeader: "test"})
	if baseMut.Code != http.StatusUnauthorized {
		t.Fatalf("reference POST /api/projects = %d, want 401", baseMut.Code)
	}
	mutRoutes := []struct{ method, path string }{
		{"PUT", "/api/llm/config"},
		{"DELETE", "/api/llm/config"},
		{"POST", "/api/llm/test"},
		{"POST", "/api/llm/models"},
	}
	for _, rt := range mutRoutes {
		rec := do(h, rt.method, rt.path, map[string]string{web.ClientHeader: "test"})
		if rec.Code != baseMut.Code || rec.Body.String() != baseMut.Body.String() {
			t.Errorf("%s %s = %d %q, want the same rejection as POST /api/projects (%d %q)",
				rt.method, rt.path, rec.Code, rec.Body.String(), baseMut.Code, baseMut.Body.String())
		}
	}

	// The token alone is not enough for a mutating request: the CSRF header is
	// still required, exactly like every other mutating route.
	rec := do(h, "PUT", "/api/llm/config", map[string]string{"Authorization": "Bearer " + testAPIToken})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT without the client header = %d, want 403", rec.Code)
	}

	// With both, the routes work and still never return the key.
	rec = do(h, "GET", "/api/llm/config", map[string]string{"Authorization": "Bearer " + testAPIToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized GET = %d: %s", rec.Code, rec.Body.String())
	}
	body, _ := json.Marshal(map[string]any{"provider": "deepseek", "api_key": llmTestKey})
	req := httptest.NewRequest(http.MethodPut, "/api/llm/config", bytes.NewReader(body))
	req.Header.Set(web.ClientHeader, "test")
	req.Header.Set("Authorization", "Bearer "+testAPIToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), llmTestKey) {
		t.Fatal("authorized PUT response contains the key")
	}
}

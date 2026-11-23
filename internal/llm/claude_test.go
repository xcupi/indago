package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Claude must authenticate the way Anthropic expects: x-api-key plus a version
// header, never a Bearer token.
func TestClaudeModelsUsesAnthropicHeaders(t *testing.T) {
	var gotKey, gotVersion, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"id":"claude-sonnet-4-5"}]}`))
	}))
	defer srv.Close()

	st := NewStore(t.TempDir())
	if _, err := st.Set(SetRequest{Provider: ProviderClaude, Model: "claude-sonnet-4-5", APIKey: "k-123", BaseURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProber(0).Models(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if gotKey != "k-123" || gotVersion == "" {
		t.Fatalf("headers: x-api-key=%q anthropic-version=%q", gotKey, gotVersion)
	}
	if gotAuth != "" {
		t.Fatalf("Claude request must not send Authorization, got %q", gotAuth)
	}
}

func TestClaudeIsAListedProvider(t *testing.T) {
	def, ok := LookupProvider(ProviderClaude)
	if !ok {
		t.Fatal("claude is not a known provider")
	}
	if def.Label != "Claude (Anthropic API)" || !def.RequiresKey || def.DefaultBaseURL == "" {
		t.Fatalf("definition = %+v", def)
	}
}

func TestClaudeAPIKeyProbeUsesMessages(t *testing.T) {
	const model = "fixture-claude-model"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("x-api-key") != "fixture-api-key" || r.Header.Get("anthropic-version") == "" || r.Header.Get("Authorization") != "" {
			t.Error("invalid Anthropic API-key headers")
		}
		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Model != model || req.MaxTokens != 1 {
			t.Errorf("unexpected connection test request: %+v, %v", req, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"OK"}]}`))
	}))
	defer srv.Close()

	cfg := Config{Provider: ProviderClaude, Model: model, BaseURL: srv.URL + "/v1", apiKey: "fixture-api-key"}
	if result := NewProber(0).Test(context.Background(), cfg); !result.OK {
		t.Fatalf("Claude API key probe failed: %+v", result)
	}
}

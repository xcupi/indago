package llm

import (
	"context"
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
	if def.Label != "Claude (Anthropic)" || def.RequiresKey || def.DefaultBaseURL == "" {
		t.Fatalf("definition = %+v", def)
	}
}

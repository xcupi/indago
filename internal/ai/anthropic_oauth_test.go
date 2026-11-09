package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// A Claude subscription session must be sent as Bearer + beta headers, never as
// x-api-key.
func TestClaudeOAuthUsesBearerAndBeta(t *testing.T) {
	var auth, beta, app, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		beta = r.Header.Get("anthropic-beta")
		app = r.Header.Get("x-app")
		key = r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"model":   "claude-sonnet-4-5",
			"content": []map[string]any{{"type": "text", "text": "ok"}},
		})
	}))
	defer srv.Close()

	gw, err := New(Settings{Enabled: true, Provider: "claude", Model: "claude-sonnet-4-5", BaseURL: srv.URL, OAuthToken: "oat-123"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Advise(context.Background(), Request{Kind: domain.AITriage, Prompt: "hi"}); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer oat-123" || beta == "" || app != "cli" || key != "" {
		t.Fatalf("headers: auth=%q beta=%q app=%q key=%q", auth, beta, app, key)
	}
}

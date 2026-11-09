package ai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indago/indago/internal/ai"
)

// The Claude subscription route only answers when the request carries the
// Claude Code identity. A long third-party system prompt is classified as
// another client and rejected with 429, so the advisory framing must travel in
// the user message while the system field stays the identity line.
func TestClaudeOAuthRequestCarriesClaudeCodeIdentity(t *testing.T) {
	var gotSystem string
	var gotUser string
	var gotUA, gotBeta, gotApp string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotBeta = r.Header.Get("anthropic-beta")
		gotApp = r.Header.Get("x-app")
		b, _ := io.ReadAll(r.Body)
		var body struct {
			System   string `json:"system"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(b, &body)
		gotSystem = body.System
		if len(body.Messages) > 0 {
			gotUser = body.Messages[0].Content
		}
		_, _ = w.Write([]byte(`{"model":"claude-sonnet-5-5","stop_reason":"end_turn","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":11,"output_tokens":2}}`))
	}))
	defer srv.Close()

	p, err := ai.NewProvider(ai.Settings{
		Provider: ai.ProviderClaude, Model: "claude-sonnet-5-5",
		BaseURL: srv.URL, OAuthToken: "oauth-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), ai.Request{Prompt: "list checks"})
	if err != nil {
		t.Fatal(err)
	}
	if gotSystem != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Fatalf("system = %q", gotSystem)
	}
	if !strings.Contains(gotUser, "advisory assistant") || !strings.Contains(gotUser, "list checks") {
		t.Fatalf("user message lost the advisory framing: %q", gotUser)
	}
	if !strings.HasPrefix(gotUA, "claude-code/") || !strings.Contains(gotUA, "(external, cli)") {
		t.Fatalf("ua = %q", gotUA)
	}
	for _, beta := range []string{"oauth-2025-04-20", "claude-code-20250219", "interleaved-thinking-2025-05-14", "fine-grained-tool-streaming-2025-05-14"} {
		if !strings.Contains(gotBeta, beta) {
			t.Fatalf("beta %q missing from %q", beta, gotBeta)
		}
	}
	if gotApp != "cli" {
		t.Fatalf("x-app = %q", gotApp)
	}
	if resp.Usage.PromptTokens != 11 || resp.Usage.CompletionTokens != 2 || resp.Usage.TotalTokens != 13 {
		t.Fatalf("usage = %+v", resp.Usage)
	}
}

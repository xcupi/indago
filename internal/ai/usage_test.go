package ai_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/indago/indago/internal/ai"
)

// Providers report usage in their own shape; the gateway must carry it to the
// task record instead of estimating tokens locally.
func TestCompleteCarriesProviderUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"model":"m","usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150}}`))
	}))
	defer srv.Close()

	p, err := ai.NewProvider(ai.Settings{Provider: ai.ProviderOpenAI, BaseURL: srv.URL, Model: "m", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Complete(context.Background(), ai.Request{Prompt: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage.PromptTokens != 120 || resp.Usage.CompletionTokens != 30 || resp.Usage.TotalTokens != 150 {
		t.Fatalf("usage = %+v", resp.Usage)
	}
}

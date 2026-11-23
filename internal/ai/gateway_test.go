package ai_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/ai"
	"github.com/indago/indago/internal/domain"
)

func TestDefaultGatewayDisabled(t *testing.T) {
	g, err := ai.New(ai.Settings{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if g.Enabled() {
		t.Fatal("gateway should be disabled by default")
	}
	if _, err := g.Advise(context.Background(), ai.Request{Kind: domain.AITriage}); !errors.Is(err, ai.ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

// TestEnabledGatewayCallsRealOpenAICompatProvider runs a fake OpenAI-shaped
// HTTP server and confirms the gateway actually performs a real network
// call (not a stub) and stamps the result Advisory. Ollama/vLLM/OpenAI/
// OpenRouter all share this same provider implementation, so one such
// backend stands in for all four.
func TestEnabledGatewayCallsRealOpenAICompatProvider(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"llama3","choices":[{"message":{"role":"assistant","content":"looks fine, low risk"}}]}`))
	}))
	defer srv.Close()

	g, err := ai.New(ai.Settings{Enabled: true, Provider: ai.ProviderOpenAI, Model: "llama3", BaseURL: srv.URL, APIKey: "local-key"})
	if err != nil {
		t.Fatal(err)
	}
	if !g.Enabled() {
		t.Fatal("gateway should be enabled")
	}
	resp, err := g.Advise(context.Background(), ai.Request{Kind: domain.AIDraftReport, Prompt: "draft an executive summary", Context: map[string]any{"param": "q"}})
	if err != nil {
		t.Fatalf("advise: %v", err)
	}
	if !resp.Advisory {
		t.Fatal("response must be stamped Advisory=true — never authoritative")
	}
	if resp.Text != "looks fine, low risk" {
		t.Fatalf("unexpected text: %q", resp.Text)
	}
	if resp.Provider != ai.ProviderOpenAI {
		t.Fatalf("provider = %q, want %q", resp.Provider, ai.ProviderOpenAI)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path = %q, want /chat/completions", gotPath)
	}
	if gotAuth != "Bearer local-key" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotBody["max_completion_tokens"] != float64(8192) || gotBody["max_tokens"] != nil {
		t.Fatal("expected a bounded OpenAI API completion")
	}
	msgs, _ := gotBody["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected system+user messages, got %d", len(msgs))
	}
}

func TestEnabledGatewayDraftsReportWithOpenRouterAndGoogle(t *testing.T) {
	for _, provider := range []string{ai.ProviderOpenRouter, ai.ProviderGoogle} {
		t.Run(provider, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer fixture-key" {
					t.Error("expected the provider API key as a bearer token")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"choices":[{"message":{"content":"The assessment found no confirmed issues."}}],"usage":{"total_tokens":14}}`))
			}))
			defer srv.Close()
			gateway, err := ai.New(ai.Settings{Enabled: true, Provider: provider, Model: "fixture-model", BaseURL: srv.URL + "/v1", APIKey: "fixture-key"})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := gateway.Advise(context.Background(), ai.Request{Kind: domain.AIDraftReport, Prompt: "Summarize an assessment with no confirmed issues."})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Provider != provider || !resp.Advisory || resp.Text != "The assessment found no confirmed issues." || resp.Usage.TotalTokens != 14 {
				t.Fatalf("unexpected summary: %+v", resp)
			}
		})
	}
}

// TestEnabledGatewayCallsRealAnthropicProvider exercises the differently-
// shaped Anthropic Messages API path (x-api-key header, content blocks).
func TestEnabledGatewayCallsRealAnthropicProvider(t *testing.T) {
	var gotKey, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"claude-3-5-sonnet","content":[{"type":"text","text":"draft summary text"}]}`))
	}))
	defer srv.Close()

	g, err := ai.New(ai.Settings{Enabled: true, Provider: ai.ProviderAnthropic, Model: "claude-3-5-sonnet", BaseURL: srv.URL, APIKey: "sk-ant-test"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := g.Advise(context.Background(), ai.Request{Kind: domain.AIDraftReport, Prompt: "draft a summary"})
	if err != nil {
		t.Fatalf("advise: %v", err)
	}
	if resp.Text != "draft summary text" || !resp.Advisory {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotKey != "sk-ant-test" {
		t.Fatalf("x-api-key = %q", gotKey)
	}
	if gotVersion == "" {
		t.Fatal("anthropic-version header must be set")
	}
}

// TestHostedProvidersRequireAPIKey: OpenAI/Anthropic/OpenRouter must fail
// closed at construction time with no key, rather than fail confusingly on
// the first real call deep inside a scan.
func TestHostedProvidersRequireAPIKey(t *testing.T) {
	for _, p := range []string{ai.ProviderOpenAI, ai.ProviderAnthropic, ai.ProviderOpenRouter, ai.ProviderGoogle} {
		if _, err := ai.New(ai.Settings{Enabled: true, Provider: p, Model: "x"}); err == nil {
			t.Fatalf("provider %s: expected error with no API key", p)
		}
	}
}

// TestLocalProvidersDoNotRequireAPIKey: Ollama/vLLM are typically
// self-hosted with no auth in front of them; requiring a key would make
// the common local-dev case unconfigurable.
func TestLocalProvidersDoNotRequireAPIKey(t *testing.T) {
	for _, p := range []string{ai.ProviderOllama, ai.ProviderVLLM} {
		if _, err := ai.New(ai.Settings{Enabled: true, Provider: p, Model: "x"}); err != nil {
			t.Fatalf("provider %s: unexpected error with no API key: %v", p, err)
		}
	}
}

func TestUnknownProviderErrors(t *testing.T) {
	if _, err := ai.New(ai.Settings{Enabled: true, Provider: "skynet"}); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestReportOnlyProvidersDoNotCallNetworkForOtherTasks(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	for _, p := range []string{ai.ProviderOpenAI, ai.ProviderAnthropic, ai.ProviderClaude, ai.ProviderOpenRouter, ai.ProviderGoogle} {
		t.Run(p, func(t *testing.T) {
			gateway, err := ai.New(ai.Settings{Enabled: true, Provider: p, Model: "fixture-model", BaseURL: server.URL, APIKey: "fixture-key"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gateway.Advise(context.Background(), ai.Request{Kind: domain.AITriage}); err == nil {
				t.Fatal("expected the gateway to reject this task")
			}
		})
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("expected no outgoing requests, got %d", got)
	}
}

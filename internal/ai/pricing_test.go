package ai

import (
	"math"
	"testing"
)

func TestEstimateCostRequiresTokenBreakdown(t *testing.T) {
	for _, usage := range []Usage{
		{},
		{TotalTokens: 100},
		{TotalTokens: 100, PromptTokens: 20, CompletionTokens: 30},
		{PromptTokens: -1, CompletionTokens: 3},
	} {
		if got := EstimateCost("openai", "gpt-4o-mini", usage); got.CostKnown {
			t.Errorf("usage %+v was reported as a known cost", usage)
		}
	}
}

func TestEstimateCostKnownModels(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		usage    Usage
		wantUSD  float64
	}{
		{
			name:     "openai gpt-4o-mini",
			provider: ProviderOpenAI,
			model:    "gpt-4o-mini",
			usage:    Usage{PromptTokens: 1_000_000, CompletionTokens: 1_000_000, TotalTokens: 2_000_000},
			wantUSD:  0.75,
		},
		{
			name:     "openai gpt-4o-mini dated suffix prefers mini over gpt-4o",
			provider: ProviderOpenAI,
			model:    "gpt-4o-mini-2024-07-18",
			usage:    Usage{PromptTokens: 120, CompletionTokens: 30, TotalTokens: 150},
			wantUSD:  0.000036,
		},
		{
			name:     "anthropic claude-sonnet-4-5 dated",
			provider: ProviderClaude,
			model:    "claude-sonnet-4-5-20250929",
			usage:    Usage{PromptTokens: 500_000, CompletionTokens: 100_000, TotalTokens: 600_000},
			wantUSD:  3.00,
		},
		{
			name:     "deepseek-chat",
			provider: ProviderDeepSeek,
			model:    "deepseek-chat",
			usage:    Usage{PromptTokens: 1_000_000, CompletionTokens: 500_000, TotalTokens: 1_500_000},
			wantUSD:  0.82,
		},
		{
			name:     "openrouter namespaced model",
			provider: ProviderOpenRouter,
			model:    "OpenAI/GPT-4o",
			usage:    Usage{PromptTokens: 100_000, CompletionTokens: 50_000, TotalTokens: 150_000},
			wantUSD:  0.75,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EstimateCost(tc.provider, tc.model, tc.usage)
			if !got.CostKnown {
				t.Fatalf("CostKnown = false, want true")
			}
			if math.Abs(got.EstimatedCostUSD-tc.wantUSD) > 1e-9 {
				t.Fatalf("EstimatedCostUSD = %.10f, want %.10f", got.EstimatedCostUSD, tc.wantUSD)
			}
		})
	}
}

func TestEstimateCostUnknownAndLocalModels(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		usage    Usage
	}{
		{
			name:     "ollama local model",
			provider: ProviderOllama,
			model:    "llama3.2:latest",
			usage:    Usage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
		{
			name:     "vllm local model even with known name",
			provider: ProviderVLLM,
			model:    "gpt-4o",
			usage:    Usage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
		{
			name:     "unmapped custom model",
			provider: ProviderCustom,
			model:    "my-fine-tuned-model",
			usage:    Usage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
		{
			name:     "empty model",
			provider: ProviderOpenAI,
			model:    "",
			usage:    Usage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EstimateCost(tc.provider, tc.model, tc.usage)
			if got.CostKnown {
				t.Fatalf("CostKnown = true, want false")
			}
			if got.EstimatedCostUSD != 0 {
				t.Fatalf("EstimatedCostUSD = %v, want 0", got.EstimatedCostUSD)
			}
		})
	}
}

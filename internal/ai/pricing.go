package ai

import (
	"math"
	"sort"
	"strings"
)

// ModelPrice defines the USD cost per 1,000,000 tokens for a model.
type ModelPrice struct {
	InputPer1M  float64
	OutputPer1M float64
}

// CostEstimate holds the estimated USD cost for a single advisory call.
// CostKnown is false for local providers (ollama, vllm) and unmapped models.
type CostEstimate struct {
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`
	CostKnown        bool    `json:"cost_known"`
}

// modelPrices maps canonical model names (lowercase) to USD per 1M tokens.
var modelPrices = map[string]ModelPrice{
	// OpenAI
	"gpt-4o":      {InputPer1M: 2.50, OutputPer1M: 10.00},
	"gpt-4o-mini": {InputPer1M: 0.15, OutputPer1M: 0.60},
	"gpt-4.1":     {InputPer1M: 2.00, OutputPer1M: 8.00},
	"gpt-4.1-mini": {
		InputPer1M: 0.40, OutputPer1M: 1.60,
	},
	"gpt-4.1-nano": {
		InputPer1M: 0.10, OutputPer1M: 0.40,
	},
	"gpt-4-turbo": {InputPer1M: 10.00, OutputPer1M: 30.00},
	"o1":          {InputPer1M: 15.00, OutputPer1M: 60.00},
	"o1-mini":     {InputPer1M: 1.10, OutputPer1M: 4.40},
	"o3":          {InputPer1M: 2.00, OutputPer1M: 8.00},
	"o3-mini":     {InputPer1M: 1.10, OutputPer1M: 4.40},
	"o4-mini":     {InputPer1M: 1.10, OutputPer1M: 4.40},
	"gpt-5":       {InputPer1M: 1.25, OutputPer1M: 10.00},
	"gpt-5-mini":  {InputPer1M: 0.25, OutputPer1M: 2.00},
	"gpt-5-nano":  {InputPer1M: 0.05, OutputPer1M: 0.40},

	// Anthropic / Claude
	"claude-opus-4-5":   {InputPer1M: 5.00, OutputPer1M: 25.00},
	"claude-opus-4-1":   {InputPer1M: 15.00, OutputPer1M: 75.00},
	"claude-opus-4":     {InputPer1M: 15.00, OutputPer1M: 75.00},
	"claude-sonnet-4-5": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-sonnet-4":   {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-haiku-4-5":  {InputPer1M: 1.00, OutputPer1M: 5.00},
	"claude-3-7-sonnet": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-3-5-sonnet": {InputPer1M: 3.00, OutputPer1M: 15.00},
	"claude-3-5-haiku":  {InputPer1M: 0.80, OutputPer1M: 4.00},
	"claude-3-opus":     {InputPer1M: 15.00, OutputPer1M: 75.00},
	"claude-3-haiku":    {InputPer1M: 0.25, OutputPer1M: 1.25},

	// DeepSeek
	"deepseek-chat":     {InputPer1M: 0.27, OutputPer1M: 1.10},
	"deepseek-reasoner": {InputPer1M: 0.55, OutputPer1M: 2.19},

	// Google Gemini
	"gemini-2.5-pro":   {InputPer1M: 1.25, OutputPer1M: 10.00},
	"gemini-2.5-flash": {InputPer1M: 0.15, OutputPer1M: 0.60},
	"gemini-2.0-flash": {InputPer1M: 0.10, OutputPer1M: 0.40},
}

// sortedModelPrefixes is ordered longest-first so dated variants like
// "gpt-4o-mini-2024-07-18" match "gpt-4o-mini" before "gpt-4o".
var sortedModelPrefixes = func() []string {
	keys := make([]string, 0, len(modelPrices))
	for k := range modelPrices {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	return keys
}()

// LookupPrice returns the per-1M-token USD pricing for (provider, model).
// Local providers (ollama, vllm) and unmapped models return (ModelPrice{}, false).
func LookupPrice(provider, model string) (ModelPrice, bool) {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == ProviderOllama || p == ProviderVLLM {
		return ModelPrice{}, false
	}
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ModelPrice{}, false
	}
	if price, ok := lookupModelName(m); ok {
		return price, true
	}
	// Strip provider namespace (e.g. OpenRouter's "openai/gpt-4o-mini").
	if idx := strings.LastIndex(m, "/"); idx >= 0 && idx+1 < len(m) {
		if price, ok := lookupModelName(m[idx+1:]); ok {
			return price, true
		}
	}
	return ModelPrice{}, false
}

func lookupModelName(m string) (ModelPrice, bool) {
	if price, ok := modelPrices[m]; ok {
		return price, true
	}
	for _, prefix := range sortedModelPrefixes {
		if strings.HasPrefix(m, prefix+"-") || strings.HasPrefix(m, prefix+":") {
			return modelPrices[prefix], true
		}
	}
	return ModelPrice{}, false
}

// EstimateCost computes the estimated USD cost for a single call's token usage.
// Pricing requires a known model and an input/output token breakdown.
func EstimateCost(provider, model string, usage Usage) CostEstimate {
	prompt, completion := usage.PromptTokens, usage.CompletionTokens
	if prompt < 0 || completion < 0 || (prompt == 0 && completion == 0) ||
		(usage.TotalTokens > 0 && usage.TotalTokens != prompt+completion) {
		return CostEstimate{}
	}
	price, ok := LookupPrice(provider, model)
	if !ok {
		return CostEstimate{}
	}
	cost := (float64(prompt)*price.InputPer1M + float64(completion)*price.OutputPer1M) / 1_000_000
	return CostEstimate{
		EstimatedCostUSD: RoundUSD(cost),
		CostKnown:        true,
	}
}

// RoundUSD rounds a USD amount to 8 decimal places to avoid float64 noise.
func RoundUSD(v float64) float64 {
	return math.Round(v*1e8) / 1e8
}

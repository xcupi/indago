package ai

import (
	"context"
	"fmt"
	"strings"
)

// anthropicDefaultVersion is the Anthropic Messages API version header this
// client speaks. Anthropic versions the API via a required header, not the
// URL path, and breaks requests that omit or send an unrecognized one.
const anthropicDefaultVersion = "2023-06-01"

// anthropicDefaultMaxTokens bounds a single advisory completion. Anthropic's
// Messages API requires max_tokens on every request (unlike OpenAI, where
// it is optional); this default suits report-drafting-length prose.
const anthropicDefaultMaxTokens = 16384

type anthropicProvider struct {
	baseURL string
	apiKey  string
	model   string
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *anthropicProvider) Name() string { return ProviderAnthropic }

func (p *anthropicProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if p.model == "" {
		return nil, fmt.Errorf("ai: %s: no model configured", ProviderAnthropic)
	}
	if p.apiKey == "" {
		return nil, fmt.Errorf("ai: %s: no API key configured", ProviderAnthropic)
	}
	headers := map[string]string{"anthropic-version": anthropicDefaultVersion, "x-api-key": p.apiKey}
	body := anthropicRequest{
		Model:     p.model,
		MaxTokens: anthropicDefaultMaxTokens,
		System:    systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userContent(req)},
		},
	}
	var out anthropicResponse
	url := strings.TrimRight(p.baseURL, "/") + "/messages"
	if err := postJSON(ctx, url, headers, body, &out); err != nil {
		return nil, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return nil, fmt.Errorf("ai: %s: %s", ProviderAnthropic, out.Error.Message)
	}
	if out.StopReason == "refusal" {
		// A subscription model may decline security-testing advice. That is a
		// policy answer, not an empty completion, and the UI should say so.
		return nil, fmt.Errorf("ai: %s refused the request (provider safety policy)", ProviderAnthropic)
	}
	var text strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		types := make([]string, 0, len(out.Content))
		for _, block := range out.Content {
			types = append(types, block.Type)
		}
		return nil, fmt.Errorf("ai: %s: empty response (stop_reason=%s, blocks=%v)", ProviderAnthropic, out.StopReason, types)
	}
	model := out.Model
	if model == "" {
		model = p.model
	}
	return &Response{
		Text: text.String(), Model: model,
		Usage: Usage{
			PromptTokens:     out.Usage.InputTokens,
			CompletionTokens: out.Usage.OutputTokens,
			TotalTokens:      out.Usage.InputTokens + out.Usage.OutputTokens,
		},
	}, nil
}

var _ Provider = (*anthropicProvider)(nil)

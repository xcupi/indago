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
const anthropicDefaultMaxTokens = 1024

// anthropicProvider talks to Anthropic's own Messages API
// (POST {baseURL}/messages), which is shaped differently from the OpenAI
// Chat Completions API: auth via x-api-key (not Authorization: Bearer), a
// required anthropic-version header, a top-level system field instead of a
// system-role message, and a content BLOCK list in the response rather than
// a single string.
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
	Model string `json:"model"`
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
	headers := map[string]string{
		"x-api-key":         p.apiKey,
		"anthropic-version": anthropicDefaultVersion,
	}
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
	var text strings.Builder
	for _, block := range out.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		return nil, fmt.Errorf("ai: %s: empty response (no text content)", ProviderAnthropic)
	}
	model := out.Model
	if model == "" {
		model = p.model
	}
	return &Response{Text: text.String(), Model: model}, nil
}

var _ Provider = (*anthropicProvider)(nil)

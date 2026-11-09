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

// anthropicProvider talks to Anthropic's own Messages API
// (POST {baseURL}/messages), which is shaped differently from the OpenAI
// Chat Completions API: auth via x-api-key (not Authorization: Bearer), a
// required anthropic-version header, a top-level system field instead of a
// system-role message, and a content BLOCK list in the response rather than
// a single string.
// claudeOAuthBeta mirrors the beta flags Claude Code sends with an OAuth
// token. All four are required: a bare Bearer with only the OAuth betas is
// answered with HTTP 429 rate_limit_error "Error".
const claudeOAuthBeta = "interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,claude-code-20250219,oauth-2025-04-20"

// claudeOAuthUserAgent identifies the request as Claude Code. Anthropic
// rejects OAuth inference whose UA is not `claude-code/<version> (external,
// cli)`; the version must stay close to the current release.
const claudeOAuthUserAgent = "claude-code/2.1.74 (external, cli)"

// claudeOAuthSystemPrefix is part of the client identity, not a prompt
// preference: OAuth requests without it are routed to the metered lane and
// rejected with 429.
const claudeOAuthSystemPrefix = "You are Claude Code, Anthropic's official CLI for Claude."

type anthropicProvider struct {
	baseURL string
	apiKey  string
	oauth   string
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
	if p.apiKey == "" && p.oauth == "" {
		return nil, fmt.Errorf("ai: %s: no API key or OAuth session configured", ProviderAnthropic)
	}
	headers := map[string]string{"anthropic-version": anthropicDefaultVersion}
	if p.oauth != "" {
		// Claude subscription tokens are Bearer tokens that also require the
		// OAuth beta flags; sending x-api-key instead is rejected.
		headers["Authorization"] = "Bearer " + p.oauth
		headers["anthropic-beta"] = claudeOAuthBeta
		headers["x-app"] = "cli"
		headers["User-Agent"] = claudeOAuthUserAgent
	} else {
		headers["x-api-key"] = p.apiKey
	}
	// OAuth requires the Claude Code identity as the WHOLE system prompt: a
	// long third-party system message is classified as another client and
	// answered with 429. The advisory framing therefore travels in the user
	// message on this route.
	system := systemPrompt
	user := userContent(req)
	if p.oauth != "" {
		system = claudeOAuthSystemPrefix
		user = systemPrompt + "\n\n" + user
	}
	body := anthropicRequest{
		Model:     p.model,
		MaxTokens: anthropicDefaultMaxTokens,
		System:    system,
		Messages: []anthropicMessage{
			{Role: "user", Content: user},
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

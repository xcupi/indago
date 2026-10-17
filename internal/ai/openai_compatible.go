package ai

import (
	"context"
	"fmt"
	"strings"
)

// openAICompatProvider talks to any backend that speaks the OpenAI Chat
// Completions API shape: POST {baseURL}/chat/completions with
// {model, messages:[{role,content},...]}, response .choices[0].message.content.
// That covers four of the five recognized providers — OpenAI itself,
// OpenRouter (an OpenAI-compatible router over many model vendors), and the
// two local/self-hosted runtimes Ollama and vLLM, which both deliberately
// implement this same API for drop-in compatibility with OpenAI clients.
// Anthropic is the one odd one out (its own Messages API, see anthropic.go).
type openAICompatProvider struct {
	name    string
	baseURL string
	apiKey  string
	model   string
}

type openAIChatRequest struct {
	Model    string              `json:"model"`
	Messages []openAIChatMessage `json:"messages"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message openAIChatMessage `json:"message"`
	} `json:"choices"`
	Model string `json:"model"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *openAICompatProvider) Name() string { return p.name }

func (p *openAICompatProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if p.model == "" {
		return nil, fmt.Errorf("ai: %s: no model configured", p.name)
	}
	headers := map[string]string{}
	if p.apiKey != "" {
		headers["Authorization"] = "Bearer " + p.apiKey
	}
	// OpenRouter asks integrators to identify their app via these headers;
	// harmless no-ops for the other backends.
	if p.name == ProviderOpenRouter {
		headers["HTTP-Referer"] = "https://github.com/indago/indago"
		headers["X-Title"] = "Indago"
	}
	body := openAIChatRequest{
		Model: p.model,
		Messages: []openAIChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userContent(req)},
		},
	}
	var out openAIChatResponse
	url := strings.TrimRight(p.baseURL, "/") + "/chat/completions"
	if err := postJSON(ctx, url, headers, body, &out); err != nil {
		return nil, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return nil, fmt.Errorf("ai: %s: %s", p.name, out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("ai: %s: empty response (no choices)", p.name)
	}
	model := out.Model
	if model == "" {
		model = p.model
	}
	return &Response{Text: out.Choices[0].Message.Content, Model: model}, nil
}

var _ Provider = (*openAICompatProvider)(nil)

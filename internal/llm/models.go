package llm

import (
	"encoding/json"
	"slices"
	"strings"
)

type modelModalities struct {
	Input  []string `json:"input_modalities"`
	Output []string `json:"output_modalities"`
}

type catalogModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	modelModalities
	Architecture json.RawMessage `json:"architecture"`
	Endpoints    json.RawMessage `json:"endpoints"`
}

func (m catalogModel) acceptsText(provider, id string) bool {
	isText := func(value string) bool { return strings.EqualFold(value, "text") }
	// Gateways can omit this metadata or expose it in a provider-specific shape.
	var architecture modelModalities
	_ = json.Unmarshal(m.Architecture, &architecture)
	for _, modality := range [][]string{m.Input, m.Output, architecture.Input, architecture.Output} {
		if len(modality) > 0 && !slices.ContainsFunc(modality, isText) {
			return false
		}
	}
	if provider == ProviderOpenRouter {
		var endpoints []string
		if err := json.Unmarshal(m.Endpoints, &endpoints); err == nil && len(endpoints) > 0 {
			return slices.ContainsFunc(endpoints, func(endpoint string) bool {
				return strings.HasSuffix(strings.TrimRight(endpoint, "/"), "/chat/completions")
			})
		}
	}

	// Some compatible catalog APIs expose IDs without capability information.
	// Keep unknown IDs and hide well-known specialized families on those APIs.
	id = strings.TrimPrefix(strings.ToLower(id), "models/")
	parts := strings.Split(id, "-")
	switch provider {
	case ProviderGoogle:
		switch parts[0] {
		case "aqa", "imagen", "veo", "lyria", "genie":
			return false
		case "gemini":
			return !slices.ContainsFunc(parts, func(part string) bool {
				switch part {
				case "embedding", "image", "banana", "live", "tts", "transcribe", "omni":
					return true
				}
				return false
			})
		}
	case ProviderOpenAI:
		switch parts[0] {
		case "whisper", "tts", "dall", "sora", "babbage", "davinci":
			return false
		case "gpt", "chatgpt", "text", "omni":
			return !slices.ContainsFunc(parts, func(part string) bool {
				switch part {
				case "embedding", "image", "moderation", "realtime", "tts", "transcribe":
					return true
				}
				return false
			})
		}
	}
	return true
}

package ai_test

import (
	"context"
	"errors"
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

func TestEnabledGatewayUsesStubProvider(t *testing.T) {
	g, err := ai.New(ai.Settings{Enabled: true, Provider: ai.ProviderOllama, Model: "llama3"})
	if err != nil {
		t.Fatal(err)
	}
	if !g.Enabled() {
		t.Fatal("gateway should be enabled")
	}
	// Provider is a stub in Phase 0.
	if _, err := g.Advise(context.Background(), ai.Request{Kind: domain.AISuggestPayloads}); !errors.Is(err, ai.ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented from stub provider, got %v", err)
	}
}

func TestUnknownProviderErrors(t *testing.T) {
	if _, err := ai.New(ai.Settings{Enabled: true, Provider: "skynet"}); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

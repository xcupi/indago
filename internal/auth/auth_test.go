package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/domain"
)

func TestAnonymousEstablishesActiveSession(t *testing.T) {
	a, err := auth.For(domain.AuthAnonymous)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID()})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if s.State != domain.SessionActive || s.Mode != domain.AuthAnonymous {
		t.Fatalf("unexpected session: state=%s mode=%s", s.State, s.Mode)
	}
	ok, err := a.Validate(context.Background(), s)
	if err != nil || !ok {
		t.Fatalf("anonymous session should validate: ok=%v err=%v", ok, err)
	}
}

func TestUnimplementedModesAreStubs(t *testing.T) {
	for _, m := range []domain.AuthMode{domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA, domain.AuthExisting} {
		a, err := auth.For(m)
		if err != nil {
			t.Fatalf("For(%s): %v", m, err)
		}
		if _, err := a.Establish(context.Background(), auth.Input{}); !errors.Is(err, auth.ErrNotImplemented) {
			t.Errorf("mode %s: expected ErrNotImplemented, got %v", m, err)
		}
	}
}

func TestUnknownModeErrors(t *testing.T) {
	if _, err := auth.For(domain.AuthMode("bogus")); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

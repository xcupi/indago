package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	for _, m := range []domain.AuthMode{domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA} {
		a, err := auth.For(m)
		if err != nil {
			t.Fatalf("For(%s): %v", m, err)
		}
		if _, err := a.Establish(context.Background(), auth.Input{}); !errors.Is(err, auth.ErrNotImplemented) {
			t.Errorf("mode %s: expected ErrNotImplemented, got %v", m, err)
		}
	}
}

func TestExistingImportsSessionMaterial(t *testing.T) {
	a, err := auth.For(domain.AuthExisting)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: path})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if s.State != domain.SessionActive || s.Mode != domain.AuthExisting || s.StatePath != path {
		t.Fatalf("unexpected session: %+v", s)
	}
	if ok, err := a.Validate(context.Background(), s); err != nil || !ok {
		t.Fatalf("existing session with its file present should validate: ok=%v err=%v", ok, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ok, err := a.Validate(context.Background(), s); err != nil || ok {
		t.Fatalf("existing session whose file is gone should not validate: ok=%v err=%v", ok, err)
	}
}

func TestExistingRequiresAStatePath(t *testing.T) {
	a, _ := auth.For(domain.AuthExisting)
	if _, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID()}); err == nil {
		t.Fatal("expected an error when no state path is given")
	}
	if _, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: "/nonexistent/state.json"}); err == nil {
		t.Fatal("expected an error when the state path does not exist")
	}
}

func TestUnknownModeErrors(t *testing.T) {
	if _, err := auth.For(domain.AuthMode("bogus")); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

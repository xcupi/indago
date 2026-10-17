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

func TestCapturedSessionModesEstablishLikeExisting(t *testing.T) {
	// Password/Interactive/MFA's Establish is identical to Existing's: by
	// the time it runs, Controller.resolveAuth has already driven the real
	// login once, at scan-CREATE time, and StatePath already points at the
	// captured material. Establish here only ever validates+imports it,
	// the same way Existing does — it must NEVER repeat the login itself.
	for _, m := range []domain.AuthMode{domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA} {
		a, err := auth.For(m)
		if err != nil {
			t.Fatalf("For(%s): %v", m, err)
		}
		if a.Mode() != m {
			t.Fatalf("For(%s).Mode() = %s, want %s", m, a.Mode(), m)
		}
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: path})
		if err != nil {
			t.Fatalf("mode %s: establish: %v", m, err)
		}
		if s.State != domain.SessionActive || s.Mode != m || s.StatePath != path {
			t.Fatalf("mode %s: unexpected session: %+v", m, s)
		}
		if ok, err := a.Validate(context.Background(), s); err != nil || !ok {
			t.Fatalf("mode %s: session with its file present should validate: ok=%v err=%v", m, ok, err)
		}
		// Without a real, already-captured state path, Establish must fail
		// closed (ValidateStateFile rejects ""), never silently succeed as
		// if it were about to drive a fresh login itself.
		if _, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID()}); !errors.Is(err, auth.ErrInvalidState) {
			t.Errorf("mode %s: establish with no state path = %v, want ErrInvalidState", m, err)
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

func TestValidateStateFileRejectsUnusableMaterial(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"empty path":         "",
		"relative path":      "state.json",
		"missing file":       filepath.Join(dir, "nope.json"),
		"directory":          dir,
		"not JSON":           write("notjson.json", "cookie=abc"),
		"JSON, wrong shape":  write("other.json", `{"hello":"world"}`),
		"JSON array":         write("array.json", `[1,2,3]`),
		"cookies wrong type": write("badcookies.json", `{"cookies":"abc"}`),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if err := auth.ValidateStateFile(path); !errors.Is(err, auth.ErrInvalidState) {
				t.Fatalf("ValidateStateFile(%q) = %v, want ErrInvalidState", path, err)
			}
		})
	}
	for _, ok := range []string{
		write("full.json", `{"cookies":[{"name":"sid","value":"1","domain":"example.com"}],"origins":[]}`),
		write("cookies-only.json", `{"cookies":[]}`),
		write("origins-only.json", `{"origins":[]}`),
	} {
		if err := auth.ValidateStateFile(ok); err != nil {
			t.Fatalf("ValidateStateFile(%s) = %v, want nil", ok, err)
		}
	}
}

func TestImplementedModes(t *testing.T) {
	for m, want := range map[domain.AuthMode]bool{
		domain.AuthAnonymous: true, domain.AuthExisting: true,
		domain.AuthPassword: true, domain.AuthInteractive: true, domain.AuthMFA: true,
	} {
		if got := auth.Implemented(m); got != want {
			t.Errorf("Implemented(%s) = %v, want %v", m, got, want)
		}
	}
	if auth.Implemented(domain.AuthMode("bogus")) {
		t.Error("Implemented(bogus) = true, want false (an unknown mode must fail closed)")
	}
}

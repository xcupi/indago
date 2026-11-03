package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// writeStateFile writes body to a fresh state.json under dir and returns it.
func writeStateFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// expiredState has two dummy persistent cookies whose expiries (1970, 1970+1s)
// are unambiguously in the past for any real clock.
const expiredState = `{"cookies":[` +
	`{"name":"dummy_a","value":"v1","domain":"example.test","path":"/","expires":1},` +
	`{"name":"dummy_b","value":"v2","domain":"example.test","path":"/","expires":2}` +
	`],"origins":[]}`

// futureState has one dummy persistent cookie expiring in 2100.
const futureState = `{"cookies":[` +
	`{"name":"dummy_a","value":"v1","domain":"example.test","path":"/","expires":4102444800}` +
	`],"origins":[]}`

func TestValidateStateFileRejectsAllExpiredCookies(t *testing.T) {
	dir := t.TempDir()
	err := auth.ValidateStateFile(writeStateFile(t, dir, "expired.json", expiredState))
	if !errors.Is(err, auth.ErrInvalidState) {
		t.Fatalf("ValidateStateFile(all expired) = %v, want ErrInvalidState", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error does not say the cookies are expired: %v", err)
	}
	// The error must never echo cookie names or values (only dummy ones are
	// used here, but the contract is the same for real material).
	for _, leaked := range []string{"dummy_a", "dummy_b", "v1", "v2"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error leaks cookie material %q: %v", leaked, err)
		}
	}
}

// The documented limitation: Indago cannot tell which cookie is the auth
// cookie, so material with ANY still-live cookie is never reported expired.
func TestValidateStateFileAcceptsMaterialWithALiveCookie(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"one future cookie among expired": `{"cookies":[` +
			`{"name":"dummy_a","value":"v1","domain":"example.test","path":"/","expires":1},` +
			`{"name":"dummy_b","value":"v2","domain":"example.test","path":"/","expires":4102444800}` +
			`],"origins":[]}`,
		"session cookie among expired": `{"cookies":[` +
			`{"name":"dummy_a","value":"v1","domain":"example.test","path":"/","expires":1},` +
			`{"name":"dummy_b","value":"v2","domain":"example.test","path":"/","expires":-1}` +
			`],"origins":[]}`,
		"origins only": `{"cookies":[],"origins":[{"origin":"https://example.test","localStorage":[]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := auth.ValidateStateFile(writeStateFile(t, dir, "state.json", body)); err != nil {
				t.Fatalf("ValidateStateFile = %v, want nil", err)
			}
		})
	}
}

// A saved session whose cookies have all expired is reported inactive (not an
// error), so the controller moves the scan to AwaitingAuth instead of quietly
// testing the target unauthenticated. Applies to AuthExisting and to every
// mode whose session was captured by a real login.
func TestValidateRejectsExpiredAndUnreadableMaterial(t *testing.T) {
	for _, m := range []domain.AuthMode{domain.AuthExisting, domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA} {
		t.Run(string(m), func(t *testing.T) {
			a, err := auth.For(m)
			if err != nil {
				t.Fatal(err)
			}
			path := writeStateFile(t, t.TempDir(), "state.json", futureState)
			s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: path})
			if err != nil {
				t.Fatalf("establish: %v", err)
			}
			if ok, err := a.Validate(context.Background(), s); err != nil || !ok {
				t.Fatalf("live material should validate: ok=%v err=%v", ok, err)
			}

			// Same path, now holding only expired cookies.
			if err := os.WriteFile(path, []byte(expiredState), 0o600); err != nil {
				t.Fatal(err)
			}
			if ok, err := a.Validate(context.Background(), s); err != nil || ok {
				t.Fatalf("expired material should not validate: ok=%v err=%v", ok, err)
			}

			// A corrupt file is not usable either — and never validates.
			if err := os.WriteFile(path, []byte("not a storage state"), 0o600); err != nil {
				t.Fatal(err)
			}
			if ok, err := a.Validate(context.Background(), s); err != nil || ok {
				t.Fatalf("corrupt material should not validate: ok=%v err=%v", ok, err)
			}

			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if ok, err := a.Validate(context.Background(), s); err != nil || ok {
				t.Fatalf("missing material should not validate: ok=%v err=%v", ok, err)
			}
		})
	}
}

// Establish surfaces the latest persistent-cookie expiry on the Session so the
// controller's own time check and the API can report it; a session cookie (or
// no cookies at all) leaves it nil because no time-based expiry is knowable.
func TestEstablishSetsExpiresAtFromPersistentCookies(t *testing.T) {
	dir := t.TempDir()
	a, err := auth.For(domain.AuthExisting)
	if err != nil {
		t.Fatal(err)
	}
	both := writeStateFile(t, dir, "both.json", `{"cookies":[`+
		`{"name":"dummy_a","value":"v1","expires":4102444800},`+
		`{"name":"dummy_b","value":"v2","expires":4102444801}`+
		`],"origins":[]}`)
	s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: both})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if s.ExpiresAt == nil || s.ExpiresAt.Unix() != 4102444801 {
		t.Fatalf("ExpiresAt = %v, want the latest cookie expiry (4102444801)", s.ExpiresAt)
	}

	withSession := writeStateFile(t, dir, "session.json", `{"cookies":[`+
		`{"name":"dummy_a","value":"v1","expires":4102444800},`+
		`{"name":"dummy_b","value":"v2","expires":-1}`+
		`],"origins":[]}`)
	s, err = a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: withSession})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if s.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil when a session cookie is present", s.ExpiresAt)
	}

	originsOnly := writeStateFile(t, dir, "origins.json", `{"cookies":[],"origins":[{"origin":"https://example.test","localStorage":[]}]}`)
	s, err = a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: originsOnly})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if s.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil for an origins-only state", s.ExpiresAt)
	}

	// The captured modes share the same Establish path.
	captured, err := auth.For(domain.AuthPassword)
	if err != nil {
		t.Fatal(err)
	}
	s, err = captured.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: both})
	if err != nil {
		t.Fatalf("captured establish: %v", err)
	}
	if s.ExpiresAt == nil || s.ExpiresAt.Unix() != 4102444801 {
		t.Fatalf("captured ExpiresAt = %v, want 4102444801", s.ExpiresAt)
	}
}

// expiredStateWithOrigins returns an all-expired-cookie state whose origins
// array is the given raw JSON.
func expiredStateWithOrigins(origins string) string {
	return `{"cookies":[` +
		`{"name":"dummy_a","value":"v1","domain":"example.test","path":"/","expires":1},` +
		`{"name":"dummy_b","value":"v2","domain":"example.test","path":"/","expires":2}` +
		`],"origins":` + origins + `}`
}

// An SPA often keeps its real session in localStorage/indexedDB while its
// cookies are stale analytics leftovers. That material is "cannot tell", never
// "expired": it must pass creation, validate, and stay off the time-based
// expiry path.
func TestAllExpiredCookiesWithOriginStorageAreNotExpired(t *testing.T) {
	dir := t.TempDir()
	for name, origins := range map[string]string{
		"localStorage": `[{"origin":"https://example.test","localStorage":[{"name":"dummy","value":"dummy"}]}]`,
		"indexedDB":    `[{"origin":"https://example.test","indexedDB":[{"name":"dummy","version":1,"stores":[]}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeStateFile(t, dir, name+".json", expiredStateWithOrigins(origins))
			if err := auth.ValidateStateFile(path); err != nil {
				t.Fatalf("ValidateStateFile = %v, want nil (origin storage is material we cannot date)", err)
			}
			a, err := auth.For(domain.AuthExisting)
			if err != nil {
				t.Fatal(err)
			}
			s, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: path})
			if err != nil {
				t.Fatalf("establish: %v", err)
			}
			if s.ExpiresAt != nil {
				t.Fatalf("ExpiresAt = %v, want nil: the cookie expiry does not describe origin storage", s.ExpiresAt)
			}
			if ok, err := a.Validate(context.Background(), s); err != nil || !ok {
				t.Fatalf("session with live origin material should validate: ok=%v err=%v", ok, err)
			}
		})
	}
}

// Origin entries with no storage, or entries that cannot be parsed, prove
// nothing about live material: an all-expired-cookie state is still expired.
func TestAllExpiredCookiesWithoutOriginStorageStillExpire(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ name, origins string }{
		{"empty arrays", `[{"origin":"https://example.test","localStorage":[],"indexedDB":[]}]`},
		{"no storage keys", `[{"origin":"https://example.test"}]`},
		{"null entry", `[null]`},
		{"malformed entries", `["not-an-object",{"localStorage":"not-an-array"}]`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeStateFile(t, dir, fmt.Sprintf("state-%d.json", i), expiredStateWithOrigins(tc.origins))
			err := auth.ValidateStateFile(path)
			if !errors.Is(err, auth.ErrInvalidState) || !strings.Contains(err.Error(), "expired") {
				t.Fatalf("ValidateStateFile = %v, want an ErrInvalidState that says the cookies are expired", err)
			}
			a, err := auth.For(domain.AuthExisting)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.Establish(context.Background(), auth.Input{ScanID: domain.NewID(), StatePath: path}); !errors.Is(err, auth.ErrInvalidState) {
				t.Fatalf("establish = %v, want ErrInvalidState", err)
			}
			if ok, err := a.Validate(context.Background(), &domain.Session{StatePath: path}); err != nil || ok {
				t.Fatalf("expired material should not validate: ok=%v err=%v", ok, err)
			}
		})
	}
}

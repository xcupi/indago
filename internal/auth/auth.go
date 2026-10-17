// Package auth defines the authentication abstraction. A single session is
// established per scan and reused throughout; the scanner never silently
// re-authenticates. On expiry the owning scan moves to AwaitingAuth and the
// operator is asked to re-authenticate.
//
// Anonymous (no credentials) and Existing (importing session material saved
// by a prior interactive login) drive no login flow of their own. Interactive
// and MFA drive a real, visible browser (browser.Manager.InteractiveLogin)
// that the operator logs into themselves (however many steps that needs,
// including any second factor) — Indago never sees or stores credentials
// for these. Password drives a HEADLESS, non-interactive login
// (browser.Manager.AutoLogin) that fills and submits a login form itself,
// using credentials from the SERVER process's own environment
// (INDAGO_AUTH_USER/INDAGO_AUTH_PASS, read fresh at login time, never
// accepted over the API/CLI, never persisted) — see
// Controller.resolveAuth in internal/scan/controller.go for where each mode
// is actually driven.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented is kept for compatibility with any caller still matching
// on it; no Authenticator in this package returns it anymore (Password,
// Interactive, and MFA all have real behavior now — see capturedSession).
var ErrNotImplemented = errors.New("auth: not implemented in Phase 0")

// ErrInvalidState reports unusable session material for AuthExisting: a
// missing, relative, unreadable, oversized, or malformed state path.
var ErrInvalidState = errors.New("auth: invalid session state")

// maxStateFileSize bounds a session state file. Playwright storage states are
// a few KB; anything far larger is not one, and is not read into memory.
const maxStateFileSize = 10 << 20

// Implemented reports whether mode has a working authenticator. All five
// domain.AuthMode values are implemented (see the package doc comment for
// which mechanism drives each one) — kept as its own function, rather than
// inlining domain.AuthMode.IsValid() at call sites, so a FUTURE mode added to
// the enum before its authenticator exists still fails closed here.
func Implemented(mode domain.AuthMode) bool {
	return mode.IsValid()
}

// ValidateStateFile checks that path names session material AuthExisting can
// use: an absolute path (the server, not the caller's shell, resolves it) to a
// readable regular file of bounded size holding a JSON object in Playwright's
// storage-state shape ({"cookies":[...], "origins":[...]}, either key may be
// absent but the file must contain at least one of them). It reads only the
// file; it never contacts the target.
func ValidateStateFile(path string) error {
	if path == "" {
		return fmt.Errorf("%w: existing-session mode requires a state path", ErrInvalidState)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: state path %q must be absolute", ErrInvalidState, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInvalidState, path)
	}
	if fi.Size() > maxStateFileSize {
		return fmt.Errorf("%w: %s is larger than %d bytes", ErrInvalidState, path, maxStateFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateFileSize+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	var state struct {
		Cookies *[]struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"cookies"`
		Origins *[]json.RawMessage `json:"origins"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("%w: %s is not a storage-state JSON file: %v", ErrInvalidState, path, err)
	}
	if state.Cookies == nil && state.Origins == nil {
		return fmt.Errorf("%w: %s has neither \"cookies\" nor \"origins\" (not a storage-state file)", ErrInvalidState, path)
	}
	return nil
}

// Input carries what an authenticator needs to establish a session. Secret
// material is referenced by path or supplied interactively — never logged.
type Input struct {
	ScanID    domain.ID
	LoginURL  string
	Username  string
	StatePath string // for AuthExisting: path to pre-existing session material
}

// Authenticator establishes and validates a session for one auth mode.
type Authenticator interface {
	Mode() domain.AuthMode
	// Establish creates or loads the session for a scan.
	Establish(ctx context.Context, in Input) (*domain.Session, error)
	// Validate reports whether the session is still active (used to detect
	// expiry so the scan can pause and request re-authentication).
	Validate(ctx context.Context, s *domain.Session) (bool, error)
}

// Anonymous is the implemented no-credential authenticator.
type Anonymous struct{}

// Mode implements Authenticator.
func (Anonymous) Mode() domain.AuthMode { return domain.AuthAnonymous }

// Establish returns an immediately-active anonymous session.
func (Anonymous) Establish(_ context.Context, in Input) (*domain.Session, error) {
	now := time.Now()
	return &domain.Session{
		ID:        domain.NewID(),
		ScanID:    in.ScanID,
		Mode:      domain.AuthAnonymous,
		State:     domain.SessionActive,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Validate always reports active for anonymous sessions.
func (Anonymous) Validate(context.Context, *domain.Session) (bool, error) { return true, nil }

var _ Authenticator = Anonymous{}

// Existing imports session material (cookies/storage state) saved by a prior
// interactive login — e.g. the operator ran an interactive-login flow once,
// out of band, and points the scan at the saved file. It performs no network
// or browser activity itself: it only validates that the material is present,
// which is why it needs none of Interactive/MFA's unimplemented machinery.
type Existing struct{}

// Mode implements Authenticator.
func (Existing) Mode() domain.AuthMode { return domain.AuthExisting }

// Establish validates in.StatePath (see ValidateStateFile) and returns an
// active session pointing at it.
func (Existing) Establish(_ context.Context, in Input) (*domain.Session, error) {
	if err := ValidateStateFile(in.StatePath); err != nil {
		return nil, err
	}
	now := time.Now()
	return &domain.Session{
		ID:        domain.NewID(),
		ScanID:    in.ScanID,
		Mode:      domain.AuthExisting,
		State:     domain.SessionActive,
		StatePath: in.StatePath,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Validate reports the session active as long as its state file is still
// present; it does not assert the material is still ACCEPTED by the target
// (that would require the network activity this mode deliberately avoids).
func (Existing) Validate(_ context.Context, s *domain.Session) (bool, error) {
	if s.StatePath == "" {
		return false, nil
	}
	_, err := os.Stat(s.StatePath)
	return err == nil, nil
}

var _ Authenticator = Existing{}

// capturedSession is the Establish/Validate half of Password, Interactive,
// and MFA: identical to Existing's behavior (validate the state file is
// present, point the Session at it — no network or browser activity here)
// because by the time ANY of this runs, the actual login already happened
// ONCE, up front, in Controller.resolveAuth at scan-CREATE time (driving a
// real browser login or auto-filling a form) — Establish must never repeat
// that on every scan Start/Resume: for Interactive/MFA that would mean
// blocking a resume on a human being present again; for Password it would
// mean a fresh login (and a fresh, possibly-rotated session) every resume
// for no reason. Only Mode() differs per instance, purely for display/
// provenance — an operator should still see "password", not "existing", on
// a scan whose session happened to be captured that way.
type capturedSession struct{ mode domain.AuthMode }

func (c capturedSession) Mode() domain.AuthMode { return c.mode }

func (c capturedSession) Establish(_ context.Context, in Input) (*domain.Session, error) {
	if err := ValidateStateFile(in.StatePath); err != nil {
		return nil, err
	}
	now := time.Now()
	return &domain.Session{
		ID:        domain.NewID(),
		ScanID:    in.ScanID,
		Mode:      c.mode,
		State:     domain.SessionActive,
		StatePath: in.StatePath,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (c capturedSession) Validate(_ context.Context, s *domain.Session) (bool, error) {
	if s.StatePath == "" {
		return false, nil
	}
	_, err := os.Stat(s.StatePath)
	return err == nil, nil
}

var _ Authenticator = capturedSession{}

// For returns the authenticator for a given mode. Anonymous and Existing
// establish/validate directly; Password, Interactive, and MFA use
// capturedSession — see its doc comment for why Establish there does NOT
// repeat the actual login (that already happened once, in
// Controller.resolveAuth, before the Session this operates on ever carries
// a real StatePath).
func For(mode domain.AuthMode) (Authenticator, error) {
	switch mode {
	case domain.AuthAnonymous:
		return Anonymous{}, nil
	case domain.AuthExisting:
		return Existing{}, nil
	case domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA:
		return capturedSession{mode: mode}, nil
	default:
		return nil, fmt.Errorf("auth: unknown mode %q", mode)
	}
}

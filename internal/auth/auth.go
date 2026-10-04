// Package auth defines the authentication abstraction. A single session is
// established per scan and reused throughout; the scanner never silently
// re-authenticates. On expiry the owning scan moves to AwaitingAuth and the
// operator is asked to re-authenticate.
//
// Phase 0 implements only the Anonymous mode (which needs no credentials). The
// password, interactive-browser, MFA, and existing-session modes are stubs that
// return ErrNotImplemented; credential handling and interactive login arrive in
// Phase 1.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/indago/indago/internal/domain"
)

// ErrNotImplemented indicates a Phase 0 stub with no behavior yet.
var ErrNotImplemented = errors.New("auth: not implemented in Phase 0")

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

// stubAuth is a Phase 0 placeholder for a not-yet-implemented mode.
type stubAuth struct{ mode domain.AuthMode }

func (s stubAuth) Mode() domain.AuthMode { return s.mode }
func (s stubAuth) Establish(context.Context, Input) (*domain.Session, error) {
	return nil, fmt.Errorf("%w: auth mode %q", ErrNotImplemented, s.mode)
}
func (s stubAuth) Validate(context.Context, *domain.Session) (bool, error) {
	return false, fmt.Errorf("%w: auth mode %q", ErrNotImplemented, s.mode)
}

// For returns the authenticator for a given mode. Only Anonymous is implemented
// in Phase 0; other modes return a stub whose operations report ErrNotImplemented.
func For(mode domain.AuthMode) (Authenticator, error) {
	switch mode {
	case domain.AuthAnonymous:
		return Anonymous{}, nil
	case domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA, domain.AuthExisting:
		return stubAuth{mode: mode}, nil
	default:
		return nil, fmt.Errorf("auth: unknown mode %q", mode)
	}
}

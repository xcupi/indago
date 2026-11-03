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
	"math"
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

// nowFunc returns the current time. It is a package-level variable so tests
// can pin the clock and assert expiry behavior deterministically; production
// code only ever reads it through stateExpired/ValidateStateFile.
var nowFunc = time.Now

// stateCookie is one cookie in a Playwright storage-state file. Expires is
// unix seconds; Playwright writes a negative value (-1) or omits the key for a
// session cookie that does not expire by time.
type stateCookie struct {
	Name    string   `json:"name"`
	Value   string   `json:"value"`
	Expires *float64 `json:"expires"`
}

// stateFile is the subset of a Playwright storage-state file this package
// needs: its cookies, plus which of the two well-known keys were present.
type stateFile struct {
	Cookies *[]stateCookie     `json:"cookies"`
	Origins *[]json.RawMessage `json:"origins"`
}

// originsOf returns a state's origins entries, or nil when the key is absent.
func originsOf(state stateFile) []json.RawMessage {
	if state.Origins == nil {
		return nil
	}
	return *state.Origins
}

// stateOrigin is one origins[] entry, reduced to whether it holds any
// browser-side storage. Only array lengths are inspected; local/session
// storage names and values are never decoded, logged, or retained.
type stateOrigin struct {
	LocalStorage []json.RawMessage `json:"localStorage"`
	IndexedDB    []json.RawMessage `json:"indexedDB"`
}

// originsHoldStorage reports whether any origins entry carries a non-empty
// localStorage or indexedDB array — the browser-side material an SPA often
// keeps its real session in. Entries that are not JSON objects, or whose keys
// are null/wrong-typed, are skipped: unparseable content proves nothing, so it
// never counts as live material (and never panics).
func originsHoldStorage(origins []json.RawMessage) bool {
	for _, raw := range origins {
		var o stateOrigin
		if err := json.Unmarshal(raw, &o); err != nil {
			continue
		}
		if len(o.LocalStorage) > 0 || len(o.IndexedDB) > 0 {
			return true
		}
	}
	return false
}

// stateExpired reports whether the saved material can no longer carry a
// session at now: it holds at least one cookie, every cookie has a positive,
// persistent expiry already in the past, AND its origins hold no browser-side
// storage.
//
// This is deliberately conservative because Indago cannot tell where the
// authenticated session actually lives. Zero cookies (an origins-only state),
// any session cookie (expires <= 0 or absent), any cookie still valid at now,
// or any origin entry with a non-empty localStorage/indexedDB array means NOT
// expired, so a scan is never paused — and a state is never rejected at
// creation — while any part of the material may still be live. The cost is a
// real limitation: material whose cookie AND origin storage have both gone
// stale cannot be distinguished from dead material by file inspection alone
// (an expired localStorage token is not time-stamped here), and material whose
// auth cookie expired while an unrelated cookie remains valid is not detected
// either. Catching those would require asking the target whether it still
// accepts the session, a separate, scope-guarded feature this package
// deliberately does not implement (auth reads files only; it never contacts
// the target).
func stateExpired(state stateFile, now time.Time) bool {
	cookies := []stateCookie(nil)
	if state.Cookies != nil {
		cookies = *state.Cookies
	}
	if len(cookies) == 0 {
		return false
	}
	if originsHoldStorage(originsOf(state)) {
		return false
	}
	for _, c := range cookies {
		exp := cookieExpiry(c)
		if exp == nil || !exp.Before(now) {
			return false
		}
	}
	return true
}

// cookieExpiry returns a cookie's persistent expiry, or nil when it does not
// expire by time (a session cookie: negative, absent, zero, or unusable).
func cookieExpiry(c stateCookie) *time.Time {
	if c.Expires == nil {
		return nil
	}
	sec := *c.Expires
	if sec <= 0 || math.IsNaN(sec) || math.IsInf(sec, 0) || sec >= float64(math.MaxInt64) {
		return nil
	}
	t := time.Unix(int64(sec), 0)
	return &t
}

// stateExpiresAt returns the latest cookie expiry — the point after which
// nothing in the material can still be valid by time — or nil when the state
// has no cookies, any cookie is a session cookie, or an origin entry holds
// browser-side storage, because then the cookie expiry does not describe the
// whole material.
func stateExpiresAt(state stateFile) *time.Time {
	if state.Cookies == nil || len(*state.Cookies) == 0 || originsHoldStorage(originsOf(state)) {
		return nil
	}
	cookies := *state.Cookies
	var latest time.Time
	for i, c := range cookies {
		exp := cookieExpiry(c)
		if exp == nil {
			return nil
		}
		if i == 0 || exp.After(latest) {
			latest = *exp
		}
	}
	return &latest
}

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
// absent but the file must contain at least one of them). Material whose
// cookies are ALL already expired — and whose origins hold no browser-side
// storage — is rejected (see stateExpired). It reads only the file; it never
// contacts the target.
func ValidateStateFile(path string) error {
	_, err := readStateFile(path)
	return err
}

// readStateFile performs ValidateStateFile's checks and returns the parsed
// material, so callers that need its cookies (for expiry) read and validate it
// once.
func readStateFile(path string) (stateFile, error) {
	if path == "" {
		return stateFile{}, fmt.Errorf("%w: existing-session mode requires a state path", ErrInvalidState)
	}
	if !filepath.IsAbs(path) {
		return stateFile{}, fmt.Errorf("%w: state path %q must be absolute", ErrInvalidState, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return stateFile{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return stateFile{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if !fi.Mode().IsRegular() {
		return stateFile{}, fmt.Errorf("%w: %s is not a regular file", ErrInvalidState, path)
	}
	if fi.Size() > maxStateFileSize {
		return stateFile{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrInvalidState, path, maxStateFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateFileSize+1))
	if err != nil {
		return stateFile{}, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return stateFile{}, fmt.Errorf("%w: %s is not a storage-state JSON file: %v", ErrInvalidState, path, err)
	}
	if state.Cookies == nil && state.Origins == nil {
		return stateFile{}, fmt.Errorf("%w: %s has neither \"cookies\" nor \"origins\" (not a storage-state file)", ErrInvalidState, path)
	}
	if state.Cookies != nil && stateExpired(state, nowFunc()) {
		return stateFile{}, fmt.Errorf("%w: %s session cookies are expired — re-authenticate and save a fresh state file", ErrInvalidState, path)
	}
	return state, nil
}

// stateUsable reports whether path's material is present, readable, well formed
// and not all-expired. Problems report false rather than an error: Validate's
// contract is a boolean, so a scan whose saved session went stale moves to
// AwaitingAuth instead of surfacing an error to the monitor.
func stateUsable(path string) bool {
	if path == "" {
		return false
	}
	return ValidateStateFile(path) == nil
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
// or browser activity itself: it only validates that the material is present
// and not entirely expired, which is why it needs none of Interactive/MFA's
// unimplemented machinery.
type Existing struct{}

// Mode implements Authenticator.
func (Existing) Mode() domain.AuthMode { return domain.AuthExisting }

// Establish validates in.StatePath (see ValidateStateFile) and returns an
// active session pointing at it, with ExpiresAt derived from the saved
// cookies when they can tell us (see stateExpiresAt).
func (Existing) Establish(_ context.Context, in Input) (*domain.Session, error) {
	return importState(domain.AuthExisting, in)
}

// Validate reports the session active only while its saved material is
// present, readable, well formed, and not entirely expired by cookie time. It
// does not assert the material is still ACCEPTED by the target (that would
// take the network activity this mode deliberately avoids).
func (Existing) Validate(_ context.Context, s *domain.Session) (bool, error) {
	return stateUsable(s.StatePath), nil
}

var _ Authenticator = Existing{}

// importState validates in.StatePath and builds the active session that points
// at it. Shared by Existing and capturedSession, whose Establish halves are
// identical by design (see capturedSession's doc comment).
func importState(mode domain.AuthMode, in Input) (*domain.Session, error) {
	state, err := readStateFile(in.StatePath)
	if err != nil {
		return nil, err
	}
	expiresAt := stateExpiresAt(state)
	now := time.Now()
	return &domain.Session{
		ID:        domain.NewID(),
		ScanID:    in.ScanID,
		Mode:      mode,
		State:     domain.SessionActive,
		StatePath: in.StatePath,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// capturedSession is the Establish/Validate half of Password, Interactive,
// and MFA: identical to Existing's behavior (validate the state file is
// present and not entirely expired, point the Session at it — no network or
// browser activity here)
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
	return importState(c.mode, in)
}

func (c capturedSession) Validate(_ context.Context, s *domain.Session) (bool, error) {
	return stateUsable(s.StatePath), nil
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

package domain

import "time"

// AuthMode is how an authenticated session is established for a scan.
type AuthMode string

const (
	AuthAnonymous   AuthMode = "anonymous"   // no authentication
	AuthPassword    AuthMode = "password"    // username/password submission
	AuthInteractive AuthMode = "interactive" // operator logs in via browser
	AuthMFA         AuthMode = "mfa"         // interactive with a second factor
	AuthExisting    AuthMode = "existing"    // import existing session material
)

// IsValid reports whether the auth mode is a known value.
func (m AuthMode) IsValid() bool {
	switch m {
	case AuthAnonymous, AuthPassword, AuthInteractive, AuthMFA, AuthExisting:
		return true
	default:
		return false
	}
}

// Session is an authenticated session established once per scan and reused
// throughout it. The scanner never silently re-authenticates during normal
// scanning; on expiry the owning scan moves to AwaitingAuth and asks the
// operator to re-authenticate.
//
// Session material (cookies, storage state) is stored on disk at StatePath,
// never inline in the database.
type Session struct {
	ID     ID           `json:"id"`
	ScanID ID           `json:"scan_id"`
	Mode   AuthMode     `json:"mode"`
	State  SessionState `json:"state"`

	StatePath string     `json:"state_path,omitempty"` // path to session material on disk
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

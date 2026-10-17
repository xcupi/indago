package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// MinAPITokenLen is the minimum length of a configured API bearer token. A
// shorter token is refused at startup: a guessable token is no control at all.
const MinAPITokenLen = 32

// ValidateAPIToken checks a token for the control API. The error never
// contains the token itself.
func ValidateAPIToken(tok string) error {
	if len(tok) < MinAPITokenLen {
		return fmt.Errorf("must be at least %d characters", MinAPITokenLen)
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] == 0x7f {
			return errors.New("must not contain whitespace or control characters")
		}
	}
	return nil
}

// SetAPIToken enables bearer-token authentication for every /api/ route. An
// empty token leaves authentication disabled (the single-operator loopback
// default). The token is kept only as a SHA-256 digest.
func (s *Server) SetAPIToken(tok string) error {
	if tok == "" {
		s.apiTokenDigest = nil
		return nil
	}
	if err := ValidateAPIToken(tok); err != nil {
		return err
	}
	d := sha256.Sum256([]byte(tok))
	s.apiTokenDigest = d[:]
	return nil
}

// requireAPIToken enforces the bearer token on /api/ routes when one is
// configured. /healthz and the static UI stay open, so the page can load and
// prompt for the token. The token is accepted only from the Authorization
// header, never from the query string or a cookie.
func (s *Server) requireAPIToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiTokenDigest == nil || !isAPIPath(r.URL.Path) ||
			bearerMatches(r.Header.Get("Authorization"), s.apiTokenDigest) {
			next.ServeHTTP(w, r)
			return
		}
		s.log.Info("api request rejected: missing or invalid bearer token",
			"method", r.Method, "path", r.URL.Path)
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "missing or invalid API token")
	})
}

// bearerMatches reports whether an Authorization header carries the token
// whose SHA-256 digest is digest. Both sides are hashed to a fixed 32 bytes
// before the constant-time comparison, so comparison time does not depend on
// the length of the presented token. A nil digest never matches.
func bearerMatches(authorization string, digest []byte) bool {
	if digest == nil {
		return false
	}
	scheme, tok, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(presented[:], digest) == 1
}

// isAPIPath reports whether p is in the control API namespace.
func isAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/")
}

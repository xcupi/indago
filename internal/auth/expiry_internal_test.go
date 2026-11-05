package auth

// Deterministic tests for the cookie-expiry helpers. The clock is a parameter
// of stateExpired and a package-level variable for the file-reading paths, so
// these tests use fixed timestamps and never sleep or depend on wall time.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testNow is the fixed reference clock for this file (2023-11-14T22:13:20Z).
var testNow = time.Unix(1700000000, 0)

// exp is a helper for taking the address of a cookie expiry literal.
func exp(v float64) *float64 { return &v }

// cookiesState builds a state file that has a cookies key and no origins.
func cookiesState(cs ...stateCookie) stateFile {
	return stateFile{Cookies: &cs}
}

// withOrigins attaches raw origins[] entries to a state file.
func withOrigins(s stateFile, entries ...string) stateFile {
	raw := make([]json.RawMessage, 0, len(entries))
	for _, e := range entries {
		raw = append(raw, json.RawMessage(e))
	}
	s.Origins = &raw
	return s
}

func TestStateExpired(t *testing.T) {
	past := exp(1)                    // 1970 — a persistent cookie long expired
	future := exp(4102444800)         // 2100 — persistent cookie still valid
	justBefore := exp(1699999999)     // one second before testNow
	now := exp(1700000000)            // exactly testNow
	sessionCookie := exp(-1)          // Playwright session cookie marker
	zeroExpiry := exp(0)              // absent-or-zero expiry is also non-persistent
	expiredPair := func() stateFile { // two cookies, both long expired
		return cookiesState(stateCookie{Expires: past}, stateCookie{Expires: justBefore})
	}
	cases := map[string]struct {
		state stateFile
		want  bool
	}{
		"no cookies at all":               {stateFile{}, false},
		"origins only (empty cookies)":    {cookiesState(), false},
		"single cookie in the past":       {cookiesState(stateCookie{Name: "c", Value: "v", Expires: past}), true},
		"every cookie in the past":        {expiredPair(), true},
		"one cookie still valid":          {cookiesState(stateCookie{Expires: past}, stateCookie{Expires: future}), false},
		"one session cookie mixed in":     {cookiesState(stateCookie{Expires: past}, stateCookie{Expires: sessionCookie}), false},
		"one zero-expiry cookie mixed in": {cookiesState(stateCookie{Expires: past}, stateCookie{Expires: zeroExpiry}), false},
		"expiry exactly now is not past":  {cookiesState(stateCookie{Expires: now}), false},
		"expiry absent":                   {cookiesState(stateCookie{Name: "c"}), false},

		// An SPA may keep its real session in origin storage while every
		// cookie in the file is stale: that material is "cannot tell", never
		// "expired".
		"all cookies past, localStorage held": {
			withOrigins(expiredPair(), `{"origin":"https://example.test","localStorage":[{"name":"dummy","value":"dummy"}]}`),
			false,
		},
		"all cookies past, indexedDB held": {
			withOrigins(expiredPair(), `{"origin":"https://example.test","indexedDB":[{"name":"dummy","version":1,"stores":[]}]}`),
			false,
		},
		// Empty, missing, null or malformed origin entries carry no evidence
		// of live material, so an all-expired-cookie state stays expired.
		"all cookies past, origin storage empty": {
			withOrigins(expiredPair(), `{"origin":"https://example.test","localStorage":[],"indexedDB":[]}`),
			true,
		},
		"all cookies past, origin without storage keys": {
			withOrigins(expiredPair(), `{"origin":"https://example.test"}`),
			true,
		},
		"all cookies past, null origin entry": {withOrigins(expiredPair(), `null`), true},
		"all cookies past, null storage keys": {withOrigins(expiredPair(), `{"localStorage":null,"indexedDB":null}`), true},
		"all cookies past, malformed origin entry": {
			withOrigins(expiredPair(), `"not-an-object"`, `{"localStorage":"not-an-array"}`),
			true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := stateExpired(tc.state, testNow); got != tc.want {
				t.Fatalf("stateExpired(%s) = %v, want %v", name, got, tc.want)
			}
		})
	}
}

func TestStateExpiresAt(t *testing.T) {
	if got := stateExpiresAt(stateFile{}); got != nil {
		t.Fatalf("stateExpiresAt(no cookies) = %v, want nil", got)
	}
	latest := time.Unix(4102444800, 0)
	got := stateExpiresAt(cookiesState(stateCookie{Expires: exp(1700000000)}, stateCookie{Expires: exp(4102444800)}))
	if got == nil || !got.Equal(latest) {
		t.Fatalf("stateExpiresAt(all persistent) = %v, want %v", got, latest)
	}
	// Any session cookie makes the state's expiry unknowable by time.
	if got := stateExpiresAt(cookiesState(stateCookie{Expires: exp(4102444800)}, stateCookie{Expires: exp(-1)})); got != nil {
		t.Fatalf("stateExpiresAt(with a session cookie) = %v, want nil", got)
	}
	if got := stateExpiresAt(cookiesState(stateCookie{Expires: exp(0)}, stateCookie{Expires: exp(4102444800)})); got != nil {
		t.Fatalf("stateExpiresAt(with a zero-expiry cookie) = %v, want nil", got)
	}
	// Origin storage means the cookie expiry does not describe the material.
	if got := stateExpiresAt(withOrigins(cookiesState(stateCookie{Expires: exp(4102444800)}),
		`{"origin":"https://example.test","localStorage":[{"name":"dummy","value":"dummy"}]}`)); got != nil {
		t.Fatalf("stateExpiresAt(with origin storage) = %v, want nil", got)
	}
	// Empty origin storage is no material, so the cookie expiry stands.
	got = stateExpiresAt(withOrigins(cookiesState(stateCookie{Expires: exp(4102444800)}),
		`{"origin":"https://example.test","localStorage":[]}`))
	if got == nil || !got.Equal(latest) {
		t.Fatalf("stateExpiresAt(with empty origin storage) = %v, want %v", got, latest)
	}
}

// ValidateStateFile must use the injectable clock, not time.Now directly: the
// same file is expired or not depending only on the injected instant.
func TestValidateStateFileUsesInjectedClock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// 4102444800 (2100-01-01) is in the future for the real clock.
	body := `{"cookies":[{"name":"dummy","value":"dummy","domain":"example.test","path":"/","expires":4102444800}],"origins":[]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStateFile(path); err != nil {
		t.Fatalf("state valid at the real clock rejected: %v", err)
	}

	old := nowFunc
	nowFunc = func() time.Time { return time.Unix(4102444801, 0) }
	t.Cleanup(func() { nowFunc = old })

	err := ValidateStateFile(path)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ValidateStateFile at an injected later clock = %v, want ErrInvalidState", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error does not say the cookies are expired: %v", err)
	}
}

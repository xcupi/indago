package chatgpt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(filepath.Join(dir, "chatgpt"))
	exp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := Credential{
		AccessToken: "access-token-value", RefreshToken: "refresh-token-value",
		BaseURL: DefaultBaseURL, AccountID: "acct-123456", Plan: "plus",
		ExpiresAt: exp, Label: "indago device-code", Owned: true,
	}
	if err := st.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if out.AccessToken != in.AccessToken || out.RefreshToken != in.RefreshToken || !out.Owned {
		t.Fatalf("round trip = %+v", out)
	}
	if !out.ExpiresAt.Equal(exp) {
		t.Fatalf("expires = %v, want %v", out.ExpiresAt, exp)
	}
	// The file must not be world-readable.
	info, err := os.Stat(filepath.Join(dir, "chatgpt", "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials perm = %o, want 600", perm)
	}
	if err := st.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("Load after Clear should report no credential")
	}
}

func TestLoadPreferredPrefersOwnStore(t *testing.T) {
	dir := t.TempDir()
	if err := NewStore(dir).Save(Credential{
		AccessToken: "own", BaseURL: DefaultBaseURL, Owned: true,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INDAGO_CHATGPT_AUTH", filepath.Join(t.TempDir(), "missing.json"))
	got, err := LoadPreferred(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "own" || !got.Owned {
		t.Fatalf("preferred = %+v, want the Indago-owned credential", got)
	}
}

func TestRefreshRefusesBorrowedCredential(t *testing.T) {
	if _, err := Refresh(t.Context(), Credential{RefreshToken: "r", Owned: false}); err == nil {
		t.Fatal("refreshing a borrowed credential must be refused")
	}
}

package web_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func TestAuthProfileCanBeSharedByTargetsAndDefaultsScanAuth(t *testing.T) {
	a := newAPI(t, nil)
	projectID, targetID := setupScan(a, "http://127.0.0.1:9/")
	ctx := context.Background()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(`{"cookies":[],"origins":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	profile := &domain.AuthProfile{
		ID: domain.NewID(), ProjectID: domain.ID(projectID), Name: "HTB SSO",
		LoginURL: "http://127.0.0.1:9/login", StatePath: statePath,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.st.AuthProfiles().Create(ctx, profile); err != nil {
		t.Fatal(err)
	}

	var target domain.Target
	a.mustJSON(a.do("GET", "/api/projects/"+string(projectID)+"/targets/"+string(targetID), nil), http.StatusOK, &target)
	a.mustJSON(a.do("PUT", "/api/projects/"+string(projectID)+"/targets/"+string(targetID), map[string]any{
		"name": target.Name, "base_url": target.BaseURL, "auth_profile_id": profile.ID,
	}), http.StatusOK, nil)

	// No auth_mode in the request: the target's profile supplies it.
	var scan domain.Scan
	a.mustJSON(a.do("POST", "/api/scans", map[string]any{
		"project_id": projectID, "target_id": targetID,
	}), http.StatusCreated, &scan)
	if scan.Config.AuthProfileID != profile.ID {
		t.Fatalf("scan auth_profile_id = %q, want %q", scan.Config.AuthProfileID, profile.ID)
	}

	// A second target can point at the same profile; deleting it clears both.
	var list []*domain.AuthProfile
	a.mustJSON(a.do("GET", "/api/projects/"+string(projectID)+"/auth-profiles", nil), http.StatusOK, &list)
	if len(list) != 1 {
		t.Fatalf("profiles = %d, want 1", len(list))
	}
	a.mustJSON(a.do("DELETE", "/api/projects/"+string(projectID)+"/auth-profiles/"+string(profile.ID), nil), http.StatusNoContent, nil)
	a.mustJSON(a.do("GET", "/api/projects/"+string(projectID)+"/targets/"+string(targetID), nil), http.StatusOK, &target)
	if target.AuthProfileID != "" {
		t.Fatalf("deleted profile still assigned to target: %q", target.AuthProfileID)
	}
}

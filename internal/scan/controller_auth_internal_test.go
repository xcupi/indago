package scan

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func authInheritanceFixture(t *testing.T) (*Controller, *memory.Store, *domain.Scan, *domain.Target) {
	t.Helper()
	st := memory.New()
	ctrl := NewController(st, queue.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	ctx := context.Background()
	now := time.Now()
	projectID := domain.NewID()
	profile := &domain.AuthProfile{
		ID: domain.NewID(), ProjectID: projectID, Name: "saved",
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := st.AuthProfiles().Create(ctx, profile); err != nil {
		t.Fatal(err)
	}
	sess := &domain.Session{
		ID: domain.NewID(), ScanID: domain.NewID(), Mode: domain.AuthAnonymous,
		State: domain.SessionNone, CreatedAt: now, UpdatedAt: now,
	}
	if err := st.Sessions().Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	sc := &domain.Scan{
		ID: domain.NewID(), ProjectID: projectID, SessionID: sess.ID,
		Config: domain.ScanConfig{AuthModeExplicit: true},
	}
	target := &domain.Target{ID: domain.NewID(), ProjectID: projectID, AuthProfileID: profile.ID}
	return ctrl, st, sc, target
}

func TestInheritTargetAuthProfileRespectsExplicitAnonymous(t *testing.T) {
	ctrl, st, sc, target := authInheritanceFixture(t)
	if err := ctrl.inheritTargetAuthProfile(context.Background(), sc, target); err != nil {
		t.Fatal(err)
	}
	got, err := st.Sessions().Get(context.Background(), sc.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != domain.AuthAnonymous {
		t.Fatalf("explicit anonymous scan became %q", got.Mode)
	}
	if sc.Config.AuthProfileID != "" {
		t.Fatalf("explicit anonymous scan recorded auth profile %q", sc.Config.AuthProfileID)
	}
}

func TestInheritTargetAuthProfileKeepsLegacyDraftBehavior(t *testing.T) {
	_, st, sc, target := authInheritanceFixture(t)
	sc.Config.AuthModeExplicit = false
	// The draft was created before the target had a profile.
	sc.Config.AuthProfileID = ""
	ctrl := NewController(st, queue.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test", Options{})
	t.Cleanup(ctrl.Shutdown)
	if err := ctrl.inheritTargetAuthProfile(context.Background(), sc, target); err != nil {
		t.Fatal(err)
	}
	got, err := st.Sessions().Get(context.Background(), sc.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != domain.AuthExisting || got.StatePath == "" {
		t.Fatalf("legacy draft did not inherit the target profile: %+v", got)
	}
}

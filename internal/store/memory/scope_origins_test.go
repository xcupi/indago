package memory_test

// The in-memory store is a first-class backend (the default for tests and dev),
// so the origin fields must round-trip there too, including the clone that keeps
// a caller from mutating stored state through a returned slice.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store/memory"
)

func TestMemoryScopeOriginsRoundTripAndClone(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Now().UTC()
	project := &domain.Project{ID: domain.NewID(), Name: "p", CreatedAt: now, UpdatedAt: now}
	if err := st.Projects().Create(ctx, project); err != nil {
		t.Fatal(err)
	}
	origins := []string{"https://app.example.com", "http://app.example.com:8080"}
	sc := &domain.Scope{
		ID:             domain.NewID(),
		ProjectID:      project.ID,
		IncludeHosts:   []string{"app.example.com"},
		AllowedOrigins: origins,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := st.Scopes().Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := st.Scopes().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AllowedOrigins, origins) {
		t.Fatalf("allowed_origins = %v, want %v", got.AllowedOrigins, origins)
	}
	// Mutating the returned slice must not mutate the stored scope.
	got.AllowedOrigins[0] = "https://evil.example"
	again, err := st.Scopes().Get(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.AllowedOrigins[0] != origins[0] {
		t.Fatalf("stored scope aliases the caller's slice: %v", again.AllowedOrigins)
	}
	// The matcher reads the same field from the in-memory store.
	if d := again.Permits("http://app.example.com:8080/x"); !d.Allowed {
		t.Fatalf("stored origin denied: %+v", d)
	}
	if d := again.Permits("https://app.example.com:8443/x"); d.Allowed {
		t.Fatal("an undeclared port was allowed")
	}
}

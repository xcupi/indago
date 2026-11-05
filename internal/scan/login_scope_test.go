package scan_test

import (
	"context"
	"errors"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
	"testing"
)

func TestCreateScanRejectsOutOfScopeLogin(t *testing.T) {
	st := memory.New()
	proj, tgt := seedProject(t, st, "http://127.0.0.1/", hostScope())
	ctrl := newCtrl(t, st, queue.NewMemory(), scan.Options{})
	for _, mode := range []domain.AuthMode{domain.AuthPassword, domain.AuthInteractive, domain.AuthMFA} {
		t.Run(string(mode), func(t *testing.T) {
			_, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{ProjectID: proj, TargetID: tgt, AuthMode: mode, LoginURL: "http://localhost/login", SuccessURL: "**/done"})
			if !errors.Is(err, scan.ErrOutOfScope) {
				t.Fatalf("expected scope rejection before browser/credential lookup, got %v", err)
			}
		})
	}
}

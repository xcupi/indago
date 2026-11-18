package scan_test

// Integration tests for seed/target scope checks. CreateScan does not send a
// request, so these are loopback-free and prove the boundary rejects an
// ambiguous path before a scan can ever launch it.

import (
	"context"
	"errors"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestCreateScanRejectsAmbiguousTargetPath(t *testing.T) {
	st := memory.New()
	ctrl := newCtrl(t, st, queue.NewMemory(), scan.Options{})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1/app/../outside", domain.Scope{
		IncludeHosts:        []string{"127.0.0.1"},
		IncludePathPrefixes: []string{"/app"},
	})

	_, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: proj,
		TargetID:  tgt,
		Name:      "ambiguous target",
		Profile:   domain.ProfileConservative,
	})
	if !errors.Is(err, scan.ErrOutOfScope) {
		t.Fatalf("CreateScan() error = %v, want ErrOutOfScope", err)
	}
}

func TestCreateScanRejectsAmbiguousSeedPaths(t *testing.T) {
	st := memory.New()
	ctrl := newCtrl(t, st, queue.NewMemory(), scan.Options{})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1/app/", domain.Scope{
		IncludeHosts:        []string{"127.0.0.1"},
		IncludePathPrefixes: []string{"/app"},
	})

	for _, seed := range []string{
		"http://127.0.0.1:1/app/%2e%2e/outside",
		"http://127.0.0.1:1/app/%252e%252e/outside",
		"http://127.0.0.1:1/app/%2f..%2foutside",
		"http://127.0.0.1:1/app/%5c..%5coutside",
		"http://127.0.0.1:1/app/..;/outside",
	} {
		t.Run(seed, func(t *testing.T) {
			_, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{
				ProjectID: proj,
				TargetID:  tgt,
				Name:      "ambiguous seed",
				Profile:   domain.ProfileConservative,
				SeedURLs:  []string{seed},
			})
			if !errors.Is(err, scan.ErrOutOfScope) && !errors.Is(err, scan.ErrInvalidSeed) {
				t.Fatalf("CreateScan(%q) error = %v, want ErrOutOfScope or ErrInvalidSeed", seed, err)
			}
		})
	}
}

func TestCreateScanAcceptsNormalSeedPath(t *testing.T) {
	st := memory.New()
	ctrl := newCtrl(t, st, queue.NewMemory(), scan.Options{})
	proj, tgt := seedProject(t, st, "http://127.0.0.1:1/app/", domain.Scope{
		IncludeHosts:        []string{"127.0.0.1"},
		IncludePathPrefixes: []string{"/app"},
	})

	sc, err := ctrl.CreateScan(context.Background(), scan.CreateScanParams{
		ProjectID: proj,
		TargetID:  tgt,
		Name:      "normal seed",
		Profile:   domain.ProfileConservative,
		SeedURLs:  []string{"http://127.0.0.1:1/app/page"},
	})
	if err != nil {
		t.Fatalf("CreateScan() error = %v, want success", err)
	}
	if sc == nil {
		t.Fatal("CreateScan() returned nil scan")
	}
}

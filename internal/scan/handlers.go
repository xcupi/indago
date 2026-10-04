package scan

import (
	"context"
	"log/slog"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/worker"
)

// phase0Handlers returns no-op handlers for every job type.
//
// IMPORTANT (Phase 0 boundary): these handlers intentionally do NOTHING against
// any target. They do not call the HTTP engine, browser, discovery sources,
// detection engines, or verification. They exist so the end-to-end pipeline
// (enqueue → lease → execute → complete) is wired and observable without any
// active target testing.
//
// Phase 1 replaces these with real handlers:
//
//	JobDiscovery → run discovery sources, emit endpoints/parameters, enqueue tests
//	JobTest      → baseline → marker → reflection → context → candidate (per engine)
//	JobVerify    → browser verification → confirmed / rejected / inconclusive
func phase0Handlers(log *slog.Logger) map[domain.JobType]worker.Handler {
	noop := func(kind domain.JobType) worker.Handler {
		return worker.HandlerFunc(func(ctx context.Context, job *domain.TestJob) error {
			log.Debug("phase0 no-op handler", "type", kind, "job", job.ID, "scan", job.ScanID)
			return nil
		})
	}
	return map[domain.JobType]worker.Handler{
		domain.JobDiscovery: noop(domain.JobDiscovery),
		domain.JobTest:      noop(domain.JobTest),
		domain.JobVerify:    noop(domain.JobVerify),
	}
}

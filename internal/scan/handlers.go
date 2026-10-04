package scan

import (
	"context"
	"log/slog"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/worker"
)

func (c *Controller) defaultHandlers(eng httpengine.Engine) map[domain.JobType]worker.Handler {
	h := phase0Handlers(c.log)
	h[domain.JobTest] = newExecutor(c.store, eng, c.opts.Evidence, c.opts.Executor, c.log)
	return h
}

// phase0Handlers returns no-op handlers for every job type; defaultHandlers
// replaces JobTest with the executor.
//
//	JobDiscovery → (discovery is run by the controller, not by queue jobs)
//	JobTest      → executor: baseline request (detection attaches here later)
//	JobVerify    → browser verification (later)
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

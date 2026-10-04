package scan

import (
	"context"
	"log/slog"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/verification"
	"github.com/indago/indago/internal/worker"
)

func (c *Controller) defaultHandlers(eng httpengine.Engine, scope domain.Scope) map[domain.JobType]worker.Handler {
	h := phase0Handlers(c.log)
	h[domain.JobTest] = newExecutor(c.store, eng, c.opts.Evidence, c.queue, c.opts.Executor, c.log)
	h[domain.JobVerify] = newVerifyExecutor(c.store, c.verifier(), c.opts.Evidence, scope, c.opts.Executor, c.log)
	return h
}

// verifier returns the Verifier a scan's JobVerify jobs should use:
// Options.Verification when set (tests inject a fake here), otherwise a real
// BrowserVerifier when Options.Browser is the concrete *browser.Manager (the
// Browser interface alone is not enough — verification needs context/page
// control, not just the Render facade), otherwise the Phase 0 Stub so
// verification cleanly no-ops (skipped, not failed) when no browser is
// configured for this scan.
func (c *Controller) verifier() verification.Verifier {
	if c.opts.Verification != nil {
		return c.opts.Verification
	}
	if mgr, ok := c.opts.Browser.(*browser.Manager); ok && mgr != nil {
		return verification.NewBrowserVerifier(mgr, c.opts.VerifyConfig)
	}
	return verification.Stub{}
}

// phase0Handlers returns no-op handlers for every job type; defaultHandlers
// replaces JobTest and JobVerify with the real executors.
//
//	JobDiscovery → (discovery is run by the controller, not by queue jobs)
//	JobTest      → executor: baseline/reflection/candidate execution
//	JobVerify    → verifyExecutor: browser verification of a reflected candidate
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

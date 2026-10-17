package scan

import (
	"context"
	"log/slog"
	"sync"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/verification"
	"github.com/indago/indago/internal/worker"
)

func (c *Controller) defaultHandlers(eng httpengine.Engine, scope domain.Scope, proxyPool []string) map[domain.JobType]worker.Handler {
	h := phase0Handlers(c.log)
	// Shared by both executors so Finding correlation (candidate-side upsert
	// and verification-side update) is race-free across the whole scan — see
	// newExecutor's doc comment. tokenMu is the same sharing pattern for the
	// dynamic (rotating/single-use) anti-CSRF token refresh — see
	// withDynamicTokenLock in dynamic_params.go.
	findingsMu := &sync.Mutex{}
	tokenMu := &sync.Mutex{}
	h[domain.JobTest] = newExecutor(c.store, eng, c.opts.Evidence, c.queue, c.opts.Executor, c.log, findingsMu, tokenMu)
	h[domain.JobVerify] = newVerifyExecutor(c.store, eng, c.verifier(), c.opts.Evidence, scope, c.opts.Executor, c.log, findingsMu, tokenMu, proxyPool)
	// DOM XSS shares findingsMu too: its Finding correlation is a
	// read-then-write against the SAME store.Findings() rows Reflected
	// XSS's own correlation touches (though never the same dedup key —
	// see domXSSFindingDedupKey's disjoint "\x00dom_xss\x00" tag).
	h[domain.JobDOMXSS] = newDOMXSSExecutor(c.store, c.browserManager(), c.opts.Evidence, scope, c.log, findingsMu)
	return h
}

// browserManager returns the concrete *browser.Manager this scan's
// DOM-XSS probing should drive, or nil when no real browser is
// configured — mirrors verifier()'s own type assertion on c.opts.Browser
// (the Browser interface alone is not enough; DOM-XSS probing needs
// context/page control and AddInitScript, not just the Render facade).
func (c *Controller) browserManager() *browser.Manager {
	if mgr, ok := c.opts.Browser.(*browser.Manager); ok {
		return mgr
	}
	return nil
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
//	JobDOMXSS    → domXSSExecutor: DOM-XSS reachability + payload verification
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
		domain.JobDOMXSS:    noop(domain.JobDOMXSS),
	}
}

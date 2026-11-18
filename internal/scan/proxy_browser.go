package scan

import (
	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
)

// discoveryBrowser returns the Browser a scan's discovery sources must use.
//
// A scan that configured domain.ScanConfig.ProxyPool gets a per-scan decorator
// around the ONE process-wide Browser: every render it performs opens its own
// context through that scan's operator proxy, round-robin. The decorator is
// built here, per scan, and never mutates the shared Manager, so:
//
//   - no proxy is process-wide (another scan's contexts are untouched);
//   - two scans with different pools (or one with none) can run concurrently
//     against the same pooled Chromium without sharing a proxy;
//   - the scope gate, the scan's rate limiter, its User-Agent and its stored
//     session all travel with the render options exactly as before.
//
// The scan's raw HTTP side already gets the same pool through scanHTTPEngine,
// and browser verification / DOM XSS through verifyExecutor.nextProxy and
// domXSSExecutor.nextProxy; this is the browser-discovery half of the same
// "every outbound request this scan makes" contract.
//
// A scan with no pool (the overwhelming majority) gets the shared Browser back
// unchanged, so the direct-connection path is byte-for-byte what it was.
func (c *Controller) discoveryBrowser(sc *domain.Scan) browser.Browser {
	if c.opts.Browser == nil {
		// No browser configured: discovery's browser source is inert (it
		// returns immediately). Nothing to proxy, and nil must stay nil so the
		// source's nil guard keeps working.
		return nil
	}
	if sc == nil {
		return c.opts.Browser
	}
	return browser.WithProxyPool(c.opts.Browser, sc.Config.ProxyPool)
}

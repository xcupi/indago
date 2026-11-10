package scan

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

// preflightTarget performs one benign request before discovery. It is deliberately
// a single GET, not a crawl: its job is to notice a target that is already
// saying "slow down", "solved a challenge", or "I don't serve automated
// clients" before the scan spends its request budget on discovery and payloads.
//
// A preflight network error is not fatal: the normal discovery path will
// classify it with the same evidence and existing retry policy. Only a
// recognised block pauses the scan.
func (c *Controller) preflightTarget(ctx context.Context, eng httpengine.Engine, target *domain.Target) error {
	if target == nil || strings.TrimSpace(target.BaseURL) == "" {
		return nil
	}
	resp, err := eng.Do(ctx, httpengine.GET(target.BaseURL))
	if err != nil {
		c.log.Debug("waf preflight: request failed; leaving classification to discovery", "target", target.ID, "err", err)
		return nil
	}
	reason := preflightBlockReason(resp)
	if reason == "" {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrWAFPreflight, reason)
}

// preflightBlockReason is pure so the policy can be tested without a network.
// It intentionally treats 429/503 and a challenge page as hard stops (there is
// no payload to judge), while a 403/406 only pauses when the response also
// carries a recognised WAF vendor — a plain application 403 may simply be an
// endpoint policy and should not block a whole scan.
func preflightBlockReason(resp *httpengine.Response) string {
	if resp == nil {
		return ""
	}
	label, captcha := detection.DetectCaptcha(resp.Body)
	vendor := wafVendor(resp.Headers)
	mitigated := strings.ToLower(strings.TrimSpace(resp.Headers.Get("CF-Mitigated")))
	switch {
	case resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusServiceUnavailable:
		retry := strings.TrimSpace(resp.Headers.Get("Retry-After"))
		if retry != "" {
			return fmt.Sprintf("target answered HTTP %d (Retry-After %s) at preflight; wait before retrying", resp.Status, retry)
		}
		return fmt.Sprintf("target answered HTTP %d (backpressure/unavailable) at preflight; wait before retrying", resp.Status)
	case captcha && strings.Contains(strings.ToLower(label), "cloudflare"):
		return fmt.Sprintf("%s challenge page at preflight; Indago does not solve or bypass CAPTCHAs — wait for the challenge/cooldown window", label)
	case mitigated == "challenge" || mitigated == "managed_challenge":
		return "target marked the preflight as a bot challenge (CF-Mitigated: " + mitigated + "); wait before retrying"
	case (resp.Status == http.StatusForbidden || resp.Status == http.StatusNotAcceptable) && vendor != "":
		return fmt.Sprintf("%s rejected the preflight with HTTP %d; wait for the WAF/cooldown window before retrying", vendor, resp.Status)
	}
	return ""
}

// wafVendor returns a short vendor label when response headers identify an
// edge/WAF. CF-Ray alone is common on a normal Cloudflare response, so callers
// only use this together with a block status or a challenge signal.
func wafVendor(h http.Header) string {
	lower := make(map[string]string, len(h))
	for k, v := range h {
		lower[strings.ToLower(k)] = strings.ToLower(strings.Join(v, " "))
	}
	if _, ok := lower["cf-ray"]; ok {
		return "Cloudflare"
	}
	if _, ok := lower["cf-mitigated"]; ok {
		return "Cloudflare"
	}
	if strings.Contains(lower["server"], "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(lower["server"], "akamai") || hasHeaderPrefix(lower, "x-akamai-") {
		return "Akamai"
	}
	if hasHeaderPrefix(lower, "x-sucuri") {
		return "Sucuri"
	}
	if strings.Contains(lower["server"], "imperva") || hasHeaderPrefix(lower, "x-iinfo") {
		return "Imperva"
	}
	for _, name := range []string{"x-waf", "x-firewall", "x-protected-by"} {
		if _, ok := lower[name]; ok {
			return "WAF"
		}
	}
	return ""
}

func hasHeaderPrefix(h map[string]string, prefix string) bool {
	for k := range h {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

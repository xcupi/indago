package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

const (
	domOpenRedirectConsolePrefix = "__INDAGO_DOM_REDIRECT__"
	domOpenRedirectMaxSelectors  = 3
)

type domOpenRedirectReport struct {
	Sink   string `json:"sink"`
	Target string `json:"target"`
}

func parseDOMOpenRedirectReports(msgs []browser.ConsoleMessage) []domOpenRedirectReport {
	var out []domOpenRedirectReport
	for _, m := range msgs {
		if !strings.HasPrefix(m.Text, domOpenRedirectConsolePrefix) {
			continue
		}
		var rep domOpenRedirectReport
		if json.Unmarshal([]byte(strings.TrimPrefix(m.Text, domOpenRedirectConsolePrefix)), &rep) == nil && rep.Target != "" {
			out = append(out, rep)
		}
	}
	return out
}

// domXSSHasRedirectLink is a narrow, static gate for the client-side redirect
// probe: a link whose onclick both reads a url= value and writes location.
func domXSSHasRedirectLink(html string) bool {
	low := strings.ToLower(html)
	return strings.Contains(low, "onclick") && strings.Contains(low, "url=") && strings.Contains(low, "location")
}

// probeDOMOpenRedirectForQuery runs bounded DOM open-redirect probing for the
// query source: both inline onclick redirect handlers and static/discovered
// query parameters that may reach location.href / location.assign /
// location.replace / window.open, without ever following a redirect out of
// scope.
func (e *domXSSExecutor) probeDOMOpenRedirectForQuery(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker string, pageScripts domXSSPageScripts, selectors []domXSSQuerySelector) {
	if domXSSHasRedirectLink(pageScripts.HTML) || len(detection.DOMOpenRedirectOnclickParams(pageScripts.HTML)) > 0 {
		if e.probeClientOpenRedirect(ctx, bctx, job, ep, marker, pageScripts.HTML) {
			return
		}
	}

	sites := detection.DOMOpenRedirectStaticSites(pageScripts.HTML, ep.URL, pageScripts.Scripts)
	if len(sites) == 0 {
		return
	}

	// Collect bounded query parameter names from static sites and discovered selectors.
	var params []string
	seen := make(map[string]struct{})
	addParam := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		params = append(params, p)
	}
	for _, s := range sites {
		if s.Source == detection.DOMSourceQuery && s.Param != "" {
			addParam(s.Param)
		}
	}
	for _, sel := range selectors {
		addParam(sel.Name)
	}
	if len(params) > domOpenRedirectMaxSelectors {
		params = params[:domOpenRedirectMaxSelectors]
	}
	for _, param := range params {
		if e.probeDOMOpenRedirectSource(ctx, bctx, job, ep, detection.DOMSourceQuery, param, marker) {
			return
		}
	}
}

// probeDOMOpenRedirectSource tests one (source, param) pair with the reserved
// non-resolvable canary.invalid URLs. The browser harness intercepts any
// assignment to canary.invalid without navigating out of scope.
func (e *domXSSExecutor) probeDOMOpenRedirectSource(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, source detection.DOMXSSSource, queryParam, marker string) bool {
	payloads := detection.DOMOpenRedirectPayloads(marker)
	for _, canary := range payloads {
		obs, navURL, err := e.navigateSource(ctx, bctx, source, ep, queryParam, marker, canary)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			continue
		}
		reports := parseDOMOpenRedirectReports(obs.Console)
		for _, rep := range reports {
			if !detection.IsDOMOpenRedirectTarget(rep.Target, marker, ep.URL) {
				continue
			}
			tc := e.newTestCase(ctx, job, navURL)
			evIDs, _ := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, obs.Screenshot, obs.HTML, []string{
				fmt.Sprintf("open redirect sink %s target: %s", rep.Sink, rep.Target),
			})
			detail, _ := json.Marshal(map[string]any{
				"source":        string(source),
				"sink":          rep.Sink,
				"param":         queryParam,
				"target":        rep.Target,
				"canary":        canary,
				"test_case_ids": []domain.ID{tc.ID},
			})
			f := &domain.Finding{
				ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
				VulnClass: domain.VulnOpenRedirect, Verdict: domain.VerdictConfirmed,
				Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh,
				Title:      "DOM open redirect: client-side navigation accepts an attacker-controlled external URL",
				Summary:    fmt.Sprintf("The %s source flowed into %s and attempted to redirect to %s (intercepted in-scope without following).", source, rep.Sink, rep.Target),
				EndpointID: ep.ID, EvidenceIDs: evIDs,
				Provenance: domain.Provenance{Engine: "dom-open-redirect", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
				Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}
			tc.Status = domain.TestCaseCompleted
			if err := e.store.Findings().Create(ctx, f); err != nil {
				e.finishTestCase(ctx, tc, err, "dom open-redirect probe: create finding")
				return false
			}
			e.finishTestCase(ctx, tc, nil, fmt.Sprintf("confirmed: %s assigned external target %s to %s (not followed)", source, rep.Target, rep.Sink))
			return true
		}
	}
	return false
}

// probeClientOpenRedirect executes the page's own onclick handler with a fake
// location object, so the handler's real regex/assignment runs without a
// navigation. A destination containing the marker on canary.invalid is
// execution of attacker-controlled redirect logic, not a text match.
func (e *domXSSExecutor) probeClientOpenRedirect(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker, pageHTML string) bool {
	canary := detection.DOMOpenRedirectCanaryURL(marker)
	paramNames := detection.DOMOpenRedirectOnclickParams(pageHTML)
	if len(paramNames) == 0 {
		paramNames = []string{"url"}
	}
	if len(paramNames) > domOpenRedirectMaxSelectors {
		paramNames = paramNames[:domOpenRedirectMaxSelectors]
	}

	for _, paramName := range paramNames {
		navURL := domXSSQueryURL(ep.URL, paramName, canary)
		tc := e.newTestCase(ctx, job, navURL)
		page, err := bctx.NewPage(ctx)
		if err != nil {
			e.finishTestCase(ctx, tc, err, "open-redirect probe: new page")
			return false
		}
		if _, err := page.Navigate(ctx, navURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
			page.Close()
			e.finishTestCase(ctx, tc, err, "open-redirect probe: navigate")
			continue
		}
		script := `(() => {
  const links = [...document.querySelectorAll('a[onclick], button[onclick]')];
  for (const link of links) {
    const handler = link.getAttribute('onclick') || '';
    if (!/(?:location|open\s*\()/i.test(handler)) continue;
    const fake = {href: location.href, assign(u) { this.href = u; }, replace(u) { this.href = u; }, toString() { return this.href; }};
    try {
      new Function('location', handler).call(window, fake);
    } catch (err) {
      if (fake.href !== location.href) return {found: true, error: String(err), target: String(fake.href)};
      continue;
    }
    if (fake.href !== location.href) return {found: true, target: String(fake.href)};
  }
  return {found: false};
})()`
		raw, err := page.Evaluate(ctx, script)
		if err != nil {
			page.Close()
			e.finishTestCase(ctx, tc, err, "open-redirect probe: evaluate")
			continue
		}
		res, _ := raw.(map[string]any)
		found, _ := res["found"].(bool)
		target, _ := res["target"].(string)
		if !found || !detection.IsDOMOpenRedirectTarget(target, marker, ep.URL) {
			page.Close()
			e.finishTestCase(ctx, tc, nil, "open-redirect probe: the page's handlers did not assign the supplied external target")
			continue
		}
		html, _ := page.Content(ctx)
		shot, _ := page.Screenshot(ctx, browser.ScreenshotOptions{})
		page.Close()
		evIDs, _ := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, html, []string{"open redirect target: " + target})
		detail, _ := json.Marshal(map[string]any{
			"source": "dom_link_onclick", "param": paramName, "target": target, "canary": canary,
			"test_case_ids": []domain.ID{tc.ID},
		})
		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
			VulnClass: domain.VulnOpenRedirect, Verdict: domain.VerdictConfirmed,
			Severity: domain.SeverityMedium, Confidence: domain.ConfidenceHigh,
			Title:      "Open redirect: a link on the page sends the user to an attacker-controlled URL",
			Summary:    "The page's own click handler took the " + paramName + " parameter and assigned it to location, so a trusted link can redirect to " + target + ".",
			EndpointID: ep.ID, EvidenceIDs: evIDs,
			Provenance: domain.Provenance{Engine: "dom-open-redirect", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
			Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		tc.Status = domain.TestCaseCompleted
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.finishTestCase(ctx, tc, err, "open-redirect probe: create finding")
			return false
		}
		e.finishTestCase(ctx, tc, nil, "confirmed: the page's onclick assigned the supplied external target to location: "+target)
		return true
	}
	return false
}

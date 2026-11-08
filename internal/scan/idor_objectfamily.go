package scan

// Case 34: an object the scan CREATES tells us where its siblings live.
//
// The IDOR differential needs an identifier to vary. Some endpoints never take
// one: they mint it. The chat page's own script posts a transcript to
// /download-transcript and the response redirects to /download-transcript/2.txt
// — the caller's own object. The neighbours' identifiers are then the arithmetic
// around that number, which the application itself named.
//
// Everything here is derived from the page's own bytes (inline and linked
// scripts); no wordlist is involved. The probe is opt-in because the first
// request POSTs a document the scan authored.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
)

const (
	idorModeObjectFamily = "object_family"

	// maxObjectFamilyScripts bounds how many linked scripts one page may add.
	maxObjectFamilyScripts = 3
	// maxObjectFamilyPaths bounds the endpoint literals tried per page.
	maxObjectFamilyPaths = 3
)

var (
	scriptSrcRE   = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	quotedPathRE  = regexp.MustCompile(`["'](/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{0,63})["']`)
	formAppendRE  = regexp.MustCompile(`\.append\(\s*["']([A-Za-z_][A-Za-z0-9_\-]{0,31})["']\s*,`)
	assetPathRE   = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?)$`)
	assetPrefixes = []string{"/resources/", "/image/", "/images/", "/static/", "/assets/", "/favicon"}
)

// scriptURLs returns the same-origin script sources referenced by a page,
// bounded.
func scriptURLs(body string) []string {
	var out []string
	for _, m := range scriptSrcRE.FindAllStringSubmatch(body, maxObjectFamilyScripts*2) {
		src := strings.TrimSpace(m[1])
		if src == "" || strings.Contains(src, "..") {
			continue
		}
		out = append(out, src)
		if len(out) >= maxObjectFamilyScripts {
			break
		}
	}
	return out
}

// objectFamilyField finds a form field name the page's scripts append to a
// FormData body (data.append("transcript", …)).
func objectFamilyField(scriptText string) string {
	m := formAppendRE.FindStringSubmatch(scriptText)
	if m == nil {
		return ""
	}
	name := m[1]
	switch strings.ToLower(name) {
	case "file", "csrf", "token", "_token":
		return "" // uploads and anti-CSRF fields are not free text
	}
	return name
}

// objectFamilyPaths returns the endpoint-looking literals in the page's scripts:
// a rooted path the scripts POST to, never a static asset.
func objectFamilyPaths(scriptText string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range quotedPathRE.FindAllStringSubmatch(scriptText, 64) {
		p := m[1]
		if seen[p] || assetPathRE.MatchString(p) {
			continue
		}
		skip := false
		for _, prefix := range assetPrefixes {
			if strings.HasPrefix(strings.ToLower(p), prefix) {
				skip = true
				break
			}
		}
		if skip || strings.Contains(p, "//") || strings.Trim(p, "/") == "" {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= maxObjectFamilyPaths {
			break
		}
	}
	return out
}

func idorModePayload(mode string) []byte {
	b, _ := json.Marshal(map[string]string{"mode": mode})
	return b
}

func idorPayloadMode(job *domain.TestJob) string {
	var p struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(job.Payload, &p)
	return p.Mode
}

// runObjectFamily implements case 34. It is driven by ONE page: the page's own
// scripts say where the object is created and which field carries it.
func (e *idorExecutor) runObjectFamily(ctx context.Context, job *domain.TestJob, tc *domain.TestCase) (idorDetail, domain.TestOutcome, error, bool, bool) {
	d := idorDetail{Engine: "idor", ObjectFamily: true}
	tc.Method, tc.URL = "GET", job.Target.URL

	pageURL, err := url.Parse(strings.TrimSpace(job.Target.URL))
	if err != nil || pageURL.Host == "" {
		d.Skipped, d.SkipReason = true, "object-family job has no usable page URL"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	origin := pageURL.Scheme + "://" + pageURL.Host

	pageResp, outcome, reqErr, _ := e.send(ctx, httpengine.GET(job.Target.URL))
	if outcome != domain.OutcomeSuccess {
		d.Skipped, d.SkipReason = true, "the page could not be fetched: "+truncate(errText(reqErr), 120)
		return d, domain.OutcomeSuccess, nil, false, true
	}

	scriptText := string(pageResp.Body)
	for _, src := range scriptURLs(string(pageResp.Body)) {
		abs := src
		if strings.HasPrefix(src, "/") {
			abs = origin + src
		}
		resp, out, _, _ := e.send(ctx, httpengine.GET(abs))
		if out == domain.OutcomeSuccess {
			scriptText += "\n" + string(resp.Body)
		}
	}

	field := objectFamilyField(scriptText)
	if field == "" {
		d.Skipped, d.SkipReason = true, "the page's scripts name no free-text form field to submit"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	paths := objectFamilyPaths(scriptText)
	if len(paths) == 0 {
		d.Skipped, d.SkipReason = true, "the page's scripts name no endpoint to submit to"
		return d, domain.OutcomeSuccess, nil, false, true
	}
	d.ObjectField = field

	marker := "indago-objfamily-" + domain.NewID().String()[:8]
	for _, p := range paths {
		if ctx.Err() != nil {
			return d, domain.OutcomeCancelled, ctx.Err(), false, false
		}
		target := origin + p
		req := httpengine.NewRequest("POST", target)
		req.NoRedirects = true
		req.Headers = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		req.Body = []byte(url.Values{field: {marker}}.Encode())
		resp, out, _, _ := e.send(ctx, req)
		if out != domain.OutcomeSuccess {
			continue
		}
		if resp.Status < 300 || resp.Status >= 400 {
			continue
		}
		loc := strings.TrimSpace(resp.Headers.Get("Location"))
		if loc == "" {
			continue
		}
		abs := loc
		if strings.HasPrefix(loc, "/") {
			abs = origin + loc
		}
		fam, ok := idor.ParseObjectFamily(abs)
		if !ok || fam.Base != p {
			continue
		}
		d.FamilyBase, d.OwnObject = fam.Base, abs
		d.CreateStatus = resp.Status

		// The caller's own object must carry the marker: proof the scan made it.
		ownResp, ownOut, _, _ := e.send(ctx, httpengine.GET(abs))
		if ownOut != domain.OutcomeSuccess || ownResp.Status != 200 {
			continue
		}
		if !strings.Contains(string(ownResp.Body), marker) {
			continue
		}
		if ids, evErr := e.persistPair(ctx, tc, ownResp, "object-family own object"); evErr == nil {
			tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
		}

		for _, sib := range fam.Siblings() {
			if ctx.Err() != nil {
				return d, domain.OutcomeCancelled, ctx.Err(), false, false
			}
			sibURL := fam.URLAt(origin, sib)
			sibResp, sibOut, _, _ := e.send(ctx, httpengine.GET(sibURL))
			if sibOut != domain.OutcomeSuccess {
				continue
			}
			var evIDs []domain.ID
			if ids, evErr := e.persistPair(ctx, tc, sibResp, fmt.Sprintf("object-family sibling %d", sib)); evErr == nil {
				evIDs = ids
				tc.EvidenceIDs = appendUniqueIDs(tc.EvidenceIDs, ids)
			}
			dec := idor.ObjectFamilyDecision(ownResp.Body, abs, sib, sibURL, sibResp.Status, sibResp.Body, marker)
			d.Attempts = append(d.Attempts, idorAttempt{
				Candidate: fmt.Sprintf("%d", sib), Source: "object_family", URL: sibURL,
				Status: sibResp.Status, Outcome: string(dec.Outcome), Reason: dec.Reason, EvidenceIDs: evIDs,
			})
			if dec.Outcome != idor.OutcomeConfirmed {
				continue
			}
			d.Verdict = domain.VerdictConfirmed
			d.Reason = dec.Reason
			e.createObjectFamilyFinding(ctx, job, tc, d, sibURL)
			return d, domain.OutcomeSuccess, nil, false, false
		}
		d.Verdict = domain.VerdictRejected
		d.Reason = fmt.Sprintf("the created object %s has no sibling that disclosed a credential", abs)
		return d, domain.OutcomeSuccess, nil, false, false
	}

	d.Verdict = domain.VerdictRejected
	d.Reason = "no script-named endpoint answered with a redirect to an object family"
	return d, domain.OutcomeSuccess, nil, false, false
}

func (e *idorExecutor) createObjectFamilyFinding(ctx context.Context, job *domain.TestJob, tc *domain.TestCase, d idorDetail, siblingURL string) {
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	sc, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		e.log.Warn("load scan for object-family finding", "scan", job.ScanID, "err", err)
		return
	}
	now := time.Now()
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: sc.ProjectID, VulnClass: domain.VulnIDOR,
		Verdict: domain.VerdictConfirmed, Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:       fmt.Sprintf("IDOR: object family at %s exposes another principal's document", truncate(d.FamilyBase, 80)),
		Summary:     d.Reason,
		EndpointID:  job.Target.EndpointID,
		EvidenceIDs: appendUniqueIDs(nil, tc.EvidenceIDs),
		Provenance:  domain.Provenance{Engine: "idor", DiscoverySource: domain.SourceCrawler, DetectedAt: now, AIAssisted: false},
		Detail:      encodeIDORDetail(d),
		CreatedAt:   now, UpdatedAt: now,
	}
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("create object-family finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueObjectFamilyProbes queues ONE job per discovered HTML page when the
// scan opted in; the probe itself is bounded (scripts, paths, siblings).
func (c *Controller) enqueueObjectFamilyProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil {
		return
	}
	// Same rule as cases 35/36: the server's -allow-state-changing authorizes
	// the POST that creates the caller's own object, and the per-scan flag
	// remains for a server that has not been started with it.
	if !sc.Config.EnableObjectFamilyProbe && !c.opts.Executor.AllowStateChanging {
		return
	}
	if !c.idorCallerIdentity(ctx, sc) {
		return
	}
	endpoints, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		c.log.Warn("object-family probe: list endpoints", "scan", scanID, "err", err)
		return
	}
	now := time.Now()
	n := 0
	for _, ep := range endpoints {
		if ep.Method != domain.MethodGET {
			continue
		}
		// Pages only: a static asset cannot name the endpoint that creates an
		// object. Discovery does not always record Content-Type, so the
		// extension is what separates a page from its assets here.
		if assetPathRE.MatchString(strings.ToLower(ep.URL)) {
			continue
		}
		if strings.Contains(ep.URL, "?") {
			continue // a parameterised page is not where an object is minted
		}
		job := &domain.TestJob{
			ID: domain.NewID(), ScanID: scanID, Type: domain.JobIDOR, State: domain.JobQueued,
			Priority: 26, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			Payload:     idorModePayload(idorModeObjectFamily),
			MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			continue
		}
		n++
		if n >= 12 { // hard bound per scan
			break
		}
	}
	if n > 0 {
		c.log.Info("object-family probe: enqueued", "scan", scanID, "jobs", n)
	}
}

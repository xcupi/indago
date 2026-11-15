package scan

// Tests for the response-driven half of the bounded automatic filter-bypass
// pass: the seam in waf_escalation.go that feeds stored canonical
// request/response evidence through AnalyzeResponseAdaptation and uses the
// resulting tactics to (re)order the documented bypass shapes, veto a throttled
// point, and record the observed WAF/sanitization signals.
//
// Everything asserted here is data the scan already stored: no test sends a
// request, and every suggested payload is still the same benign-marker breakout
// the evasion planner produced.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// --- fixtures ---------------------------------------------------------------

// storeEvasionResponse persists one response the way the executor does: an
// HTTP/1.1 dump blob plus an evidence row, returning the row's ID.
func storeEvasionResponse(t *testing.T, env *scanEnv, status int, headers map[string]string, body string) domain.ID {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s: %s\r\n", name, headers[name])
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	ref, err := env.ev.Put(env.scanID, domain.EvidenceResponse, ".http", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	ev := &domain.Evidence{
		ID: domain.NewID(), ScanID: env.scanID, Kind: domain.EvidenceResponse,
		BlobPath: ref.BlobPath, Size: ref.Size, SHA256: ref.SHA256, CreatedAt: time.Now(),
	}
	if err := env.st.Evidence().Create(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

// adaptationParent persists the reflection parent job + test case for a plan
// made of the given canonical candidates. Unlike escalationParent it lets a
// test choose the exact canonical payload, which is what fixes the probe shape
// the response-driven analyzer compares against.
func adaptationParent(t *testing.T, env *scanEnv, q queue.Queue, ep *domain.Endpoint, ip *domain.InjectionPoint, canonical ...detection.Candidate) *detection.ReflectionReport {
	t.Helper()
	probe := detection.NewProbe(env.scanID, ip.ID)
	body := []byte("<p>" + probe.Value() + "</p>")
	rep := detection.AnalyzeReflection(probe, nil, body)
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	detection.ClassifyContexts(&rep, body, detection.ContextOptions{ContentType: "text/html"})
	rep.Plan = &detection.CandidatePlan{Source: detection.SourceBuiltin, Marker: probe.Token, Candidates: canonical}
	if rep.Plan == nil || len(rep.Plan.Candidates) == 0 {
		t.Fatal("setup: no canonical candidates")
	}

	parent := &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobTest,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID}, MaxAttempts: 3,
	}
	completedEscalationJob(t, q, env.scanID, parent)

	detail, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := env.st.TestCases().Create(context.Background(), &domain.TestCase{
		ID: domain.NewID(), ScanID: env.scanID, JobID: parent.ID, InjectionPointID: ip.ID,
		VulnClass: domain.VulnReflectedXSS, Status: domain.TestCaseCompleted,
		Outcome: domain.OutcomeSuccess, Detail: detail, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return &rep
}

// adaptationCandidateCase leaves behind exactly what a real canonical candidate
// run persists: the succeeded child job, its completed TestCase, and a candidate
// reflection report whose Evidence points at the stored baseline and probe
// response blobs.
func adaptationCandidateCase(t *testing.T, env *scanEnv, q queue.Queue, ep *domain.Endpoint, ip *domain.InjectionPoint, cand detection.Candidate,
	baselineStatus int, baselineBody string, probeStatus int, probeHeaders map[string]string, probeBody string) *domain.TestJob {
	t.Helper()
	probe := detection.NewProbe(env.scanID, ip.ID)
	rep := detection.AnalyzeReflection(probe, nil, []byte(probeBody))
	rep.Parameter = "q"
	rep.Location = domain.LocationQuery
	rep.Baseline = detection.ResponseSummary{Status: baselineStatus, BodyLen: len(baselineBody)}
	rep.Mutated = detection.ResponseSummary{Status: probeStatus, BodyLen: len(probeBody)}
	rep.Candidate = &cand
	rep.Evidence = detection.ReflectionEvidence{
		BaselineResponse: storeEvasionResponse(t, env, baselineStatus, map[string]string{"Content-Type": "text/html"}, baselineBody),
		MutatedResponse:  storeEvasionResponse(t, env, probeStatus, probeHeaders, probeBody),
	}

	job := canonicalCandidateJob(t, env, ep, ip, cand)
	completedEscalationJob(t, q, env.scanID, job)

	detail, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := env.st.TestCases().Create(context.Background(), &domain.TestCase{
		ID: domain.NewID(), ScanID: env.scanID, JobID: job.ID, InjectionPointID: ip.ID,
		VulnClass: domain.VulnReflectedXSS, Status: domain.TestCaseCompleted,
		Outcome: domain.OutcomeSuccess, Detail: detail, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return job
}

// techniqueJobRecord is one enqueued automatic bypass job with its decoded
// payload, so a test can assert both what was planned and why.
type techniqueJobRecord struct {
	job   *domain.TestJob
	cand  detection.Candidate
	adapt *evasionAdaptation
}

// techniqueJobs returns the automatic pass's jobs, highest queue priority
// first (ties keep queue order, as the worker pool would lease them).
func techniqueJobs(t *testing.T, q queue.Queue, scanID domain.ID) []techniqueJobRecord {
	t.Helper()
	jobs, err := q.Jobs(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	var out []techniqueJobRecord
	for _, job := range jobs {
		if len(job.Payload) == 0 {
			continue
		}
		var cj candidateJob
		if err := json.Unmarshal(job.Payload, &cj); err != nil || cj.Candidate.Technique == "" {
			continue
		}
		out = append(out, techniqueJobRecord{job: job, cand: cj.Candidate, adapt: cj.Adaptation})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].job.Priority > out[j].job.Priority })
	return out
}

func techniqueByTechnique(records []techniqueJobRecord, technique string) (techniqueJobRecord, bool) {
	for _, rec := range records {
		if rec.cand.Technique == technique {
			return rec, true
		}
	}
	return techniqueJobRecord{}, false
}

func scriptTagCandidate(env *scanEnv, ip *domain.InjectionPoint) detection.Candidate {
	token := detection.NewProbe(env.scanID, ip.ID).Token
	return detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText,
		Context: detection.CtxHTMLText, Trigger: detection.TriggerLoad,
		Value: "<script>" + token + "</script>", Transformation: "raw",
		Priority: 90, DedupKey: "canonical-script-" + token,
	}
}

func svgOnloadCandidate(env *scanEnv, ip *domain.InjectionPoint) detection.Candidate {
	token := detection.NewProbe(env.scanID, ip.ID).Token
	return detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLText,
		Context: detection.CtxHTMLText, Trigger: detection.TriggerLoad,
		Value: "<svg onload=" + token + ">", Transformation: "raw",
		Priority: 90, DedupKey: "canonical-svg-" + token,
	}
}

// --- stripped tags ------------------------------------------------------------

// A canonical <script> probe came back with only its marker: the response
// proves the tag name is stripped, so the svg/onload shapes must be sent (and
// verified) first instead of the planner's default order, and the evidence must
// be recorded on the jobs.
func TestWAFEscalation_PrioritizesShapesAfterStrippedScriptTag(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()

	cand := scriptTagCandidate(env, ip)
	adaptationParent(t, env, q, ep, ip, cand)
	token := detection.NewProbe(env.scanID, ip.ID).Token
	// The marker is echoed inside a paragraph; the <script> wrapper is gone.
	adaptationCandidateCase(t, env, q, ep, ip, cand, 200, "<p>baseline</p>", 200,
		map[string]string{"Content-Type": "text/html"}, "<p>"+token+"</p>")

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

	records := techniqueJobs(t, q, env.scanID)
	if len(records) < 2 {
		t.Fatalf("stripped <script> enqueued %d bypass shapes, want the bounded pass", len(records))
	}
	for _, rec := range records {
		if rec.adapt == nil {
			t.Fatalf("bypass job %q carries no response-adaptation metadata", rec.cand.DedupKey)
		}
		if !adaptContainsString(rec.adapt.Sanitized, "script_tag") {
			t.Fatalf("job %q recorded sanitized=%v, want script_tag", rec.cand.DedupKey, rec.adapt.Sanitized)
		}
		if !adaptContainsString(rec.adapt.Tactics, "html_event_handler_svg") {
			t.Fatalf("job %q recorded tactics=%v, want html_event_handler_svg", rec.cand.DedupKey, rec.adapt.Tactics)
		}
	}
	if records[0].adapt.Probes != 1 {
		t.Fatalf("analysed %d probes, want 1", records[0].adapt.Probes)
	}

	// <svG OnLoad> is the first documented shape that still carries the svg
	// element + onload handler the response kept in the marker echo.
	if records[0].cand.Technique != "case_variation" {
		t.Fatalf("highest-priority shape = %q (%d), want case_variation (%d)",
			records[0].cand.Technique, records[0].job.Priority, records[0].cand.Priority)
	}
	if !adaptContainsString(records[0].adapt.Matched, "html_event_handler_svg") {
		t.Fatalf("case_variation recorded matched=%v, want html_event_handler_svg", records[0].adapt.Matched)
	}
	if records[0].job.Priority <= records[0].cand.Priority {
		t.Fatalf("response-driven shape was not prioritized: job priority %d <= planned %d",
			records[0].job.Priority, records[0].cand.Priority)
	}

	// A shape that keeps the stripped primitive (or names no suggested
	// primitive at all) must not outrank the matched ones.
	alt, ok := techniqueByTechnique(records, "alt_separator")
	if !ok {
		t.Fatal("alt_separator shape missing from the bounded pass")
	}
	if alt.job.Priority >= records[0].job.Priority {
		t.Fatalf("alt_separator (%d) outranked the matched case_variation (%d)", alt.job.Priority, records[0].job.Priority)
	}
	focus, ok := techniqueByTechnique(records, "custom_element_focus")
	if ok && focus.job.Priority >= records[0].job.Priority {
		t.Fatalf("custom_element_focus (%d) outranked the matched case_variation (%d)", focus.job.Priority, records[0].job.Priority)
	}
}

// A canonical <svg onload> probe came back with the handler attribute removed:
// switching handler family is the documented advice, so the onfocus shape must
// lead — not another onload shape.
func TestWAFEscalation_PrioritizesAlternativeHandlerAfterHandlerStrip(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()

	cand := svgOnloadCandidate(env, ip)
	adaptationParent(t, env, q, ep, ip, cand)
	token := detection.NewProbe(env.scanID, ip.ID).Token
	adaptationCandidateCase(t, env, q, ep, ip, cand, 200, "<p>baseline</p>", 200,
		map[string]string{"Content-Type": "text/html"}, "<p>"+token+"</p>")

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

	records := techniqueJobs(t, q, env.scanID)
	if len(records) < 2 {
		t.Fatalf("stripped handler enqueued %d bypass shapes, want the bounded pass", len(records))
	}
	for _, rec := range records {
		if rec.adapt == nil || !adaptContainsString(rec.adapt.Sanitized, "event_handler:onload") {
			t.Fatalf("job %q recorded sanitized=%v, want event_handler:onload", rec.cand.DedupKey, rec.adapt.Sanitized)
		}
	}
	if records[0].cand.Technique != "custom_element_focus" {
		t.Fatalf("highest-priority shape = %q, want custom_element_focus (onfocus)", records[0].cand.Technique)
	}
	if !adaptContainsString(records[0].adapt.Matched, "html_event_handler_onfocus") {
		t.Fatalf("onfocus shape recorded matched=%v, want html_event_handler_onfocus", records[0].adapt.Matched)
	}

	// The shape that re-sends the stripped onload handler must rank below it.
	onload, ok := techniqueByTechnique(records, "case_variation")
	if !ok {
		t.Fatal("case_variation shape missing from the bounded pass")
	}
	if onload.job.Priority >= records[0].job.Priority {
		t.Fatalf("an onload shape (%d) outranked the onfocus shape (%d)", onload.job.Priority, records[0].job.Priority)
	}
	if adaptContainsString(onload.adapt.Matched, "html_event_handler_onfocus") {
		t.Fatalf("onload shape wrongly recorded a handler-switch match: %v", onload.adapt.Matched)
	}
}

// --- blocked responses --------------------------------------------------------

// A 403 block page naming the WAF: the vendor and block signal must be recorded
// on every enqueued job, and the block-specific shape tactics must drive the
// ordering.
func TestWAFEscalation_RecordsWAFVendorOnBlockedResponse(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()

	cand := svgOnloadCandidate(env, ip)
	adaptationParent(t, env, q, ep, ip, cand)
	adaptationCandidateCase(t, env, q, ep, ip, cand, 200, "<p>baseline</p>", 403,
		map[string]string{"Server": "ModSecurity"}, "Request blocked by ModSecurity")

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

	records := techniqueJobs(t, q, env.scanID)
	if len(records) == 0 {
		t.Fatal("a 403 filter rejection must still get the bounded bypass pass")
	}
	for _, rec := range records {
		if rec.adapt == nil {
			t.Fatalf("job %q carries no response-adaptation metadata", rec.cand.DedupKey)
		}
		if rec.adapt.WAFVendor != "ModSecurity" {
			t.Fatalf("job %q recorded waf_vendor=%q, want ModSecurity", rec.cand.DedupKey, rec.adapt.WAFVendor)
		}
		if !rec.adapt.Blocked || rec.adapt.BlockSignal != "modsecurity" {
			t.Fatalf("job %q recorded blocked=%v signal=%q, want true/modsecurity",
				rec.cand.DedupKey, rec.adapt.Blocked, rec.adapt.BlockSignal)
		}
		if !adaptContainsString(rec.adapt.Tactics, "html_case_variation") {
			t.Fatalf("job %q recorded tactics=%v, want the block shape set", rec.cand.DedupKey, rec.adapt.Tactics)
		}
	}
	if records[0].cand.Technique != "case_variation" {
		t.Fatalf("highest-priority shape = %q, want case_variation", records[0].cand.Technique)
	}
	if !adaptContainsString(records[0].adapt.Matched, "html_case_variation") {
		t.Fatalf("case_variation recorded matched=%v, want html_case_variation", records[0].adapt.Matched)
	}
	// The unrelated allow-list body/onresize shape is not what a block-shape
	// suggestion names, so it must rank below the matched ones.
	if rec, ok := techniqueByTechnique(records, "allowlisted_tag_event"); ok && rec.job.Priority >= records[0].job.Priority {
		t.Fatalf("allowlisted_tag_event (%d) outranked the block-matched shape (%d)", rec.job.Priority, records[0].job.Priority)
	}
}

// --- backpressure -------------------------------------------------------------

// A canonical probe answered 429/503 is the target asking for less traffic, not
// a filter decision. No block-diagnostic Finding is persisted here, so this
// proves the veto comes from the probe response itself rather than from
// findingDetail.Throttled.
func TestWAFEscalation_SuppressesEscalationWhenProbeAskedForBackoff(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ctx := context.Background()
			env := newScanEnv(t)
			ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
			p := env.param(ep, "q", domain.LocationQuery, "hello")
			ip := env.injection(ep, p)
			q := queue.NewMemory()

			cand := svgOnloadCandidate(env, ip)
			adaptationParent(t, env, q, ep, ip, cand)
			adaptationCandidateCase(t, env, q, ep, ip, cand, 200, "<p>baseline</p>", status,
				map[string]string{"Content-Type": "text/html"}, "slow down")

			evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

			if got := techniqueJobs(t, q, env.scanID); len(got) != 0 {
				t.Fatalf("HTTP %d (backpressure) was escalated through: %+v", status, got)
			}
		})
	}
}

// A Retry-After on a failed probe is the same request for less traffic.
func TestWAFEscalation_SuppressesEscalationOnRetryAfter(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()

	cand := svgOnloadCandidate(env, ip)
	adaptationParent(t, env, q, ep, ip, cand)
	adaptationCandidateCase(t, env, q, ep, ip, cand, 200, "<p>baseline</p>", 403,
		map[string]string{"Content-Type": "text/html", "Retry-After": "120"}, "request rejected")

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

	if got := techniqueJobs(t, q, env.scanID); len(got) != 0 {
		t.Fatalf("a Retry-After answer was escalated through: %+v", got)
	}
}

// --- analysis / ranking units -------------------------------------------------

func TestWAFEscalationShapeMatching(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		category detection.CandidateCategory
		tactic   EvasionTactic
		want     int
	}{
		{
			name: "same handler family matches", value: "<svg/onload=mk>", category: detection.CatHTMLText,
			tactic: EvasionTactic{ID: "svg", Vector: adaptVectorHTML, Payload: "<svg onload=mk>"},
			want:   evasionMatchHandler,
		},
		{
			name: "different handler family gets no credit", value: "<svg onload=mk>", category: detection.CatHTMLText,
			tactic: EvasionTactic{ID: "onfocus", Vector: adaptVectorHTML, Payload: "<svg tabindex=1 onfocus=mk>"},
			want:   evasionMatchNone,
		},
		{
			name: "handler-less markup matches on element", value: "<svg><a><animate attributeName=href values=javascript:mk /></a></svg>",
			category: detection.CatHTMLText,
			tactic:   EvasionTactic{ID: "svg", Vector: adaptVectorHTML, Payload: "<svg onload=mk>"},
			want:     evasionMatchElement,
		},
		{
			name: "percent-encoded element still recognised", value: "%3Csvg%20onload%3Dmk%3E", category: detection.CatHTMLText,
			tactic: EvasionTactic{ID: "svg", Vector: adaptVectorHTML, Payload: "<svg onload=mk>"},
			want:   evasionMatchHandler,
		},
		{
			name: "js tactic matches a js candidate", value: "';mk//", category: detection.CatJS,
			tactic: EvasionTactic{ID: "js", Vector: adaptVectorJS, Payload: `';{marker}//`},
			want:   evasionMatchVector,
		},
		{
			name: "js tactic ignores an html candidate", value: "<svg onload=mk>", category: detection.CatHTMLText,
			tactic: EvasionTactic{ID: "js", Vector: adaptVectorJS, Payload: `';{marker}//`},
			want:   evasionMatchNone,
		},
		{
			name: "url tactic matches a url candidate", value: "java\tscript:mk", category: detection.CatURL,
			tactic: EvasionTactic{ID: "url", Vector: adaptVectorURL, Payload: "java\tscript:{marker}"},
			want:   evasionMatchVector,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cand := detection.Candidate{Category: tc.category, Value: tc.value}
			if got := evasionTacticMatch(cand, tc.tactic); got != tc.want {
				t.Fatalf("evasionTacticMatch = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWAFEscalationRankingKeepsDocumentedSet(t *testing.T) {
	tactics := []EvasionTactic{
		{ID: "html_event_handler_svg", Vector: adaptVectorHTML, Priority: 62, Payload: "<svg onload=mk>", Trigger: adaptSanScriptTag},
	}
	cands := []detection.Candidate{
		{Technique: "custom_element_focus", Priority: 42, Value: "<x-mk autofocus tabindex=1 onfocus=mk>"},
		{Technique: "case_variation", Priority: 50, Value: "<SvG OnLoad=mk>"},
		{Technique: "alt_separator", Priority: 48, Value: "<svg/onload=mk>"},
	}
	got := rankEvasionCandidatesByAdaptation(cands, evasionAnalysis{
		evasionAdaptation: evasionAdaptation{Probes: 1, Sanitized: []string{adaptSanScriptTag}},
		tactics:           tactics,
	})
	if len(got) != len(cands) {
		t.Fatalf("ranking changed the candidate count: %d -> %d", len(cands), len(got))
	}
	seen := map[string]bool{}
	for _, cand := range got {
		if seen[cand.DedupKey+"|"+cand.Technique] {
			t.Fatalf("ranking duplicated a shape: %+v", cand)
		}
		seen[cand.DedupKey+"|"+cand.Technique] = true
	}
	if got[0].Technique != "case_variation" || got[1].Technique != "alt_separator" || got[2].Technique != "custom_element_focus" {
		gotOrder := []string{got[0].Technique, got[1].Technique, got[2].Technique}
		t.Fatalf("ranking order = %v, want [case_variation alt_separator custom_element_focus]", gotOrder)
	}
	// No tactics available: the planner's order is preserved untouched.
	unchanged := rankEvasionCandidatesByAdaptation(cands, evasionAnalysis{})
	for i := range cands {
		if unchanged[i].Technique != cands[i].Technique {
			t.Fatalf("analysis without tactics reordered the plan: %v", unchanged)
		}
	}
}

func TestWAFEscalationParsesStoredResponseDump(t *testing.T) {
	dump := "HTTP/1.1 403 Forbidden\r\nServer: ModSecurity\r\nContent-Type: text/html\r\n\r\n<html>blocked</html>"
	status, headers, body, ok := parseResponseEvidenceDump([]byte(dump))
	if !ok {
		t.Fatal("stored dump not parsed")
	}
	if status != 403 || headers["Server"] != "ModSecurity" || body != "<html>blocked</html>" {
		t.Fatalf("parsed status=%d headers=%v body=%q", status, headers, body)
	}
	for _, bad := range []string{"", "<html>no status line</html>", "HTTP/1.1 403 Forbidden"} {
		if _, _, _, ok := parseResponseEvidenceDump([]byte(bad)); ok {
			t.Fatalf("refusing malformed dump %q failed", bad)
		}
	}
}

// A point with no stored candidate evidence must keep the planner's exact
// behaviour: same shapes, same priorities, no fabricated metadata.
func TestWAFEscalationWithoutEvidenceKeepsPlannedOrder(t *testing.T) {
	ctx := context.Background()
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", domain.MethodGET)
	p := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, p)
	q := queue.NewMemory()
	_, rep := escalationParent(t, env, q, ep, ip)
	for _, cand := range rep.Plan.Candidates {
		completedCanonicalEscalationJob(t, env, q, ep, ip, cand)
	}

	evasionController(env, q).enqueueEvasionEscalationCandidates(ctx, env.scanID)

	records := techniqueJobs(t, q, env.scanID)
	if len(records) == 0 {
		t.Fatal("no-evidence point did not get the bounded pass")
	}
	for _, rec := range records {
		if rec.adapt != nil {
			t.Fatalf("job %q invented adaptation metadata without evidence", rec.cand.DedupKey)
		}
		if rec.job.Priority != rec.cand.Priority {
			t.Fatalf("job %q priority %d != planned %d", rec.cand.DedupKey, rec.job.Priority, rec.cand.Priority)
		}
	}
}

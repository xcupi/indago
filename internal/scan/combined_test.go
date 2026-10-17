package scan

// Combined (multi-parameter) candidate tests: pair-selection (same-context
// pairing, ceiling enforcement, determinism), the "only when single-param
// already failed" gating, combined-request building, and finding
// correlation/dedup for composite findings.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
)

// --- reflectedSitesFor / selectCombinedPairs (pure pair-selection logic) ---

func siteAt(ip domain.ID, name string, ctx detection.Context, sub string) reflectedSite {
	return reflectedSite{injectionPointID: ip, parameterName: name, location: domain.LocationQuery, context: ctx, contextSub: sub}
}

func TestSelectCombinedPairs_OnlySameContextPairs(t *testing.T) {
	a := siteAt(domain.NewID(), "a", detection.CtxHTMLAttrValue, "double_quoted")
	b := siteAt(domain.NewID(), "b", detection.CtxHTMLAttrValue, "double_quoted")
	c := siteAt(domain.NewID(), "c", detection.CtxJSString, "double_quoted") // different context: must not pair with a/b
	pairs := selectCombinedPairs([]reflectedSite{a, b, c})
	if len(pairs) != 1 {
		t.Fatalf("pairs = %d, want 1 (only a+b share a context)", len(pairs))
	}
	if pairs[0].context != detection.CtxHTMLAttrValue {
		t.Fatalf("pair context = %s, want html_attr_value", pairs[0].context)
	}
	names := map[string]bool{pairs[0].a.parameterName: true, pairs[0].b.parameterName: true}
	if !names["a"] || !names["b"] {
		t.Fatalf("pair = %+v, want {a,b}", pairs[0])
	}
}

func TestSelectCombinedPairs_UnsupportedContextNeverPaired(t *testing.T) {
	a := siteAt(domain.NewID(), "a", detection.CtxHTMLText, "")
	b := siteAt(domain.NewID(), "b", detection.CtxHTMLText, "")
	pairs := selectCombinedPairs([]reflectedSite{a, b})
	if len(pairs) != 0 {
		t.Fatalf("pairs = %d, want 0: html_text is out of this piece's 2-category scope", len(pairs))
	}
}

func TestSelectCombinedPairs_NeverPairsASiteWithItself(t *testing.T) {
	ip := domain.NewID()
	a := siteAt(ip, "a", detection.CtxHTMLAttrValue, "double_quoted")
	// Same injection point ID appearing twice (shouldn't happen in practice,
	// but the guard must hold regardless).
	pairs := selectCombinedPairs([]reflectedSite{a, a})
	if len(pairs) != 0 {
		t.Fatalf("pairs = %d, want 0: a site must never pair with itself", len(pairs))
	}
}

func TestSelectCombinedPairs_NeverATriple(t *testing.T) {
	a := siteAt(domain.NewID(), "a", detection.CtxHTMLAttrValue, "double_quoted")
	b := siteAt(domain.NewID(), "b", detection.CtxHTMLAttrValue, "double_quoted")
	c := siteAt(domain.NewID(), "c", detection.CtxHTMLAttrValue, "double_quoted")
	pairs := selectCombinedPairs([]reflectedSite{a, b, c})
	// 3 sites -> C(3,2) = 3 pairs, never a single 3-way grouping.
	if len(pairs) != 3 {
		t.Fatalf("pairs = %d, want 3 (pairs only, never a triple)", len(pairs))
	}
	for _, p := range pairs {
		if p.a.parameterName == p.b.parameterName {
			t.Fatalf("pair %+v names the same parameter twice", p)
		}
	}
}

func TestSelectCombinedPairs_CeilingEnforced(t *testing.T) {
	// 4 sites in one context -> C(4,2) = 6 possible pairs, exceeding the
	// documented ceiling of 5.
	var sites []reflectedSite
	for _, name := range []string{"p1", "p2", "p3", "p4"} {
		sites = append(sites, siteAt(domain.NewID(), name, detection.CtxHTMLAttrValue, "double_quoted"))
	}
	pairs := selectCombinedPairs(sites)
	if len(pairs) != maxCombinedPairsPerEndpoint {
		t.Fatalf("pairs = %d, want the ceiling %d", len(pairs), maxCombinedPairsPerEndpoint)
	}
}

func TestSelectCombinedPairs_DeterministicRegardlessOfInputOrder(t *testing.T) {
	ip1, ip2, ip3 := domain.NewID(), domain.NewID(), domain.NewID()
	order1 := []reflectedSite{
		siteAt(ip1, "zebra", detection.CtxHTMLAttrValue, "double_quoted"),
		siteAt(ip2, "apple", detection.CtxHTMLAttrValue, "double_quoted"),
		siteAt(ip3, "mango", detection.CtxHTMLAttrValue, "double_quoted"),
	}
	order2 := []reflectedSite{order1[2], order1[0], order1[1]} // same sites, different input order
	p1 := selectCombinedPairs(order1)
	p2 := selectCombinedPairs(order2)
	if len(p1) != len(p2) {
		t.Fatalf("pair count differs by input order: %d vs %d", len(p1), len(p2))
	}
	for i := range p1 {
		if p1[i].a.parameterName != p2[i].a.parameterName || p1[i].b.parameterName != p2[i].b.parameterName {
			t.Fatalf("pair %d differs by input order: %+v vs %+v", i, p1[i], p2[i])
		}
	}
	// Deterministic by parameter name, not input order: "apple" (first
	// alphabetically) must be the "a" half of its pair.
	if p1[0].a.parameterName != "apple" {
		t.Fatalf("first pair's a-half = %q, want the alphabetically-first name \"apple\"", p1[0].a.parameterName)
	}
}

// --- reflectedSitesFor: derives sites purely from already-recorded Findings ---

func combinedTestFinding(scanID, epID, ipID domain.ID, paramName string, loc domain.ParamLocation, cat detection.CandidateCategory, ctx detection.Context, sub string) *domain.Finding {
	d := findingDetail{
		ParameterName: paramName, DedupKey: "k-" + paramName,
		Candidates: []detection.Candidate{{Category: cat, Context: ctx, ContextSub: sub, Value: "v"}},
	}
	return &domain.Finding{
		ID: domain.NewID(), ScanID: scanID, EndpointID: epID, InjectionPointID: ipID,
		VulnClass: domain.VulnReflectedXSS, Verdict: domain.VerdictPending, Location: loc,
		Detail: d.encode(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func TestReflectedSitesFor_SkipsDiagnosticsAndAlreadyCombined(t *testing.T) {
	scanID, epID := domain.NewID(), domain.NewID()
	real := combinedTestFinding(scanID, epID, domain.NewID(), "q", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")

	blockD := findingDetail{ParameterName: "q", DedupKey: "block", BlockSuspected: true}
	block := &domain.Finding{ID: domain.NewID(), ScanID: scanID, EndpointID: epID, VulnClass: domain.VulnReflectedXSS, Detail: blockD.encode()}

	captchaD := findingDetail{ParameterName: "q", DedupKey: "captcha", CaptchaSuspected: true}
	captcha := &domain.Finding{ID: domain.NewID(), ScanID: scanID, EndpointID: epID, VulnClass: domain.VulnReflectedXSS, Detail: captchaD.encode()}

	alreadyCombinedD := findingDetail{
		ParameterName: "x", DedupKey: "combined-already", Combined: true, ParameterBName: "y",
		Candidates: []detection.Candidate{{Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue, Combined: true, Value: "v", ValueB: "w"}},
	}
	alreadyCombined := &domain.Finding{ID: domain.NewID(), ScanID: scanID, EndpointID: epID, InjectionPointID: domain.NewID(), VulnClass: domain.VulnReflectedXSS, Detail: alreadyCombinedD.encode()}

	sites := reflectedSitesFor([]*domain.Finding{real, block, captcha, alreadyCombined})
	if len(sites) != 1 {
		t.Fatalf("sites = %d, want 1 (block/captcha/already-combined findings must be skipped)", len(sites))
	}
	if sites[0].parameterName != "q" {
		t.Fatalf("site = %+v, want parameter q", sites[0])
	}
}

func TestEndpointHasConfirmed(t *testing.T) {
	scanID, epID := domain.NewID(), domain.NewID()
	pending := combinedTestFinding(scanID, epID, domain.NewID(), "a", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	if endpointHasConfirmed([]*domain.Finding{pending}) {
		t.Fatal("no confirmed finding present: endpointHasConfirmed must be false")
	}
	confirmed := combinedTestFinding(scanID, epID, domain.NewID(), "b", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	confirmed.Verdict = domain.VerdictConfirmed
	if !endpointHasConfirmed([]*domain.Finding{pending, confirmed}) {
		t.Fatal("a confirmed finding is present: endpointHasConfirmed must be true")
	}
}

// --- findParamByNameLocation ---

func TestFindParamByNameLocation(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	pa := env.param(ep, "a", domain.LocationQuery, "1")
	pb := env.param(ep, "b", domain.LocationQuery, "2")
	params := []*domain.Parameter{pa, pb}

	if got := findParamByNameLocation(params, "b", domain.LocationQuery); got == nil || got.ID != pb.ID {
		t.Fatalf("findParamByNameLocation(b) = %v, want %v", got, pb)
	}
	if got := findParamByNameLocation(params, "missing", domain.LocationQuery); got != nil {
		t.Fatalf("findParamByNameLocation(missing) = %v, want nil", got)
	}
}

// --- enqueueCombinedCandidates: the gating (requirement B) + enqueue end to end ---

func TestEnqueueCombinedCandidates_SkipsEndpointWithConfirmed(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	pa := env.param(ep, "a", domain.LocationQuery, "1")
	pb := env.param(ep, "b", domain.LocationQuery, "2")
	ipA := env.injection(ep, pa)
	ipB := env.injection(ep, pb)

	fa := combinedTestFinding(env.scanID, ep.ID, ipA.ID, "a", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	fa.Verdict = domain.VerdictConfirmed // single-param testing ALREADY confirmed here
	fb := combinedTestFinding(env.scanID, ep.ID, ipB.ID, "b", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	if err := env.st.Findings().Create(context.Background(), fa); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Findings().Create(context.Background(), fb); err != nil {
		t.Fatal(err)
	}

	q := queue.NewMemory()
	c := NewController(env.st, q, execLog(), "test", Options{})
	c.enqueueCombinedCandidates(context.Background(), env.scanID)

	jobs, err := q.Jobs(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("jobs = %d, want 0: this endpoint already has a Confirmed finding, so combined pairing must not run (requirement B)", len(jobs))
	}
}

func TestEnqueueCombinedCandidates_EnqueuesWhenNoConfirmed(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	pa := env.param(ep, "a", domain.LocationQuery, "1")
	pb := env.param(ep, "b", domain.LocationQuery, "2")
	ipA := env.injection(ep, pa)
	ipB := env.injection(ep, pb)

	fa := combinedTestFinding(env.scanID, ep.ID, ipA.ID, "a", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	fb := combinedTestFinding(env.scanID, ep.ID, ipB.ID, "b", domain.LocationQuery, detection.CatHTMLAttr, detection.CtxHTMLAttrValue, "double_quoted")
	if err := env.st.Findings().Create(context.Background(), fa); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Findings().Create(context.Background(), fb); err != nil {
		t.Fatal(err)
	}

	q := queue.NewMemory()
	c := NewController(env.st, q, execLog(), "test", Options{})
	c.enqueueCombinedCandidates(context.Background(), env.scanID)

	jobs, err := q.Jobs(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want exactly 1 combined candidate job", len(jobs))
	}
	var cj candidateJob
	if err := json.Unmarshal(jobs[0].Payload, &cj); err != nil {
		t.Fatal(err)
	}
	if !cj.Candidate.Combined {
		t.Fatal("enqueued job's candidate must be Combined")
	}
	names := map[string]bool{cj.Candidate.Parameter: true, cj.Candidate.ParameterB: true}
	if !names["a"] || !names["b"] {
		t.Fatalf("combined candidate parameters = %+v, want {a,b}", cj.Candidate)
	}
	if jobs[0].Target.InjectionPointID != ipA.ID {
		t.Fatalf("job target injection point = %s, want %s (the first/\"closer\" site)", jobs[0].Target.InjectionPointID, ipA.ID)
	}
}

// --- buildRequest: a combined injection mutates BOTH parameters in ONE request ---

func TestBuildRequestCombinedInjectionMutatesBothParameters(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s?a=orig_a&b=orig_b&c=orig_c", domain.MethodGET)
	pa := env.param(ep, "a", domain.LocationQuery, "orig_a")
	pb := env.param(ep, "b", domain.LocationQuery, "orig_b")
	pc := env.param(ep, "c", domain.LocationQuery, "orig_c")
	params := []*domain.Parameter{pa, pb, pc}

	req, err := buildRequest(ep, params, &injection{param: pa, value: "MARK_A", paramB: pb, valueB: "MARK_B"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(req.URL, "a=MARK_A") {
		t.Errorf("URL %q missing overridden a=MARK_A", req.URL)
	}
	if !contains(req.URL, "b=MARK_B") {
		t.Errorf("URL %q missing overridden b=MARK_B", req.URL)
	}
	if !contains(req.URL, "c=orig_c") {
		t.Errorf("URL %q should leave the THIRD, uninvolved parameter untouched", req.URL)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// --- Finding correlation/dedup for composite (combined) findings ---

func TestFindingDedupKey_CombinedNeverCollidesWithSingleParam(t *testing.T) {
	ip := domain.NewID()
	single := candAt(detection.CatHTMLAttr, detection.CtxHTMLAttrValue, `">`)
	combined := detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue,
		Value: `">`, ValueB: "<svg onload=m>", Combined: true, InjectionPointBID: domain.NewID(),
	}
	if findingDedupKey(ip, single) == findingDedupKey(ip, combined) {
		t.Fatal("a combined candidate's dedup key must never collide with a single-parameter one at the same injection point/category/context")
	}
}

func TestFindingDedupKey_DistinctCombinedPairsDoNotCollide(t *testing.T) {
	ipA := domain.NewID()
	pairAB := detection.Candidate{Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue, Combined: true, InjectionPointBID: domain.NewID()}
	pairAC := detection.Candidate{Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue, Combined: true, InjectionPointBID: domain.NewID()}
	if findingDedupKey(ipA, pairAB) == findingDedupKey(ipA, pairAC) {
		t.Fatal("two combined pairs sharing the first parameter but pairing it with a DIFFERENT second parameter must not collide")
	}
}

func TestUpsertPendingFinding_CombinedTitleAndDetail(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("http://x/s", domain.MethodGET)
	focus := env.param(ep, "left", domain.LocationQuery, "v1")
	ip := env.injection(ep, focus)

	cand := detection.Candidate{
		Source: detection.SourceBuiltin, Category: detection.CatHTMLAttr, Context: detection.CtxHTMLAttrValue,
		Value: `">`, ValueB: "<svg onload=m>", Combined: true, Parameter: "left", ParameterB: "right",
		InjectionPointBID: domain.NewID(), DedupKey: "combined\x00test",
	}
	f, err := upsertPendingFinding(context.Background(), env.st, env.scanID, ep, ip.ID, focus, cand, domain.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(f.Title, "left") || !contains(f.Title, "right") || !contains(f.Title, "combined") {
		t.Fatalf("combined finding title = %q, want both parameter names and \"combined\"", f.Title)
	}
	d := decodeFindingDetail(f.Detail)
	if !d.Combined || d.ParameterBName != "right" {
		t.Fatalf("finding detail = %+v, want Combined=true ParameterBName=right", d)
	}
}

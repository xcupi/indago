package scan

// Server-side template injection (SSTI) engine.
//
// One JobSSTI is enqueued per eligible injection point. The engine sends a
// small set of arithmetic template expressions through the HTTP engine. A
// template expression is harmless: the request contains e.g. "{{7*7}}" while
// a vulnerable server evaluates it and returns "49".
//
// A verdict is CONFIRMED only when two independent expressions produce their
// own computed result and neither the raw payload nor the result was already
// present in the baseline response. Reflection, a single marker, transport
// errors and ordinary pages containing the same numbers are never promoted to
// a finding. No template statement, file access, network access or state change
// is sent.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/fingerprint"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const sstiEngine = "ssti"

type sstiAttempt struct {
	Payload  string `json:"payload"`
	Expected string `json:"expected"`
	Kind     string `json:"kind,omitempty"`
	Output   bool   `json:"output"`
	Status   int    `json:"status,omitempty"`
}

type sstiDetail struct {
	Engine         string               `json:"engine"`
	Parameter      string               `json:"parameter"`
	Location       domain.ParamLocation `json:"location"`
	BaselineStatus int                  `json:"baseline_status,omitempty"`
	// TemplateEngines is the fingerprint's ordered engine recommendation for the
	// baseline response. It drives which payload shape is probed first and is
	// recorded so a reader can see why that order was chosen.
	TemplateEngines []string       `json:"template_engines,omitempty"`
	Attempts        []sstiAttempt  `json:"attempts,omitempty"`
	ConfirmedCount  int            `json:"confirmed_count"`
	Verdict         domain.Verdict `json:"verdict"`
	Reason          string         `json:"reason,omitempty"`
	EvidenceIDs     []domain.ID    `json:"evidence_ids,omitempty"`
}

type sstiExecutor struct {
	*commandInjectionExecutor
}

// NewSSTIExecutorForTest exposes the executor to tests without exporting the
// production constructor.
func NewSSTIExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sstiExecutor {
	return newSSTIExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newSSTIExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sstiExecutor {
	return &sstiExecutor{commandInjectionExecutor: newCommandInjectionExecutor(st, eng, ev, cfg, log, findingsMu)}
}

var _ worker.Handler = (*sstiExecutor)(nil)

type sstiVariant struct {
	prefix   string
	suffix   string
	expr     string
	expected string
	family   string
}

const (
	sstiFamilyPHP    = "php"
	sstiFamilyNode   = "node"
	sstiFamilyJava   = "java"
	sstiFamilyPython = "python"
	sstiFamilyRuby   = "ruby"
)

func sstiVariants() []sstiVariant {
	// Pairs are deliberate: many engines support only one syntax, so a
	// single probe per family would make a real ERB/Jinja/Freemarker target
	// inconclusive. Each pair uses different arithmetic results; reflection
	// alone still cannot produce either computed value.
	variants := []sstiVariant{
		{prefix: "<%= ", suffix: " %>", expr: "7*7", expected: "49", family: sstiFamilyRuby},
		{prefix: "<%= ", suffix: " %>", expr: "11*13", expected: "143", family: sstiFamilyRuby},
		{prefix: "<%= ", suffix: " %>", expr: "7*7", expected: "49", family: sstiFamilyNode},
		{prefix: "<%= ", suffix: " %>", expr: "11*13", expected: "143", family: sstiFamilyNode},
		{prefix: "{{", suffix: "}}", expr: "7*7", expected: "49", family: sstiFamilyNode},
		{prefix: "{{", suffix: "}}", expr: "11*13", expected: "143", family: sstiFamilyNode},
		{prefix: "{{", suffix: "}}", expr: "7*7", expected: "49", family: sstiFamilyPHP},
		{prefix: "{{", suffix: "}}", expr: "11*13", expected: "143", family: sstiFamilyPHP},
		{prefix: "{{", suffix: "}}", expr: "7*7", expected: "49", family: sstiFamilyPython},
		{prefix: "{{", suffix: "}}", expr: "11*13", expected: "143", family: sstiFamilyPython},
		{prefix: "${", suffix: "}", expr: "7*7", expected: "49", family: sstiFamilyJava},
		{prefix: "${", suffix: "}", expr: "11*13", expected: "143", family: sstiFamilyJava},
		{prefix: "#{", suffix: "}", expr: "7*7", expected: "49", family: sstiFamilyJava},
		{prefix: "#{", suffix: "}", expr: "11*13", expected: "143", family: sstiFamilyJava},
		{prefix: "*{", suffix: "}", expr: "7*7", expected: "49", family: sstiFamilyJava},
		{prefix: "*{", suffix: "}", expr: "11*13", expected: "143", family: sstiFamilyJava},
		{prefix: "{", suffix: "}", expr: "7*7", expected: "49", family: sstiFamilyPHP},
		{prefix: "{", suffix: "}", expr: "11*13", expected: "143", family: sstiFamilyPHP},
		// Velocity uses a statement followed by a reference, not a bare
		// expression; keep the two probes distinct so a reflected payload
		// cannot supply both values.
		{prefix: "#set($indago=", suffix: ")$indago", expr: "7*7", expected: "49", family: sstiFamilyJava},
		{prefix: "#set($indago=", suffix: ")$indago", expr: "11*13", expected: "143", family: sstiFamilyJava},
	}
	return variants
}

// sstiContextVariants handles the second SSTI shape: the parameter is placed
// inside an existing template expression, e.g. engine.render("Hello {{"+name+"}}").
// In that shape a plain "{{7*7}}" is just part of the variable name. Reusing the
// operator's observed value and closing the surrounding expression produces
// "{{value}}{{7*7}}" (and the equivalent shapes for other engines).
func sstiContextVariants(baseValue string) []sstiVariant {
	baseValue = strings.TrimSpace(baseValue)
	if baseValue == "" {
		return nil
	}
	return []sstiVariant{
		{prefix: baseValue + "}}{{", suffix: "}}", expr: "7*7", expected: "49", family: sstiFamilyNode},
		{prefix: baseValue + "}}{{", suffix: "}}", expr: "11*13", expected: "143", family: sstiFamilyNode},
		{prefix: baseValue + "}${", suffix: "}", expr: "7*7", expected: "49", family: sstiFamilyJava},
		{prefix: baseValue + "}${", suffix: "}", expr: "11*13", expected: "143", family: sstiFamilyJava},
		{prefix: baseValue + " %><%= ", suffix: " %>", expr: "7*7", expected: "49", family: sstiFamilyRuby},
		{prefix: baseValue + " %><%= ", suffix: " %>", expr: "11*13", expected: "143", family: sstiFamilyRuby},
	}
}

// sstiSupportedFamilies is the local marker table: it only returns families
// when the baseline response carries a technology marker that makes a template
// engine plausible. sstiStackFor consults it as a fallback when the shared
// fingerprint catalog recognises nothing, so an unmodelled stack does not turn
// a reachable injection point into a silent skip. An unknown stack with no
// marker at all is still skipped rather than sprayed with template syntax.
func sstiSupportedFamilies(resp *httpengine.Response) map[string]string {
	supported := map[string]string{}
	if resp == nil {
		return supported
	}
	h := resp.Headers
	powered := strings.ToLower(h.Get("X-Powered-By"))
	server := strings.ToLower(h.Get("Server"))
	cookies := strings.ToLower(strings.Join(h.Values("Set-Cookie"), "\n"))
	body := strings.ToLower(string(resp.Body))
	add := func(family, evidence string) {
		if _, ok := supported[family]; !ok {
			supported[family] = evidence
		}
	}
	if strings.Contains(powered, "php") || strings.Contains(cookies, "phpsessid") ||
		strings.Contains(cookies, "laravel_session") || strings.Contains(body, "laravel") {
		add(sstiFamilyPHP, "PHP application fingerprint")
	}
	if strings.Contains(powered, "express") || strings.Contains(cookies, "connect.sid") {
		add(sstiFamilyNode, "Express/Node application fingerprint")
	}
	if strings.Contains(server, "tomcat") || strings.Contains(server, "jetty") ||
		strings.Contains(server, "coyote") || strings.Contains(server, "undertow") ||
		strings.Contains(cookies, "jsessionid") || strings.Contains(powered, "servlet") {
		add(sstiFamilyJava, "Java servlet application fingerprint")
	}
	if strings.Contains(server, "werkzeug") || strings.Contains(server, "gunicorn") ||
		strings.Contains(server, "uvicorn") || strings.Contains(powered, "python") ||
		strings.Contains(cookies, "csrftoken") || strings.Contains(body, "csrfmiddlewaretoken") {
		add(sstiFamilyPython, "Python web application fingerprint")
	}
	if strings.Contains(server, "passenger") || strings.Contains(server, "webrick") ||
		strings.Contains(cookies, "_session_id") || strings.Contains(cookies, "_rails") {
		add(sstiFamilyRuby, "Ruby/Rails application fingerprint")
	}
	return supported
}

// Payload shapes — the delimiter pair a template engine evaluates. Every shape
// below already exists in sstiVariants; the tables that follow only decide which
// of them is tried first, they never add a payload.
const (
	sstiSyntaxMustache = "mustache" // {{7*7}}
	sstiSyntaxDollar   = "dollar"   // ${7*7}
	sstiSyntaxHash     = "hash"     // #{7*7}
	sstiSyntaxStar     = "star"     // *{7*7}
	sstiSyntaxErb      = "erb"      // <%= 7*7 %>
	sstiSyntaxSmarty   = "smarty"   // {7*7}
	sstiSyntaxVelocity = "velocity" // #set($indago=7*7)$indago
)

// sstiFamilyDotNet carries a detected .NET stack. No Razor variant exists yet,
// so families built only from it end up probing nothing and the point is
// reported as skipped rather than sprayed with another engine's syntax.
const sstiFamilyDotNet = "dotnet"

// sstiEngineShape ties a fingerprint template-engine name to the variant family
// that can express it and to the payload shapes worth trying for it, most
// likely first (Jinja2/Twig → "{{…}}", Freemarker/EL → "${…}", ERB/EJS →
// "<%= … %>").
type sstiEngineShape struct {
	family string
	syntax []string
}

var sstiEngineShapes = map[string]sstiEngineShape{
	fingerprint.TplJinja2:     {family: sstiFamilyPython, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplDjango:     {family: sstiFamilyPython, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplMako:       {family: sstiFamilyPython, syntax: []string{sstiSyntaxDollar}},
	fingerprint.TplTwig:       {family: sstiFamilyPHP, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplSmarty:     {family: sstiFamilyPHP, syntax: []string{sstiSyntaxSmarty, sstiSyntaxMustache}},
	fingerprint.TplBlade:      {family: sstiFamilyPHP, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplERB:        {family: sstiFamilyRuby, syntax: []string{sstiSyntaxErb}},
	fingerprint.TplHaml:       {family: sstiFamilyRuby, syntax: []string{sstiSyntaxErb}},
	fingerprint.TplFreemarker: {family: sstiFamilyJava, syntax: []string{sstiSyntaxDollar, sstiSyntaxHash}},
	fingerprint.TplVelocity:   {family: sstiFamilyJava, syntax: []string{sstiSyntaxVelocity, sstiSyntaxDollar}},
	fingerprint.TplSpEL:       {family: sstiFamilyJava, syntax: []string{sstiSyntaxDollar, sstiSyntaxStar, sstiSyntaxHash}},
	fingerprint.TplThymeleaf:  {family: sstiFamilyJava, syntax: []string{sstiSyntaxStar, sstiSyntaxDollar}},
	fingerprint.TplEJS:        {family: sstiFamilyNode, syntax: []string{sstiSyntaxErb, sstiSyntaxMustache}},
	fingerprint.TplHandlebars: {family: sstiFamilyNode, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplNunjucks:   {family: sstiFamilyNode, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplPug:        {family: sstiFamilyNode, syntax: []string{sstiSyntaxHash}},
	// Mustache is language-agnostic; "{{…}}" is already carried by the PHP and
	// Node families, so either one can express it.
	fingerprint.TplMustache: {family: sstiFamilyPHP, syntax: []string{sstiSyntaxMustache}},
	fingerprint.TplRazor:    {family: sstiFamilyDotNet},
}

// sstiStack is the passive applicability decision for one injection point:
// whether a template probe is worth a request, which engine families the
// response supports, the recommended engine order, and — when the answer is no —
// why.
type sstiStack struct {
	probe    bool
	engines  []string
	families map[string]string
	reason   string
}

// sstiStackFor runs the shared fingerprint gate over an ALREADY-FETCHED
// baseline response; it sends nothing. Analysis is the only source of the
// engine recommendation: this layer does not guess syntax, it elects which
// existing variant family to try first.
//
// The gate is authoritative whenever it has positive evidence that the response
// is not a rendered document: a static asset, a binary body, a cache reply and a
// serialized JSON reply with no engine named all suppress the probe. When the
// catalog recognises nothing at all, the local markers in sstiSupportedFamilies
// are still consulted — an unmodelled stack must not silently turn a reachable
// injection point into a skip — and only a complete absence of evidence skips
// (the historical behaviour).
func sstiStackFor(url string, resp *httpengine.Response) sstiStack {
	stack := sstiStack{families: map[string]string{}}
	if resp == nil {
		stack.reason = "no baseline response"
		return stack
	}
	prof := fingerprint.Analyze(fingerprint.Observation{
		URL:    url,
		Status: resp.Status,
		Header: resp.Headers,
		Body:   resp.Body,
	})
	// Checked first so the local fallback below can never re-enable a probe on a
	// body that cannot be rendered at all.
	if prof.Status == http.StatusNotModified || prof.StaticAsset || prof.ContentKind == fingerprint.KindBinary {
		stack.reason = "baseline response is a static asset, a binary body or a cache reply"
		return stack
	}
	ok, engines := fingerprint.ShouldProbeSSTI(prof)
	local := sstiSupportedFamilies(resp)
	switch {
	case ok:
		stack.probe = true
		stack.engines = engines
		// The union keeps the local markers' coverage (a bare product word, a
		// Passenger header) while the engine families add what the shared
		// catalog spotted. Membership only: order is not observable here.
		for family, evidence := range local {
			stack.families[family] = evidence
		}
		for family, evidence := range sstiFamiliesForEngines(engines) {
			if _, seen := stack.families[family]; !seen {
				stack.families[family] = evidence
			}
		}
	case prof.ContentKind == fingerprint.KindJSON:
		// ShouldProbeSSTI only refuses JSON after checking for explicit engine
		// evidence, so reaching this case means there is none: serialized data
		// with no template surface. Any other refusal (a client-rendered shell)
		// falls through to the local markers instead, which stays fail-open.
		stack.reason = "baseline is serialized JSON with no template engine evidence"
	case len(local) == 0:
		stack.reason = "no supported template stack fingerprint"
	default:
		stack.probe = true
		stack.families = local
	}
	return stack
}

// sstiFamiliesForEngines maps a fingerprint engine recommendation onto the
// variant families that can express it.
func sstiFamiliesForEngines(engines []string) map[string]string {
	families := make(map[string]string, len(engines))
	for _, engine := range engines {
		shape, ok := sstiEngineShapes[strings.ToLower(strings.TrimSpace(engine))]
		if !ok || shape.family == "" {
			continue
		}
		if _, seen := families[shape.family]; !seen {
			families[shape.family] = "template engine " + shape.family + " detected (" + engine + ")"
		}
	}
	return families
}

// sstiVariantSyntax names the payload shape a variant uses. It is derived from
// the delimiters themselves, so the tag can never drift from what is sent.
func sstiVariantSyntax(v sstiVariant) string {
	switch {
	case strings.Contains(v.prefix, "<%="):
		return sstiSyntaxErb
	case strings.Contains(v.prefix, "#set("):
		return sstiSyntaxVelocity
	case strings.HasSuffix(v.prefix, "{{"):
		return sstiSyntaxMustache
	case strings.HasSuffix(v.prefix, "${"):
		return sstiSyntaxDollar
	case strings.HasSuffix(v.prefix, "#{"):
		return sstiSyntaxHash
	case strings.HasSuffix(v.prefix, "*{"):
		return sstiSyntaxStar
	case strings.HasSuffix(v.prefix, "{"):
		return sstiSyntaxSmarty
	}
	return ""
}

// sstiShapeRank turns the recommended engine order into a shape priority: a
// shape named earlier by an earlier engine sorts first.
func sstiShapeRank(engines []string) map[string]int {
	rank := make(map[string]int, 4)
	for _, engine := range engines {
		shape, ok := sstiEngineShapes[strings.ToLower(strings.TrimSpace(engine))]
		if !ok {
			continue
		}
		for i, syntax := range shape.syntax {
			if current, seen := rank[syntax]; !seen || i < current {
				rank[syntax] = i
			}
		}
	}
	return rank
}

// sstiPrioritizedVariants stable-sorts a filtered plan so the shapes the
// detected engines actually evaluate come first. It only reorders: no variant is
// dropped, and shapes no engine recommends keep their relative order behind the
// recommended ones.
func sstiPrioritizedVariants(variants []sstiVariant, engines []string) []sstiVariant {
	rank := sstiShapeRank(engines)
	if len(rank) == 0 || len(variants) < 2 {
		return variants
	}
	out := make([]sstiVariant, len(variants))
	copy(out, variants)
	score := func(v sstiVariant) int {
		if r, ok := rank[sstiVariantSyntax(v)]; ok {
			return r
		}
		return len(rank) + 1
	}
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) < score(out[j]) })
	return out
}

func sstiFilteredVariants(variants []sstiVariant, supported map[string]string) []sstiVariant {
	out := make([]sstiVariant, 0, len(variants))
	for _, v := range variants {
		if !v.familyAllowed(supported) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (v sstiVariant) familyAllowed(supported map[string]string) bool {
	if v.family == "" {
		return true
	}
	_, ok := supported[v.family]
	return ok
}

func (e *sstiExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve ssti target: %w", err)
	}
	if focus == nil {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !isSSTILocation(focus.Location) || isDynamicTokenName(focus.Name) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "parameter location is not template-injectable")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}
	if isWriteLikeEndpoint(ep, params) && (!e.cfg.AllowStateChanging || e.cfg.SkipWriteEndpoints) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}

	baseValue := strings.TrimSpace(focus.Example)
	if baseValue == "" {
		baseValue = commandInjectionBaseValue(focus.Name)
	}
	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build ssti baseline: %w", err)
	}
	baseResp, outcome, reqErr := e.do(ctx, base)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishSSTIError(ctx, job, started, ep, focus, outcome, reqErr)
	}

	d := sstiDetail{Engine: sstiEngine, Parameter: focus.Name, Location: focus.Location, BaselineStatus: baseResp.Status}
	baseEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "ssti baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baseEvidence...)
	baseBody := string(baseResp.Body)
	stack := sstiStackFor(ep.URL, baseResp)
	if !stack.probe {
		return e.finishSSTIUnavailable(ctx, job, started, ep, stack.reason)
	}
	d.TemplateEngines = stack.engines
	variants := sstiPrioritizedVariants(sstiFilteredVariants(sstiVariants(), stack.families), stack.engines)
	if len(variants) == 0 {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "no template probe shape for the detected stack")
	}

	confirmedValues := map[string]bool{}
	for _, v := range variants {
		key := v.prefix + v.expected
		if _, already := confirmedValues[key]; already {
			continue
		}
		// A page that already renders this number in its baseline is not
		// evidence of template evaluation for this parameter.
		if strings.Contains(baseBody, v.expected) {
			continue
		}
		payload := v.prefix + v.expr + v.suffix
		attempt := sstiAttempt{Payload: truncate(payload, 200), Expected: v.expected, Kind: "template"}
		params = e.refreshParams(ctx, ep, params, focus)
		req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
		if err != nil {
			attempt.Status = 0
			d.Attempts = append(d.Attempts, attempt)
			continue
		}
		resp, respOutcome, _ := e.do(ctx, req)
		if resp != nil {
			attempt.Status = resp.Status
		}
		if respOutcome == domain.OutcomeSuccess && resp != nil {
			body := string(resp.Body)
			attempt.Output = strings.Contains(body, v.expected) && !strings.Contains(body, payload)
			ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "ssti "+v.expr)
			d.EvidenceIDs = append(d.EvidenceIDs, ev...)
		}
		d.Attempts = append(d.Attempts, attempt)
		if attempt.Output {
			confirmedValues[key] = true
		}
		if len(confirmedValues) >= 2 {
			break
		}
	}

	if len(confirmedValues) < 2 {
		contextVariants := sstiPrioritizedVariants(sstiFilteredVariants(sstiContextVariants(baseValue), stack.families), stack.engines)
		for _, v := range contextVariants {
			key := v.prefix + v.expected
			if _, already := confirmedValues[key]; already {
				continue
			}
			if strings.Contains(baseBody, v.expected) {
				continue
			}
			payload := v.prefix + v.expr + v.suffix
			attempt := sstiAttempt{Payload: truncate(payload, 200), Expected: v.expected, Kind: "template-context"}
			params = e.refreshParams(ctx, ep, params, focus)
			req, err := buildRequest(ep, params, &injection{param: focus, value: payload})
			if err != nil {
				attempt.Status = 0
				d.Attempts = append(d.Attempts, attempt)
				continue
			}
			resp, respOutcome, _ := e.do(ctx, req)
			if resp != nil {
				attempt.Status = resp.Status
			}
			if respOutcome == domain.OutcomeSuccess && resp != nil {
				body := string(resp.Body)
				attempt.Output = strings.Contains(body, v.expected) && !strings.Contains(body, payload)
				ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "ssti-context "+v.expr)
				d.EvidenceIDs = append(d.EvidenceIDs, ev...)
			}
			d.Attempts = append(d.Attempts, attempt)
			if attempt.Output {
				confirmedValues[key] = true
			}
			if len(confirmedValues) >= 2 {
				break
			}
		}
	}

	d.ConfirmedCount = len(confirmedValues)
	if d.ConfirmedCount >= 2 {
		d.Verdict = domain.VerdictConfirmed
		d.Reason = "two independent template expressions were evaluated by the server"
		e.persistSSTICase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed server-side template injection: two independent arithmetic expressions evaluated")
		e.correlateSSTI(ctx, job, ep, focus, d)
		return nil
	}
	note := "no server-side template evaluation observed"
	if d.ConfirmedCount == 1 {
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one template marker was evaluated; a second independent marker is required"
		note = "one template marker observed; not enough to confirm"
	} else {
		d.Verdict = domain.VerdictRejected
	}
	e.persistSSTICase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
	return nil
}

func isSSTILocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationPath:
		return true
	default:
		return false
	}
}

func (e *sstiExecutor) persistSSTICase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sstiDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnSSTI,
		Status: status, Outcome: outcome, Method: string(ep.Method), URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("ssti: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *sstiExecutor) finishSSTIUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSSTI, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "ssti skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped ssti case: %w", err)
	}
	return nil
}

func (e *sstiExecutor) finishSSTIError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "redirect target is outside the scan scope")
	}
	if isTLSRedirectMismatch(reqErr) {
		return e.finishSSTIUnavailable(ctx, job, started, ep, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSSTI, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "ssti baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("ssti baseline failed: %s", msg)
}

func (e *sstiExecutor) correlateSSTI(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sstiDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnSSTI, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "Server-side template injection in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    "Two independent template expressions were evaluated by the server.",
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: sstiEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("ssti: persist finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueSSTIProbes queues one bounded job per eligible injection point.
func (c *Controller) enqueueSSTIProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableSSTI {
		return
	}
	ips, err := c.store.InjectionPoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		ep, err := c.store.Endpoints().Get(ctx, ip.EndpointID)
		if err != nil || ep == nil || !isSSTILocation(ip.Location) {
			continue
		}
		params, err := c.store.Parameters().ListByEndpoint(ctx, ep.ID)
		if err != nil {
			continue
		}
		var focus *domain.Parameter
		for _, p := range params {
			if p.ID == ip.ParameterID {
				focus = p
				break
			}
		}
		if focus == nil || isDynamicTokenName(focus.Name) {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"endpoint_id": string(ep.ID), "parameter_id": string(focus.ID)})
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobSSTI,
			State: domain.JobQueued, Priority: 46, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("ssti: enqueue", "scan", scanID, "err", err)
		}
	}
}

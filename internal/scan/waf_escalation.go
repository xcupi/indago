package scan

// Response-driven selection for the bounded automatic filter-bypass pass.
//
// internal/scan/evasion_escalation.go owns WHEN that pass may run, and
// internal/scan/waf_adaptive.go owns WHAT the target's own responses say about
// its filter. This file is the seam between them: it reads the canonical
// candidates' stored request/response evidence, runs the pure analyzer
// (AnalyzeResponseAdaptation) over it, and turns the result into
//
//   - a backpressure veto: a 429/503 — or a Retry-After on a failed probe —
//     skips that injection point even when no block-diagnostic Finding happened
//     to record the throttle at findingDetail.Throttled,
//   - an ordering of the bypass shapes internal/detection/evasion.go already
//     documents, so the primitive a response just proved it strips is not the
//     first thing sent again, and
//   - a durable record of the WAF vendor / sanitization signals the decision
//     was based on, attached to every job the pass enqueues.
//
// Boundaries (AGENTS.md §2.2, §3) that do NOT move here:
//
//   - Tactic matching only REORDERS candidates the documented evasion planner
//     produced. It never adds a shape, never obfuscates further, and never
//     changes the marker: every candidate stays the same documented
//     benign-marker breakout.
//   - Nothing here sends a request, opens a browser, stores evidence, or makes
//     a verdict. A missing/unreadable evidence blob simply means that candidate
//     is not analysed — it never justifies (or suppresses) a pass by itself.
//   - No LLM, no CAPTCHA handling, no proxy/TLS-fingerprint/timing technique.

import (
	"bytes"
	"context"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

const (
	// evasionMaxAdaptationProbes bounds how many canonical candidates are
	// re-read per injection point. They are taken in plan order (highest
	// priority first), so the selection is deterministic and one response can
	// never turn the analysis into an evidence sweep.
	evasionMaxAdaptationProbes = 8
	// evasionResponseReadLimit bounds how much of one stored response dump is
	// read back. It is deliberately larger than waf_adaptive.go's own body
	// window: the dump carries the status line and headers ahead of the body.
	evasionResponseReadLimit = 1 << 20
	// evasionHandlerMatchBoost / evasionElementMatchBoost /
	// evasionVectorMatchBoost are the bounded priority increments a planned
	// bypass shape gets when a response-derived tactic names a primitive it
	// carries. Handler-level evidence is the most specific (the response proved
	// that specific event attribute is filtered), element-level is weaker, and
	// a vector-only match (a JS/URL tactic against a candidate of that family)
	// weakest. They are small on purpose: evidence only reorders the documented
	// set, it never outranks every shape unconditionally.
	evasionHandlerMatchBoost = 20
	evasionElementMatchBoost = 10
	evasionVectorMatchBoost  = 10
)

// Match strengths returned by evasionTacticMatch. Higher is stronger evidence.
const (
	evasionMatchNone = iota
	evasionMatchVector
	evasionMatchElement
	evasionMatchHandler
)

// evasionProbe is one canonical candidate's stored request/response pair,
// reduced to exactly the inputs AnalyzeResponseAdaptation takes.
type evasionProbe struct {
	Payload        string
	BaselineStatus int
	BaselineBody   string
	ProbeStatus    int
	ProbeHeaders   map[string]string
	ProbeBody      string
}

// evasionAdaptation is the durable, operator-facing summary of what the
// canonical probe responses said about the target's filter. It is attached to
// every technique job the automatic pass enqueues, so the escalation's
// reasoning is auditable from the queued work alone.
type evasionAdaptation struct {
	// Probes is how many canonical candidate responses were analysed.
	Probes int `json:"probes"`
	// WAFVendor names the edge/WAF the responses identified, or "generic".
	WAFVendor string `json:"waf_vendor,omitempty"`
	// Blocked/BlockSignal record an outright block decision, not backpressure.
	Blocked     bool   `json:"blocked,omitempty"`
	BlockSignal string `json:"block_signal,omitempty"`
	// BackoffRequired is true when the responses asked for less traffic. The
	// escalation never runs for such a point, so this is only recorded for
	// completeness on jobs enqueued before the veto existed (restart).
	BackoffRequired bool `json:"backoff_required,omitempty"`
	// Sanitized/Escaped are the transformations the responses performed.
	Sanitized []string `json:"sanitized,omitempty"`
	Escaped   []string `json:"escaped,omitempty"`
	// Tactics lists every response-derived tactic id, best first.
	Tactics []string `json:"tactics,omitempty"`
	// Matched names the tactics THIS candidate's shape answers. Empty when the
	// response evidence did not point at this shape.
	Matched []string `json:"matched_tactics,omitempty"`
	// Reason is the analyzer's one-sentence explanation for the strongest
	// signal observed.
	Reason string `json:"reason,omitempty"`
}

// evasionAnalysis is the in-memory analysis result: the persisted summary plus
// the full tactic data used for matching.
type evasionAnalysis struct {
	evasionAdaptation
	tactics []EvasionTactic
}

// observed reports whether any response actually said something about the
// filter. A vendor header alone counts (it is factual edge identification), but
// an empty analysis (no probes, or probes that showed nothing) does not.
func (a evasionAnalysis) observed() bool {
	return a.Probes > 0 && (a.BackoffRequired || a.Blocked || a.WAFVendor != "" ||
		len(a.Sanitized) > 0 || len(a.Escaped) > 0 || len(a.tactics) > 0)
}

// forCandidate returns the persisted summary for one candidate, or nil when the
// responses justified nothing (so an ordinary pass keeps its payload shape).
func (a evasionAnalysis) forCandidate(matched []string) *evasionAdaptation {
	if !a.observed() {
		return nil
	}
	out := a.evasionAdaptation
	out.Matched = matched
	return &out
}

// summarizeEvasionProbes merges the per-probe analyses into one deterministic
// picture. Backpressure and block signals are sticky: one throttled probe
// disqualifies the point rather than being averaged away by the others, which is
// the same rule findingDetail.Throttled follows.
func summarizeEvasionProbes(probes []evasionProbe) evasionAnalysis {
	var out evasionAnalysis
	var sanitized, escaped []string
	var lists [][]EvasionTactic
	var firstReason, blockReason, backoffReason string

	for _, probe := range probes {
		if probe.ProbeStatus == 0 {
			continue
		}
		plan := AnalyzeResponseAdaptation(probe.Payload, probe.BaselineStatus, probe.BaselineBody,
			probe.ProbeStatus, probe.ProbeHeaders, probe.ProbeBody)
		out.Probes++
		sanitized = append(sanitized, plan.Sanitized...)
		escaped = append(escaped, plan.Escaped...)
		lists = append(lists, plan.Tactics)
		if plan.BackoffRequired && backoffReason == "" {
			backoffReason = plan.Reason
		}
		out.BackoffRequired = out.BackoffRequired || plan.BackoffRequired
		if plan.Blocked && blockReason == "" {
			blockReason = plan.Reason
		}
		if plan.Blocked && !out.Blocked {
			out.Blocked = true
			out.BlockSignal = plan.BlockSignal
		}
		if out.WAFVendor == "" && plan.WAFVendor != "" {
			out.WAFVendor = plan.WAFVendor
		}
		if firstReason == "" && plan.Reason != "" {
			firstReason = plan.Reason
		}
	}

	out.Sanitized = adaptSortedUnique(sanitized)
	out.Escaped = adaptSortedUnique(escaped)
	out.tactics = adaptMergeTactics(lists...)
	for _, tactic := range out.tactics {
		out.Tactics = append(out.Tactics, tactic.ID)
	}
	switch {
	case backoffReason != "":
		out.Reason = backoffReason
	case blockReason != "":
		out.Reason = blockReason
	default:
		out.Reason = firstReason
	}
	return out
}

// escalationAdaptation reads the stored response evidence of one source's
// canonical candidates and summarizes what those responses said about the
// target's filter. Test cases are visited in plan order, and only the first
// evasionMaxAdaptationProbes usable probes are analysed, so the analysis is
// deterministic and bounded.
func (c *Controller) escalationAdaptation(ctx context.Context, src evasionEscalationSource) evasionAnalysis {
	probes := make([]evasionProbe, 0, evasionMaxAdaptationProbes)
	for _, tc := range src.canonical {
		if len(probes) == evasionMaxAdaptationProbes {
			break
		}
		if tc == nil || len(tc.Detail) == 0 {
			continue
		}
		rep, err := detection.ParseReflection(tc.Detail)
		if err != nil || rep == nil || rep.Candidate == nil {
			continue
		}
		probe, ok := c.evasionProbeFrom(ctx, rep)
		if !ok {
			continue
		}
		probes = append(probes, probe)
	}
	return summarizeEvasionProbes(probes)
}

// evasionProbeFrom reduces one candidate reflection report to an analyzer
// input. A candidate with no evidence of any response (no stored body and no
// recorded status) is skipped: analysing an empty response would fabricate a
// "nothing reflected" claim that the run never made.
func (c *Controller) evasionProbeFrom(ctx context.Context, rep *detection.ReflectionReport) (evasionProbe, bool) {
	if rep == nil || rep.Candidate == nil {
		return evasionProbe{}, false
	}
	payload := strings.TrimSpace(rep.Candidate.Value)
	if payload == "" {
		return evasionProbe{}, false
	}
	probe := evasionProbe{
		Payload:        payload,
		BaselineStatus: rep.Baseline.Status,
		ProbeStatus:    rep.Mutated.Status,
	}
	// The stored response dump is the authoritative probe response; the
	// report's summary only fills in when the blob is gone (retention).
	if status, headers, body, ok := c.readResponseEvidence(ctx, rep.Evidence.MutatedResponse); ok {
		probe.ProbeStatus, probe.ProbeHeaders, probe.ProbeBody = status, headers, body
	}
	if probe.ProbeStatus <= 0 {
		return evasionProbe{}, false
	}
	if status, _, body, ok := c.readResponseEvidence(ctx, rep.Evidence.BaselineResponse); ok {
		probe.BaselineStatus, probe.BaselineBody = status, body
	}
	return probe, true
}

// readResponseEvidence opens one stored response blob and parses the HTTP/1.1
// message text the executor writes (status line, headers, body). It returns
// ok=false for anything it cannot read exactly, so the caller analyses fewer
// probes rather than guessing at a partial one.
func (c *Controller) readResponseEvidence(ctx context.Context, id domain.ID) (int, map[string]string, string, bool) {
	if id.Empty() || c.store == nil || c.opts.Evidence == nil {
		return 0, nil, "", false
	}
	ev, err := c.store.Evidence().Get(ctx, id)
	if err != nil || ev == nil || ev.BlobPath == "" {
		return 0, nil, "", false
	}
	rc, err := c.opts.Evidence.Open(ev.BlobPath)
	if err != nil {
		return 0, nil, "", false
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, evasionResponseReadLimit))
	if err != nil {
		return 0, nil, "", false
	}
	return parseResponseEvidenceDump(data)
}

// parseResponseEvidenceDump splits a stored HTTP/1.1 dump into its status,
// headers and body. The body is returned verbatim (the dump is already the
// engine's own rendered message), so no content-type or transfer-encoding
// interpretation can alter the evidence being analysed.
func parseResponseEvidenceDump(data []byte) (int, map[string]string, string, bool) {
	if len(data) == 0 {
		return 0, nil, "", false
	}
	var head, body []byte
	switch {
	case bytes.HasPrefix(data, []byte("HTTP/")):
		idx := bytes.Index(data, []byte("\r\n\r\n"))
		sepLen := len("\r\n\r\n")
		if idx < 0 {
			idx = bytes.Index(data, []byte("\n\n"))
			sepLen = len("\n\n")
		}
		if idx < 0 {
			// A status line with no header terminator is not a complete dump.
			return 0, nil, "", false
		}
		head, body = data[:idx], data[idx+sepLen:]
	default:
		return 0, nil, "", false
	}

	lines := strings.Split(string(head), "\n")
	statusFields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(lines[0], "\r")))
	if len(statusFields) < 2 {
		return 0, nil, "", false
	}
	status, err := strconv.Atoi(statusFields[1])
	if err != nil || status < 100 || status > 599 {
		return 0, nil, "", false
	}

	headers := make(map[string]string, len(lines))
	for _, line := range lines[1:] {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		// First spelling wins: the analyzer lowercases names itself, and a
		// deterministic choice is what keeps repeated analyses identical.
		if _, exists := headers[name]; !exists {
			headers[name] = strings.TrimSpace(value)
		}
	}
	return status, headers, string(body), true
}

// evasionHandlerNames are the event handlers the shape matcher recognises: the
// analyzer's own handler set plus every handler the documented bypass shapes
// carry. Membership is a fixed list (never a heuristic scan for "on…"), so a
// word like "content" cannot masquerade as an event handler.
var evasionHandlerNames = []string{
	"onanimationstart", "onbegin", "onerror", "onfocus", "onload",
	"onmouseenter", "onmouseover", "onpageshow", "onpointerdown",
	"onpointerenter", "onresize", "ontoggle",
}

// evasionVectorFamilies says which candidate categories can answer a tactic's
// vector. It is only used for the non-markup vectors: an HTML tactic has to
// name an element or a handler, because every HTML candidate would otherwise
// match every HTML tactic and the ranking would carry no information.
func evasionVectorFamily(vector string, cat detection.CandidateCategory) bool {
	switch vector {
	case adaptVectorJS:
		return cat == detection.CatJS
	case adaptVectorURL:
		return cat == detection.CatURL
	default:
		return false
	}
}

// evasionShape returns the primitives a payload carries: lowercase element
// names (ASCII '<' or a percent-encoded %3c) and lowercase event-handler names.
// Both lists are sorted and deduplicated, so matching is order-independent.
func evasionShape(value string) (elements, handlers []string) {
	lower := strings.ToLower(value)
	for _, handler := range evasionHandlerNames {
		if strings.Contains(lower, handler) {
			handlers = append(handlers, handler)
		}
	}
	for _, marker := range []string{"<", "%3c"} {
		for from := 0; from < len(lower); {
			idx := strings.Index(lower[from:], marker)
			if idx < 0 {
				break
			}
			start := from + idx + len(marker)
			end := start
			for end < len(lower) && evasionIsTagByte(lower[end]) {
				end++
			}
			if end > start {
				elements = append(elements, lower[start:end])
			}
			// start > from always holds, so this terminates.
			from = end
		}
	}
	sort.Strings(elements)
	sort.Strings(handlers)
	return adaptSortedUnique(elements), adaptSortedUnique(handlers)
}

func evasionIsTagByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

func evasionHasString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// evasionTacticMatch reports how strongly a planned bypass shape answers one
// response-derived tactic.
//
// When both sides carry an event handler, the handler family is the
// discriminator: a shape that keeps the handler the response just proved it
// strips gets NO credit, even if it shares the element name. That is what keeps
// a "<details open ontoggle>" suggestion from merely re-sending "onload".
func evasionTacticMatch(cand detection.Candidate, tactic EvasionTactic) int {
	candElements, candHandlers := evasionShape(cand.Value)
	tacticElements, tacticHandlers := evasionShape(tactic.Payload)

	if len(candHandlers) > 0 && len(tacticHandlers) > 0 {
		for _, handler := range tacticHandlers {
			if evasionHasString(candHandlers, handler) {
				return evasionMatchHandler
			}
		}
		return evasionMatchNone
	}
	if len(tacticElements) > 0 {
		for _, element := range tacticElements {
			if evasionHasString(candElements, element) {
				return evasionMatchElement
			}
		}
	}
	if evasionVectorFamily(tactic.Vector, cand.Category) {
		return evasionMatchVector
	}
	return evasionMatchNone
}

// matchingEvasionTactics lists the ids of every tactic the candidate's shape
// answers, in the analyzer's priority order (tactics arrive sorted).
func matchingEvasionTactics(cand detection.Candidate, tactics []EvasionTactic) []string {
	var out []string
	for _, tactic := range tactics {
		if evasionTacticMatch(cand, tactic) != evasionMatchNone {
			out = append(out, tactic.ID)
		}
	}
	return out
}

// evasionCandidateBoost is the bounded priority increment the strongest match
// earns. Zero means the response evidence says nothing about this shape.
func evasionCandidateBoost(cand detection.Candidate, tactics []EvasionTactic) int {
	best := 0
	for _, tactic := range tactics {
		var boost int
		switch evasionTacticMatch(cand, tactic) {
		case evasionMatchHandler:
			boost = evasionHandlerMatchBoost
		case evasionMatchElement:
			boost = evasionElementMatchBoost
		case evasionMatchVector:
			boost = evasionVectorMatchBoost
		}
		if boost > best {
			best = boost
		}
	}
	return best
}

// evasionCandidatePriority is the queue priority a planned bypass shape gets:
// its own planned priority plus the bounded response-driven boost. The queue
// leases higher priorities first, so a matched shape is actually sent (and
// verified) before the shapes the evidence argues against — not merely listed
// in a different order.
func evasionCandidatePriority(cand detection.Candidate, tactics []EvasionTactic) int {
	return cand.Priority + evasionCandidateBoost(cand, tactics)
}

// rankEvasionCandidatesByAdaptation reorders the planned bypass shapes so the
// ones the responses justify come first, keeping the planner's own order among
// equal matches (sort.SliceStable). It only permutes the documented set: the
// same DedupKeys are enqueued, which keeps restart reconciliation unchanged.
func rankEvasionCandidatesByAdaptation(cands []detection.Candidate, a evasionAnalysis) []detection.Candidate {
	if len(cands) < 2 || len(a.tactics) == 0 {
		return cands
	}
	type ranked struct {
		cand     detection.Candidate
		priority int
	}
	items := make([]ranked, len(cands))
	for i, cand := range cands {
		items[i] = ranked{cand: cand, priority: evasionCandidatePriority(cand, a.tactics)}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].priority > items[j].priority })
	out := make([]detection.Candidate, len(items))
	for i, item := range items {
		out[i] = item.cand
	}
	return out
}

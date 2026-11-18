package scan

// XML external entity (XXE) engine.
//
// XXE is only applicable to an endpoint whose observed request body is XML and
// whose parser resolves entities. The engine never guesses an XML endpoint or
// sprays XML at a form/JSON route: discovery must have captured an XML request
// body in the browser network, or the operator must have supplied one.
//
// Two confirmation signals exist. Both are marker-only — no local file is read,
// no response data is exfiltrated and nothing on the target changes:
//
//  1. In-band (default, no collaborator needed): the DOCTYPE internal subset
//     declares a harmless INTERNAL entity (<!ENTITY indago_x "indagox">) and
//     the document references it. A parser that expands DTD entities replaces
//     the reference with the literal value, which the application can only
//     hand back to us through its own response. Confirmation needs TWO
//     INDEPENDENT markers (separate requests, separately randomized names and
//     values) and a strict non-reflection check: a response that carries the
//     entity NAME (which exists only in the declaration we sent) is treated as
//     an echo of our payload, never as expansion.
//  2. Out-of-band (only when the operator configured a callback+poll URL): an
//     EXTERNAL entity pointing at the collaborator. This remains the only path
//     that detects a parser which resolves external entities without ever
//     reflecting document content, so it is preserved whenever configured and
//     used after in-band produced no signal. The external reference is placed
//     at two ordered positions, one request each: first in element content (the
//     classic probe), and — when that produced no callback — in the document's
//     DTD. A parser processes the DTD before it validates the document's root
//     element, so the DTD position still resolves when the application rejects
//     a synthesized probe body outright because its real schema was never
//     observed. Only the collaborator's own hit confirms either position.
//
// The in-band probe cannot become a resource-exhaustion payload: it declares
// two single-level entities holding short hex literals, never a SYSTEM or
// PUBLIC resource, and never nests one entity inside another.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
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

const (
	xxeEngine = "xxe"

	// xxeModeInBand / xxeModeOutOfBand record which signal produced a verdict
	// so a triager can tell a fully local proof from a collaborator hit.
	xxeModeInBand    = "in_band"
	xxeModeOutOfBand = "out_of_band"

	// defaultXXEProbeBody is used only when discovery observed an explicit XML
	// endpoint (e.g. a form declaring contentType/enctype="application/xml")
	// without a captured request body.
	defaultXXEProbeBody = "<indago>probe</indago>"

	// xxeShapeContentReference / xxeShapeDTDReference name where an out-of-band
	// probe placed its external reference, so a triager can tell which position
	// the target's parser actually honoured.
	xxeShapeContentReference = "content_reference"
	xxeShapeDTDReference     = "dtd_reference"

	// xxePollTries bounds how long (seconds) one probe waits for the
	// collaborator to record the hit.
	xxePollTries = 8
)

// xxeOOBShapes is the bounded, ordered set of out-of-band reference positions.
// The content reference is sent first: it is the classic shape and reflects the
// document the endpoint was actually observed sending. The DTD reference is the
// schema-independent fallback — an endpoint whose real XML schema was never
// observed rejects a synthesized body before it reads any element content, and
// a content-only reference is then never dereferenced.
var xxeOOBShapes = []struct {
	Name  string
	Build func(body, callback string) (string, bool)
}{
	{xxeShapeContentReference, injectXXE},
	{xxeShapeDTDReference, injectXXEDTD},
}

var xxeRootRe = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.:-]*)(\s[^>]*)?>`)

// xxeRootElementRe also matches a self-closing root. The content probes cannot
// use such a document (there is no content to put a reference in), but a
// DTD-level reference does not need any.
var xxeRootElementRe = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.:-]*)(\s[^>]*)?/?>`)

// xxeAttempt is one out-of-band probe.
type xxeAttempt struct {
	Payload  string `json:"payload"`
	Shape    string `json:"shape,omitempty"`
	Status   int    `json:"status,omitempty"`
	Callback bool   `json:"callback"`
}

// xxeInBandAttempt is one document-internal entity probe.
type xxeInBandAttempt struct {
	Payload   string `json:"payload"`
	Entity    string `json:"entity,omitempty"`
	Status    int    `json:"status,omitempty"`
	Expanded  bool   `json:"expanded"`
	Reflected bool   `json:"raw_markup_reflected,omitempty"`
}

type xxeDetail struct {
	Engine      string             `json:"engine"`
	Mode        string             `json:"mode,omitempty"`
	Attempts    []xxeAttempt       `json:"attempts,omitempty"`
	InBand      []xxeInBandAttempt `json:"in_band,omitempty"`
	Verdict     domain.Verdict     `json:"verdict"`
	Reason      string             `json:"reason,omitempty"`
	EvidenceIDs []domain.ID        `json:"evidence_ids,omitempty"`
}

type xxeExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex
	callback   string
	poll       string
	pollTries  int
}

func NewXXEExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *xxeExecutor {
	return newXXEExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newXXEExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *xxeExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &xxeExecutor{store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log, findingsMu: findingsMu, pollTries: xxePollTries}
}

func (e *xxeExecutor) withCallback(url, poll string) {
	e.callback = strings.TrimSpace(url)
	e.poll = strings.TrimSpace(poll)
}

func (e *xxeExecutor) hasCallback() bool { return e.callback != "" && e.poll != "" }

var _ worker.Handler = (*xxeExecutor)(nil)

// xxeProfile fingerprints an already-fetched baseline response for the XXE
// gate. It is passive: the observation is handed in, nothing is fetched.
func xxeProfile(ep *domain.Endpoint, resp *httpengine.Response) fingerprint.Profile {
	obs := fingerprint.Observation{}
	if ep != nil {
		obs.URL = ep.URL
	}
	if resp != nil {
		obs.Status = resp.Status
		obs.Header = resp.Headers
		obs.Body = resp.Body
	}
	return fingerprint.Analyze(obs)
}

func isExplicitXMLMediaType(raw string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(raw, ";", 2)[0]))
	return mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml")
}

func isXMLBodyEndpoint(ep *domain.Endpoint) bool {
	if ep == nil {
		return false
	}
	switch ep.Method {
	case domain.MethodPOST, domain.MethodPUT, domain.MethodPATCH:
	default:
		return false
	}
	if strings.TrimSpace(ep.RequestBody) == "" {
		return isExplicitXMLMediaType(ep.ContentType)
	}
	if !strings.Contains(strings.ToLower(ep.ContentType), "xml") {
		return false
	}
	return strings.Contains(ep.RequestBody, "<")
}

func (e *xxeExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	ep, err := e.store.Endpoints().Get(ctx, job.Target.EndpointID)
	if err != nil {
		return fmt.Errorf("resolve xxe endpoint: %w", err)
	}
	if !isXMLBodyEndpoint(ep) {
		return e.finishXXEUnavailable(ctx, job, "no observed XML request body")
	}
	if e.cfg.SkipWriteEndpoints || !e.cfg.AllowStateChanging {
		return e.finishXXEUnavailable(ctx, job, "state-changing XML endpoint skipped by policy")
	}
	reqBody := ep.RequestBody
	if strings.TrimSpace(reqBody) == "" {
		reqBody = defaultXXEProbeBody
	}
	req := &httpengine.Request{
		Method:      string(ep.Method),
		URL:         ep.URL,
		Body:        []byte(reqBody),
		ContentType: ep.ContentType,
	}
	baseResp, baseOutcome, _ := e.do(ctx, req)
	if baseOutcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishXXEUnavailable(ctx, job, "baseline XML request did not succeed")
	}
	// Passive applicability gate: an XML parser has to be plausibly in play for
	// THIS endpoint before an entity is sent. The fingerprint reads the baseline
	// response that was just fetched plus the endpoint's own request shape and
	// sends nothing; a JSON-only request/response pair with no XML anywhere is
	// refused here even if the stored content type merely contained "xml".
	if !fingerprint.ShouldProbeXXE(xxeProfile(ep, baseResp), ep.ContentType, reqBody) {
		return e.finishXXEUnavailable(ctx, job, "fingerprint found no XML surface on this endpoint")
	}
	d := xxeDetail{Engine: xxeEngine}
	if ev, err := e.persistEvidence(ctx, job.ScanID, baseResp, "xxe baseline"); err == nil {
		d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	}
	baseBody := string(baseResp.Body)

	// Phase 1: in-band, document-internal entities. Deterministic and local to
	// the target, so it runs even when no collaborator is configured.
	inBand := e.tryInBand(ctx, job, ep, req, baseBody, &d)
	if inBand.Confirmed {
		d.Mode = xxeModeInBand
		d.Verdict = domain.VerdictConfirmed
		d.Reason = "the XML parser expanded two independent document-internal entities"
		e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeSuccess,
			"confirmed document-internal entity expansion")
		e.correlateXXE(ctx, job, ep, d)
		return nil
	}

	// Phase 2: out-of-band, only when the operator configured a collaborator.
	// This is the only signal that survives a parser which resolves external
	// entities without reflecting document content.
	if e.hasCallback() {
		return e.tryOutOfBand(ctx, job, ep, req, &d)
	}

	switch {
	case inBand.Sent == 0:
		// The document has no place to put an entity reference (e.g. a
		// self-closing root and no callback configured to test externally).
		return e.finishXXEUnavailable(ctx, job, "XML body has no injectable root element")
	case inBand.Failed == inBand.Sent && inBand.Sent > 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "in-band entity probes did not complete"
		e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeError, "xxe in-band probe did not complete")
		return nil
	case inBand.Expanded == 1:
		// One expansion is real but not independent: a second marker is required
		// before calling the endpoint an XXE finding.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one document-internal entity was expanded; a second independent marker is required"
		e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "one document-internal entity expanded; not enough to confirm")
		return nil
	case inBand.Reflected:
		d.Verdict = domain.VerdictRejected
		d.Reason = "the endpoint echoed the XML markup without expanding the entity, and no callback is configured"
	default:
		d.Verdict = domain.VerdictRejected
		d.Reason = "no document-internal entity expansion observed and no external callback configured"
	}
	e.persistXXECase(ctx, job, d, domain.TestCaseCompleted, domain.OutcomeSuccess, "no XML entity expansion observed")
	return nil
}

// xxeInBandResult summarizes the internal-entity probes of one job.
type xxeInBandResult struct {
	Confirmed bool
	Reflected bool // the endpoint returned our declaration markup instead of parsing it
	Sent      int
	Expanded  int // probes whose entity was actually expanded
	Failed    int // probes whose request did not complete successfully
}

// xxeEntityProbe is one harmless document-internal entity: a random name and a
// random marker value, both unique to this request.
type xxeEntityProbe struct {
	Name  string
	Value string
}

func newXXEEntityProbe() xxeEntityProbe {
	// The name and the value are deliberately different strings: the NAME exists
	// only in the declaration we send, so seeing it proves the response echoed
	// our markup, while the VALUE can only appear once the reference is expanded.
	token := markerToken("")
	return xxeEntityProbe{Name: "indago_" + token, Value: "indago" + token}
}

// tryInBand sends at most two internal-entity probes. Each probe carries its
// own randomly named entity and its own random value in a separate request, so
// two confirmations cannot come from one expansion or from a page that happens
// to contain a number. A response that returns our declaration markup stops the
// loop: a second probe would be echoed exactly the same way.
func (e *xxeExecutor) tryInBand(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, req *httpengine.Request, baseBody string, d *xxeDetail) xxeInBandResult {
	var res xxeInBandResult
	expanded := 0
	for i := 0; i < 2; i++ {
		probe := newXXEEntityProbe()
		payload, ok := injectXXEInternal(string(req.Body), probe)
		if !ok {
			return res
		}
		attempt := xxeInBandAttempt{Payload: truncate(payload, 300), Entity: probe.Name}
		body := *req
		body.Body = []byte(payload)
		resp, outcome, _ := e.do(ctx, &body)
		res.Sent++
		if resp != nil {
			attempt.Status = resp.Status
			if ev, err := e.persistEvidence(ctx, job.ScanID, resp, "xxe in-band entity "+probe.Name); err == nil {
				d.EvidenceIDs = append(d.EvidenceIDs, ev...)
			}
		}
		if outcome != domain.OutcomeSuccess || resp == nil {
			res.Failed++
			d.InBand = append(d.InBand, attempt)
			continue
		}
		got := string(resp.Body)
		// The entity NAME only exists in the declaration we sent: a response
		// that carries it echoed our payload (raw or escaped) rather than
		// expanding it, so it is never evidence and never worth a second probe.
		if xxeMarkupEchoed(got, probe) {
			attempt.Reflected = true
			res.Reflected = true
			d.InBand = append(d.InBand, attempt)
			return res
		}
		if xxeEntityExpanded(got, baseBody, probe) {
			attempt.Expanded = true
			expanded++
			res.Expanded = expanded
		}
		d.InBand = append(d.InBand, attempt)
		if expanded >= 2 {
			res.Confirmed = true
			return res
		}
	}
	return res
}

// xxeMarkupEchoed reports whether the response returned the entity NAME we
// declared. An expanded entity leaves only its value behind, so the presence of
// the name means the endpoint handed back the markup instead of parsing it.
func xxeMarkupEchoed(body string, p xxeEntityProbe) bool {
	return strings.Contains(body, p.Name)
}

// xxeEntityExpanded reports whether respBody carries the probe's literal marker
// value in a response that did not echo the declaration and in a body that did
// not already contain it. The value is random per request, so its presence can
// only be explained by the parser substituting the entity reference.
func xxeEntityExpanded(respBody, baseBody string, p xxeEntityProbe) bool {
	if respBody == "" || !strings.Contains(respBody, p.Value) {
		return false
	}
	if strings.Contains(baseBody, p.Value) {
		return false
	}
	return !xxeMarkupEchoed(respBody, p)
}

// tryOutOfBand sends the external-entity probes and polls the collaborator. Used
// only when the operator configured both a callback and a poll URL. Each probe
// shape is sent at most once, in the fixed xxeOOBShapes order, and the loop stops
// on the first collaborator hit.
func (e *xxeExecutor) tryOutOfBand(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, req *httpengine.Request, d *xxeDetail) error {
	d.Mode = xxeModeOutOfBand
	marker := fmt.Sprintf("indago-xxe-%d", time.Now().UnixNano()%1000000000)
	callback := strings.TrimRight(e.callback, "/") + "/" + marker
	sent, completed := 0, 0
	for _, shape := range xxeOOBShapes {
		payload, ok := shape.Build(string(req.Body), callback)
		if !ok {
			continue
		}
		sent++
		attempt := xxeAttempt{Payload: truncate(payload, 300), Shape: shape.Name}
		probe := *req
		probe.Body = []byte(payload)
		resp, outcome, _ := e.do(ctx, &probe)
		if resp != nil {
			attempt.Status = resp.Status
			if ev, err := e.persistEvidence(ctx, job.ScanID, resp, "xxe "+shape.Name+" request"); err == nil {
				d.EvidenceIDs = append(d.EvidenceIDs, ev...)
			}
		}
		d.Attempts = append(d.Attempts, attempt)
		if outcome != domain.OutcomeSuccess {
			continue
		}
		completed++
		if e.pollForCallback(ctx, marker) {
			d.Attempts[len(d.Attempts)-1].Callback = true
			d.Verdict = domain.VerdictConfirmed
			d.Reason = "the XML parser resolved an external entity and called the collaborator"
			e.persistXXECase(ctx, job, *d, domain.TestCaseCompleted, domain.OutcomeSuccess, "confirmed XML external entity processing")
			e.correlateXXE(ctx, job, ep, *d)
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	switch {
	case sent == 0:
		return e.finishXXEUnavailable(ctx, job, "XML body has no injectable root element")
	case completed == 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "XXE request did not complete"
		e.persistXXECase(ctx, job, *d, domain.TestCaseCompleted, domain.OutcomeError, "xxe request did not complete")
		return nil
	}
	d.Verdict = domain.VerdictRejected
	d.Reason = "no external entity callback observed"
	expanded := 0
	for _, a := range d.InBand {
		if a.Expanded {
			expanded++
		}
	}
	if expanded == 1 {
		// The parser did expand one internal entity, so a negative verdict would
		// overstate the evidence; it just never produced a second independent
		// marker or an out-of-band hit.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one document-internal entity was expanded, but no second independent marker and no external callback confirmed it"
	}
	e.persistXXECase(ctx, job, *d, domain.TestCaseCompleted, domain.OutcomeSuccess, "no external entity callback observed")
	return nil
}

// pollForCallback waits for the collaborator to report the probe's marker. It is
// the only thing that can confirm an out-of-band probe: the target's own request
// to the collaborator, never the target's response status.
func (e *xxeExecutor) pollForCallback(ctx context.Context, marker string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	tries := e.pollTries
	if tries <= 0 {
		tries = xxePollTries
	}
	for i := 0; i < tries; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second):
		}
		pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, e.poll, nil)
		if err != nil {
			return false
		}
		pollResp, err := client.Do(pollReq)
		if err != nil {
			continue
		}
		body := make([]byte, 1<<20)
		n, _ := pollResp.Body.Read(body)
		pollResp.Body.Close()
		if strings.Contains(string(body[:n]), marker) {
			return true
		}
	}
	return false
}

// injectXXE inserts an EXTERNAL entity declaration pointing at the collaborator
// and places its reference right after the root element's opening tag.
func injectXXE(body, callback string) (string, bool) {
	out, ok := injectXMLDTD(body, `<!ENTITY xxe SYSTEM "`+xmlEntityEscape(callback)+`">`)
	if !ok {
		return "", false
	}
	return injectXMLRefAfterRoot(out, "&xxe;")
}

// injectXXEDTD references the collaborator from the document's DTD rather than
// from element content. A parser processes the DTD before it validates or
// unmarshals the document's root element, so this reference is still resolved
// when the application rejects a synthesized probe body outright — exactly the
// case where a content-only reference is never read.
//
// A document that already carries a DOCTYPE gets a parameter-entity reference
// inside that subset (a second DOCTYPE would be invalid); otherwise the external
// DTD subset is used, which needs no internal-subset support at all and is the
// most widely honoured DTD-level reference. Either way the payload is one short
// URL and one reference: no nesting, no entity expansion chain.
func injectXXEDTD(body, callback string) (string, bool) {
	url := xmlEntityEscape(callback)
	if strings.Contains(body, "<!DOCTYPE") {
		return injectXMLDTD(body, `<!ENTITY % indago SYSTEM "`+url+`">%indago;`)
	}
	m := xxeRootElementRe.FindStringSubmatchIndex(body)
	if m == nil {
		return "", false
	}
	name := body[m[2]:m[3]]
	insert := m[0]
	if strings.HasPrefix(strings.TrimSpace(body), "<?xml") {
		if idx := strings.Index(body, "?>"); idx >= 0 {
			insert = idx + 2
		}
	}
	return body[:insert] + `<!DOCTYPE ` + name + ` SYSTEM "` + url + `">` + body[insert:], true
}

// injectXXEInternal inserts one INTERNAL entity — a short literal, never a
// file or a URL — and places its reference where a parser is most likely to
// hand the resolved value back: the first text-only element if the document has
// one, otherwise the root element's own content.
func injectXXEInternal(body string, p xxeEntityProbe) (string, bool) {
	decl := `<!ENTITY ` + p.Name + ` "` + xmlEntityEscape(p.Value) + `">`
	out, ok := injectXMLDTD(body, decl)
	if !ok {
		return "", false
	}
	ref := "&" + p.Name + ";"
	if leaf, ok := injectXMLRefIntoLeaf(out, ref); ok {
		return leaf, true
	}
	return injectXMLRefAfterRoot(out, ref)
}

// injectXMLDTD adds a DTD internal subset carrying one markup declaration. An
// existing DOCTYPE is reused (the declaration goes inside its internal subset)
// instead of emitting a second, invalid DOCTYPE.
func injectXMLDTD(body, declaration string) (string, bool) {
	if idx := strings.Index(body, "<!DOCTYPE"); idx >= 0 {
		open, close, end := xxeInternalSubset(body, idx)
		if end < 0 {
			return "", false
		}
		switch {
		case open >= 0 && close > open:
			return body[:close] + declaration + body[close:], true
		case open >= 0:
			return "", false // unterminated internal subset: never guess a repair
		default:
			return body[:end] + " [" + declaration + "]" + body[end:], true
		}
	}
	m := xxeRootRe.FindStringSubmatchIndex(body)
	if m == nil {
		return "", false
	}
	name := body[m[2]:m[3]]
	insert := m[0]
	if strings.HasPrefix(strings.TrimSpace(body), "<?xml") {
		if idx := strings.Index(body, "?>"); idx >= 0 {
			insert = idx + 2
		}
	}
	doctype := "<!DOCTYPE " + name + " [" + declaration + "]>"
	return body[:insert] + doctype + body[insert:], true
}

// xxeInternalSubset locates a DOCTYPE's internal subset and its end offset. It
// tracks bracket depth and quotes so a '>' inside a markup declaration is not
// mistaken for the end of the DOCTYPE.
func xxeInternalSubset(body string, start int) (open, close, end int) {
	open, close, end = -1, -1, -1
	depth := 0
	var quote byte
	for i := start; i < len(body); i++ {
		c := body[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '[':
			if depth == 0 && open < 0 {
				open = i
			}
			depth++
		case ']':
			depth--
			if depth == 0 {
				close = i
			}
		case '>':
			if depth <= 0 {
				return open, close, i
			}
		}
	}
	return open, close, end
}

// injectXMLRefAfterRoot places the entity reference as the root element's first
// content node.
func injectXMLRefAfterRoot(body, ref string) (string, bool) {
	loc := xxeRootRe.FindStringIndex(body)
	if loc == nil {
		return "", false
	}
	if strings.HasSuffix(strings.TrimSpace(body[loc[0]:loc[1]]), "/>") {
		return "", false // self-closing root has no content to put a reference in
	}
	return body[:loc[1]] + ref + body[loc[1]:], true
}

// injectXMLRefIntoLeaf replaces the text of the first text-only element with the
// entity reference. A leaf value is the shape an application most often echoes
// back, which makes in-band confirmation observable without a collaborator.
func injectXMLRefIntoLeaf(body, ref string) (string, bool) {
	for _, m := range xxeRootRe.FindAllStringSubmatchIndex(body, -1) {
		if strings.HasSuffix(strings.TrimSpace(body[m[0]:m[1]]), "/>") {
			continue
		}
		name := body[m[2]:m[3]]
		rest := body[m[1]:]
		if strings.HasPrefix(rest, "<") {
			continue // nested content or an empty element, not a text leaf
		}
		idx := strings.Index(rest, "</"+name+">")
		if idx <= 0 {
			continue
		}
		if text := rest[:idx]; strings.Contains(text, "<") {
			continue
		}
		return body[:m[1]] + ref + rest[idx:], true
	}
	return "", false
}

func xmlEntityEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func (e *xxeExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, fmt.Errorf("nil request")
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	if err == nil {
		return resp, domain.OutcomeSuccess, nil
	}
	if ctx.Err() != nil {
		return nil, domain.OutcomeCancelled, ctx.Err()
	}
	return nil, domain.OutcomeError, err
}

func (e *xxeExecutor) persistEvidence(ctx context.Context, scanID domain.ID, resp *httpengine.Response, role string) ([]domain.ID, error) {
	if e.evidence == nil || resp == nil || resp.Request == nil {
		return nil, nil
	}
	var ids []domain.ID
	captured := *resp.Request
	captured.Headers = resp.Request.Headers.Clone()
	if redactRequestCookieValues(captured.Headers) {
		role += " (cookie values redacted)"
	}
	reqID, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceRequest, ".http", "message/http", dumpRequest(&captured), role+" request")
	if err != nil {
		return ids, err
	}
	ids = append(ids, reqID)
	recorded := *resp
	recorded.Headers = resp.Headers.Clone()
	note := role + " response"
	if redactSetCookieValues(recorded.Headers) {
		note += " (cookie values redacted)"
	}
	respID, err := putEvidenceBlob(ctx, e.store, e.evidence, scanID, domain.EvidenceResponse, ".http", "message/http", dumpResponse(&recorded), note)
	if err != nil {
		return ids, err
	}
	ids = append(ids, respID)
	return ids, nil
}

func (e *xxeExecutor) persistXXECase(ctx context.Context, job *domain.TestJob, d xxeDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnXXE, Status: status, Outcome: outcome, URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("xxe: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *xxeExecutor) finishXXEUnavailable(ctx context.Context, job *domain.TestJob, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnXXE, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		URL: job.Target.URL, Note: "xxe skipped: " + reason, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped xxe case: %w", err)
	}
	return nil
}

func (e *xxeExecutor) correlateXXE(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, d xxeDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	title := "XML entity expansion in an XML request body"
	summary := "An observed XML request body made the server's XML parser expand two document-internal entities and return their values. No local file or network resource was involved."
	if d.Mode == xxeModeOutOfBand {
		title = "XML external entity processing in an XML request body"
		summary = "An observed XML request body caused the server to resolve an external entity and call the collaborator."
	}
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnXXE, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title: title, Summary: summary,
		EndpointID: ep.ID, EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: xxeEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("xxe: persist finding", "scan", job.ScanID, "err", err)
	}
}

func (c *Controller) enqueueXXEProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableXXE {
		return
	}
	eps, err := c.store.Endpoints().ListByScan(ctx, scanID)
	if err != nil {
		return
	}
	// An operator-supplied XML body is an explicit override for an endpoint
	// whose body is not visible during page load (typically a form that only
	// submits XML after a click). It is never inferred and never used instead
	// of an observed body; the normal observed-body candidates below still run.
	// A collaborator is no longer required for the body to be useful: the
	// in-band internal-entity probe confirms expansion on its own.
	if sc.Config.XXEBodyURL != "" && sc.Config.XXEBody != "" {
		found := false
		for _, ep := range eps {
			if ep != nil && ep.URL == sc.Config.XXEBodyURL && ep.Method == domain.MethodPOST && isXMLBodyEndpoint(ep) {
				found = true
				break
			}
		}
		if !found {
			now := time.Now()
			ep := &domain.Endpoint{
				ID:          domain.NewID(),
				ScanID:      scanID,
				URL:         sc.Config.XXEBodyURL,
				Method:      domain.MethodPOST,
				Source:      domain.SourceUserProvided,
				ContentType: "application/xml",
				RequestBody: sc.Config.XXEBody,
				CreatedAt:   now,
			}
			if err := c.store.Endpoints().Create(ctx, ep); err != nil {
				c.log.Warn("xxe: persist operator XML body", "scan", scanID, "err", err)
			} else {
				eps = append(eps, ep)
			}
		}
	}
	for _, ep := range eps {
		if !isXMLBodyEndpoint(ep) {
			continue
		}
		now := time.Now()
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobXXE,
			State: domain.JobQueued, Priority: 47, Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL},
			MaxAttempts: 1, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("xxe: enqueue", "scan", scanID, "err", err)
		}
	}
}

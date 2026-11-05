// Package verification defines the verification contract: turning a detection
// *candidate* into a Verdict (confirmed / rejected / inconclusive) using real
// browser evidence. "Reflection alone is NOT a confirmed XSS" — verification is
// the authority that promotes a candidate to confirmed, backed by evidence. An
// LLM is never consulted for this decision (AGENTS.md §2.5): the verdict is
// produced by the deterministic signal match in signal.go.
//
// Phase 0 provided the interface and a Stub only. Phase 1 (browser.go) is the
// real, Chromium-backed implementation.
package verification

import (
	"context"
	"errors"
	"net/http"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/ratelimit"
)

// ErrNotImplemented indicates the Phase 0 stub with no behavior.
var ErrNotImplemented = errors.New("verification: not implemented in Phase 0")

// ErrUnsupportedMethod is returned when the method/body representation cannot
// be replayed as a browser document navigation (currently GET/HEAD, POST/form,
// and bounded POST/JSON are supported). The caller treats this as not attempted.
var ErrUnsupportedMethod = errors.New("verification: request method or body representation is not supported for browser navigation")

// Input is the context for one verification attempt: the candidate that
// reflected, the exact request that produced the reflection, and the
// scope/session under which to replay it.
type Input struct {
	ScanID         domain.ID
	VulnClass      domain.VulnClass
	InjectionPoint domain.InjectionPoint

	// Candidate is the detection candidate that reflected (its Value is what was
	// sent; its Source distinguishes builtin from a future advisory candidate).
	Candidate detection.Candidate
	// Marker is the bare, unique sentinel substring (the reflection probe's
	// token) embedded inside Candidate.Value. It — not the whole candidate
	// value — is what an uncaught-exception message would name, and what is
	// searched for in the rendered DOM.
	Marker string
	// Method and URL are the exact request that produced the reflection.
	// Browser document replay supports GET/HEAD, POST with LocationForm and
	// FormValues, or POST with LocationJSON, JSONBody and ContentType. Other
	// body-carrying method/location combinations are not attempted.
	Method   string
	URL      string
	Location domain.ParamLocation
	// FormValues carries the exact application/x-www-form-urlencoded body the
	// candidate step sent (every observed field, with the injection point's
	// field holding the candidate's own value) — only consulted when Method is
	// POST and Location is LocationForm.
	FormValues map[string]string
	// JSONBody carries the exact, already-mutated JSON request body produced by
	// the HTTP candidate step. It is replayed only for POST + LocationJSON.
	JSONBody []byte
	// ContentType is the observed request media type (including parameters such
	// as charset); JSON verification requires application/json or a +json type.
	ContentType string
	// ExtraHeaders, when set, carries a Header-location candidate's header
	// override (name -> the candidate's value) that must reach the
	// verifying browser context BEFORE navigation — see
	// browser.ContextOptions.ExtraHeaders. Empty for every other location.
	ExtraHeaders map[string]string
	// ExtraCookies, when set, carries a Cookie-location candidate's cookie
	// override that must reach the verifying browser context BEFORE
	// navigation (see browser.Context.SetCookies). Empty for every other
	// location.
	ExtraCookies []*http.Cookie

	// Scope gates every request the browser makes (navigation, redirects,
	// subresources) — see browser.ContextOptions.AllowRequest. A zero Scope
	// permits nothing (fails closed), matching domain.Scope's own default.
	Scope domain.Scope
	// SessionStatePath, when non-empty, seeds the browser context with the
	// scan's saved (authenticated) session material.
	SessionStatePath string
	// Limiter, when non-nil, paces this attempt's navigation with the scan's
	// shared rate limiter (see browser.NavOptions.Limiter).
	Limiter *ratelimit.Limiter
	// ProxyServer, when non-empty, routes this one verification attempt's
	// browser context through the given proxy (operator-supplied; see
	// domain.ScanConfig.ProxyPool and browser.ContextOptions.ProxyServer).
	// "" (the default) is a direct connection.
	ProxyServer string
}

// ResultEvidence carries the raw artifacts a verification attempt produced. The
// caller (the scan executor) persists these and fills Result.EvidenceRefs with
// their IDs — verification itself has no store dependency, mirroring how
// internal/detection stays pure and leaves persistence to internal/scan.
type ResultEvidence struct {
	Screenshot []byte   // PNG, nil if not captured
	DOMHTML    string   // rendered HTML at observation time
	BrowserLog []string // console errors + page errors + dialog messages, in order
}

// Result is the outcome of one verification attempt. The Verdict is
// authoritative (subject to the operator); EvidenceRefs is populated by the
// caller once Evidence has been persisted. Report is the structured detail
// meant for TestCase.Detail (mirroring detection.ReflectionReport).
type Result struct {
	Verdict      domain.Verdict
	Confidence   domain.Confidence
	Notes        string
	EvidenceRefs []domain.ID
	Evidence     ResultEvidence
	Report       *Report
}

// Verifier confirms or rejects a candidate using runtime evidence.
type Verifier interface {
	Verify(ctx context.Context, in Input) (*Result, error)
}

// Stub is the Phase 0 no-op verifier.
type Stub struct{}

// Verify implements Verifier.
func (Stub) Verify(context.Context, Input) (*Result, error) { return nil, ErrNotImplemented }

var _ Verifier = Stub{}

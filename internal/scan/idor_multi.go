package scan

// Two-account differential IDOR helper (User A vs User B).
//
// The single-session IDOR engine (internal/scan/idor.go) can only compare the
// scan's own object against a foreign IDENTIFIER: it never holds a second
// principal's session, so a target that authorizes by SESSION rather than by
// identifier is out of its reach. This file adds the complementary check for a
// caller that legitimately holds two authorized accounts:
//
//	GET/HEAD  A's resource URL  ── User A's credential  → baseline (what A sees)
//	                            ├─ User B's credential  → what B is allowed to see
//	                            └─ no credential        → public/private control
//
// All three legs are the same method, the same URL and (always) an empty body;
// only the credential changes. That isolates the authorization boundary from
// every other variable.
//
// Boundaries (non-negotiable, inherited from AGENTS.md §2 and §3):
//
//   - GET and HEAD only. A body-carrying method is refused BEFORE any request
//     is built, so this helper can never mutate target state.
//   - No request body, no Content-Type, no upload, no form submission, no
//     delete/update verb — ever, whatever the scan's own opt-ins say.
//   - At most three requests per probe: A (skipped when a baseline is
//     supplied), B, and one unauthenticated control. No retries, no
//     enumeration, no redirect following.
//   - Redirects are NOT followed (NoRedirects): one leg = exactly one
//     response, so a 302 to a login page is itself the denial signal and no
//     credential can be replayed to a different host or port by a redirect.
//   - Each leg carries exactly the credential supplied for that leg. Legs are
//     JARLESS (no ambient cookie jar from discovery, another scan or an earlier
//     leg can leak between accounts) and the control leg is NOCOOKIES, so
//     nothing at all authenticates it.
//   - A confirmation requires POSITIVE evidence (the document reproduces A's
//     content, or names A's own principal) AND the unauthenticated control
//     must not receive the same document. A resource that is simply public is
//     never reported as a cross-account exposure.
//
// Nothing here is wired into the worker/controller: handlers.go belongs to the
// wiring slice, so this is a self-contained helper/executor the controller can
// adopt without changing its shape.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
)

const (
	// multiAccountRoleA, multiAccountRoleB and multiAccountRoleAnonymous name
	// the three legs everywhere they appear (result, evidence, detail JSON).
	multiAccountRoleA       = "user_a"
	multiAccountRoleB       = "user_b"
	multiAccountRoleAnon    = "anonymous"
	multiAccountEngineName  = "idor_multi"
	multiAccountBaselineGot = "fetched"
	multiAccountBaselineSup = "supplied"

	// maxMultiAccountReadsPerProbe is the hard bound on requests one probe may
	// send: the baseline read (unless supplied), the second account's read, and
	// the unauthenticated control. Nothing in this file can exceed it.
	maxMultiAccountReadsPerProbe = 3

	// maxMultiAccountCompareBytes bounds the bytes a body comparison reads, so
	// a large document cannot make one probe expensive.
	maxMultiAccountCompareBytes = 512 << 10

	// minMultiAccountContentBytes is the smallest body the differential will
	// treat as "the resource". A tiny body (an "OK" marker, a one-line error)
	// carries too little content to tell "the same object" apart from "the same
	// generic answer", so it can never confirm.
	minMultiAccountContentBytes = 96

	// defaultMultiAccountSimilarity is the content-similarity threshold above
	// which two bodies are considered the same document.
	defaultMultiAccountSimilarity = 0.80

	// defaultMultiAccountTimeout bounds each leg's own network I/O.
	defaultMultiAccountTimeout = 15 * time.Second
)

// MultiAccountOutcome is the differential's result for one probe.
type MultiAccountOutcome string

const (
	// MultiAccountConfirmed means User B received User A's resource while the
	// unauthenticated control did not.
	MultiAccountConfirmed MultiAccountOutcome = "confirmed"
	// MultiAccountRejected means the target enforced the account boundary
	// (a denial, a login redirect, or a different document for User B).
	MultiAccountRejected MultiAccountOutcome = "rejected"
	// MultiAccountInconclusive means the comparison could not be made or
	// proved nothing either way.
	MultiAccountInconclusive MultiAccountOutcome = "inconclusive"
	// MultiAccountSkipped means the probe was refused before any request was
	// sent (unsafe method, missing credential, unusable URL).
	MultiAccountSkipped MultiAccountOutcome = "skipped"
)

// Verdict maps the differential outcome onto the domain verdict lattice.
func (o MultiAccountOutcome) Verdict() domain.Verdict {
	switch o {
	case MultiAccountConfirmed:
		return domain.VerdictConfirmed
	case MultiAccountRejected:
		return domain.VerdictRejected
	default:
		return domain.VerdictInconclusive
	}
}

// MultiAccountSubject is one account's request identity: the session cookies
// and/or headers (typically Authorization) that make a request belong to it.
// The helper never invents, imports or guesses credentials.
type MultiAccountSubject struct {
	// Label is an operator-facing name for the account ("user_a", "victim").
	// It is presentation only and is never sent anywhere.
	Label string `json:"label,omitempty"`
	// Cookies are exactly the cookies this leg sends. They are sent JARLESS, so
	// no ambient jar state joins them.
	Cookies []*http.Cookie `json:"-"`
	// Headers are additional request headers for this leg — Authorization in
	// the usual case. "Cookie" is refused here (use Cookies) so the per-leg
	// isolation guarantee cannot be bypassed by a raw header.
	Headers map[string]string `json:"-"`
}

// cosmeticHeader reports whether a header carries no identity of its own and
// therefore does not make a subject "credentialed".
func cosmeticHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "user-agent", "accept", "accept-language", "accept-encoding", "referer", "origin", "connection":
		return true
	default:
		return false
	}
}

// hasCredentials reports whether this subject carries something that can
// authenticate a request.
func (s MultiAccountSubject) hasCredentials() bool {
	for _, c := range s.Cookies {
		if c != nil && strings.TrimSpace(c.Name) != "" {
			return true
		}
	}
	for name, value := range s.Headers {
		if strings.TrimSpace(value) == "" || cosmeticHeader(name) {
			continue
		}
		return true
	}
	return false
}

// describe is the operator-facing label for a leg, never a credential value.
func (s MultiAccountSubject) describe(fallback string) string {
	if l := strings.TrimSpace(s.Label); l != "" {
		return truncate(l, 60)
	}
	return fallback
}

// MultiAccountBaseline is a User A response the caller already holds. Supplying
// it removes one request from the probe: the differential then sends only the
// second account and the unauthenticated control.
type MultiAccountBaseline struct {
	Status int
	Body   []byte
	// FinalURL is the URL the baseline was actually read from, when known.
	FinalURL string
}

// MultiAccountProbe is one two-account differential request.
type MultiAccountProbe struct {
	// Method must be GET or HEAD. Anything else is skipped before any request.
	Method domain.HTTPMethod
	// URL is User A's resource endpoint. All three legs request exactly this.
	URL string
	// UserA is User A's identity. It is only needed when BaselineA is nil.
	UserA MultiAccountSubject
	// UserB is the second account's identity. Always required.
	UserB MultiAccountSubject
	// BaselineA, when non-nil, is User A's already-observed response.
	BaselineA *MultiAccountBaseline
}

// multiAccountReadMethod reports whether a method is a strict read. HEAD is
// accepted (it is a read) but can never confirm: it carries no body.
func multiAccountReadMethod(m domain.HTTPMethod) bool {
	switch m {
	case domain.MethodGET, domain.MethodHEAD:
		return true
	default:
		return false
	}
}

// validate refuses a probe that must not touch the target. Every refusal is a
// SkipReason, never a request.
func (p MultiAccountProbe) validate() error {
	if strings.TrimSpace(p.URL) == "" {
		return errors.New("no resource URL was supplied")
	}
	u, err := url.Parse(strings.TrimSpace(p.URL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("resource URL %q is not an absolute URL", p.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("resource URL scheme %q is not http(s)", u.Scheme)
	}
	if !multiAccountReadMethod(p.Method) {
		return fmt.Errorf("method %s is state-changing; the two-account differential performs GET/HEAD reads only", p.Method)
	}
	if !p.UserB.hasCredentials() {
		return errors.New("User B has no session cookie or Authorization header; there is no second account to compare")
	}
	if p.BaselineA == nil && !p.UserA.hasCredentials() {
		return errors.New("no User A baseline response and no User A credential; the differential has no reference")
	}
	// Checked in a fixed order (A, then B) so a probe with two bad subjects
	// always reports the same reason.
	for _, role := range []string{multiAccountRoleA, multiAccountRoleB} {
		subj := p.UserA
		if role == multiAccountRoleB {
			subj = p.UserB
		}
		names := make([]string, 0, len(subj.Headers))
		for name := range subj.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := validateMultiAccountHeader(name, subj.Headers[name]); err != nil {
				return fmt.Errorf("%s: %w", role, err)
			}
		}
	}
	return nil
}

// validateMultiAccountHeader keeps the per-leg credential boundary intact and
// refuses header values that could not be sent as a plain HTTP field.
func validateMultiAccountHeader(name, value string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("an empty header name is not valid")
	}
	for _, r := range trimmed {
		if r <= ' ' || r >= 0x7f || r == ':' {
			return fmt.Errorf("header name %q is not a valid HTTP field name", name)
		}
	}
	switch strings.ToLower(trimmed) {
	case "cookie":
		return errors.New(`a raw "Cookie" header is refused: supply the cookies through MultiAccountSubject.Cookies so each leg's credential stays isolated`)
	case "host":
		return errors.New(`a "Host" override is refused: every leg must request the same origin`)
	case "content-length", "transfer-encoding", "expect":
		return fmt.Errorf("header %q is body-transport metadata and is refused: the differential never sends a body", trimmed)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("header %q contains a control character and cannot be sent as one HTTP field", trimmed)
	}
	return nil
}

// MultiAccountExchange is one leg as it was actually sent: the request the
// helper built and the response the engine returned. Both are kept so the
// caller can persist them with the same evidence helpers every other engine
// uses. They are NOT part of the detail JSON (a request object carries
// credentials, and a TestCase detail must never become a credential store).
type MultiAccountExchange struct {
	Role     string               `json:"role"`
	Request  *httpengine.Request  `json:"-"`
	Response *httpengine.Response `json:"-"`
	// Err is the transport error for this leg, "" when a response was received.
	Err string `json:"error,omitempty"`
}

// Status is the observed status code, 0 when the leg failed.
func (x MultiAccountExchange) Status() int {
	if x.Response == nil {
		return 0
	}
	return x.Response.Status
}

// MultiAccountSignals records what the three legs actually showed. It is pure
// data: the verdict is derived from it by decideMultiAccount, and the report
// can explain a confirmation without re-reading any body.
type MultiAccountSignals struct {
	AStatus             int     `json:"a_status"`
	BStatus             int     `json:"b_status"`
	AnonymousStatus     int     `json:"anonymous_status"`
	ABContentSimilarity float64 `json:"ab_content_similarity"`
	AAnonSimilarity     float64 `json:"a_anon_similarity"`
	ContentComparable   bool    `json:"content_comparable"`
	BDenied             bool    `json:"b_denied"`
	BLoginPage          bool    `json:"b_login_page"`
	BRedirected         bool    `json:"b_redirected"`
	PubliclyReadable    bool    `json:"publicly_readable"`
	NamesUserA          bool    `json:"names_user_a"`
	IdentityConflict    bool    `json:"identity_conflict"`
	AIdentity           string  `json:"a_identity,omitempty"`
	BaselineSource      string  `json:"baseline_source,omitempty"`
}

// MultiAccountResult is one probe's outcome plus the evidence handles the
// caller needs to persist and correlate it.
type MultiAccountResult struct {
	Engine  string              `json:"engine"`
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url,omitempty"`
	Outcome MultiAccountOutcome `json:"outcome"`
	Verdict domain.Verdict      `json:"verdict,omitempty"`
	Reason  string              `json:"reason,omitempty"`
	// Requests is how many HTTP requests this probe actually sent (0 for a
	// skip, 2 with a supplied baseline, otherwise at most 3).
	Requests  int                    `json:"requests"`
	Signals   MultiAccountSignals    `json:"signals"`
	Exchanges []MultiAccountExchange `json:"-"`
}

// Confirmed reports whether the probe proved cross-account exposure.
func (r MultiAccountResult) Confirmed() bool { return r.Outcome == MultiAccountConfirmed }

// EvidencePairs returns the legs that actually produced a response, in send
// order (A, B, anonymous), so the caller can persist each request/response
// pair as evidence exactly like the other engines do.
func (r MultiAccountResult) EvidencePairs() []MultiAccountExchange {
	out := make([]MultiAccountExchange, 0, len(r.Exchanges))
	for _, x := range r.Exchanges {
		if x.Request != nil && x.Response != nil {
			out = append(out, x)
		}
	}
	return out
}

// MultiAccountLegSummary is the credential-free record of one leg.
type MultiAccountLegSummary struct {
	Role       string `json:"role"`
	Status     int    `json:"status,omitempty"`
	FinalURL   string `json:"final_url,omitempty"`
	BodyBytes  int    `json:"body_bytes,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Redirected bool   `json:"redirected,omitempty"`
	Error      string `json:"error,omitempty"`
}

// MultiAccountDetail is the restart-safe, credential-free record a TestCase or
// Finding can carry: no cookies, no Authorization value, no body content.
type MultiAccountDetail struct {
	Engine   string                   `json:"engine"`
	Method   string                   `json:"method,omitempty"`
	URL      string                   `json:"url,omitempty"`
	Outcome  MultiAccountOutcome      `json:"outcome"`
	Verdict  domain.Verdict           `json:"verdict,omitempty"`
	Reason   string                   `json:"reason,omitempty"`
	Requests int                      `json:"requests"`
	Signals  MultiAccountSignals      `json:"signals"`
	Legs     []MultiAccountLegSummary `json:"legs,omitempty"`
}

// Detail builds the credential-free record for TestCase.Detail /
// Finding.Detail.
func (r MultiAccountResult) Detail() MultiAccountDetail {
	d := MultiAccountDetail{
		Engine: r.Engine, Method: r.Method, URL: r.URL, Outcome: r.Outcome,
		Verdict: r.Verdict, Reason: r.Reason, Requests: r.Requests, Signals: r.Signals,
	}
	for _, x := range r.Exchanges {
		leg := MultiAccountLegSummary{Role: x.Role, Status: x.Status(), Error: x.Err}
		if x.Response != nil {
			leg.FinalURL = x.Response.FinalURL
			leg.BodyBytes = len(x.Response.Body)
			leg.Truncated = x.Response.Truncated
			// The differential never follows a redirect, so a 3xx is the
			// response itself rather than a link in a chain.
			leg.Redirected = x.Response.Status >= 300 && x.Response.Status < 400 || len(x.Response.RedirectChain) > 0
		}
		d.Legs = append(d.Legs, leg)
	}
	return d
}

// DetailJSON is Detail encoded as JSON. It never contains a credential or a
// response body.
func (r MultiAccountResult) DetailJSON() ([]byte, error) {
	return json.Marshal(r.Detail())
}

// MultiAccountConfig tunes one executor. Zero values are the safe defaults.
type MultiAccountConfig struct {
	// RequestTimeout bounds each leg's own network I/O.
	RequestTimeout time.Duration
	// SimilarityThreshold above which two bodies are the same document
	// (default 0.80, clamped to (0,1]).
	SimilarityThreshold float64
}

func (c MultiAccountConfig) withDefaults() MultiAccountConfig {
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultMultiAccountTimeout
	}
	if c.SimilarityThreshold <= 0 || c.SimilarityThreshold > 1 {
		c.SimilarityThreshold = defaultMultiAccountSimilarity
	}
	return c
}

// MultiAccountExecutor performs two-account differential reads through an
// httpengine.Engine. The engine MUST already be scope-enforcing when it is used
// against a real target: this helper deliberately performs no scope check of
// its own (same contract as the rest of internal/scan).
type MultiAccountExecutor struct {
	engine httpengine.Engine
	cfg    MultiAccountConfig
	log    *slog.Logger
}

// NewMultiAccountExecutor returns an executor over eng. A nil logger is fine.
func NewMultiAccountExecutor(eng httpengine.Engine, cfg MultiAccountConfig, log *slog.Logger) *MultiAccountExecutor {
	return &MultiAccountExecutor{engine: eng, cfg: cfg.withDefaults(), log: log}
}

// Run performs the differential. It returns an error only when it cannot run at
// all (no engine, cancelled context); every target-observed outcome — including
// a transport failure of one leg — is a result.
func (e *MultiAccountExecutor) Run(ctx context.Context, probe MultiAccountProbe) (MultiAccountResult, error) {
	res := MultiAccountResult{Engine: multiAccountEngineName, Method: string(probe.Method), URL: probe.URL}
	if e == nil || e.engine == nil {
		return res, errors.New("idor_multi: no HTTP engine configured")
	}
	if err := probe.validate(); err != nil {
		res.Outcome = MultiAccountSkipped
		res.Verdict = domain.VerdictInconclusive
		res.Reason = "not run: " + err.Error()
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// Leg A: either the supplied baseline (no request) or one read with A's own
	// credential.
	var aEx MultiAccountExchange
	if probe.BaselineA != nil {
		aEx = MultiAccountExchange{Role: multiAccountRoleA, Response: &httpengine.Response{
			Status: probe.BaselineA.Status, Body: probe.BaselineA.Body, FinalURL: probe.BaselineA.FinalURL,
		}}
	} else {
		req, err := multiAccountLegRequest(probe.Method, probe.URL, probe.UserA, false)
		if err != nil {
			res.Outcome = MultiAccountSkipped
			res.Verdict = domain.VerdictInconclusive
			res.Reason = "not run: " + err.Error()
			return res, nil
		}
		aEx = e.read(ctx, multiAccountRoleA, req)
	}
	res.Exchanges = append(res.Exchanges, aEx)
	res.Requests = multiAccountRequestCount(res.Exchanges)

	// Leg B: exactly the second account's credential.
	bReq, err := multiAccountLegRequest(probe.Method, probe.URL, probe.UserB, false)
	if err != nil {
		res.Outcome = MultiAccountSkipped
		res.Verdict = domain.VerdictInconclusive
		res.Reason = "not run: " + err.Error()
		return res, nil
	}
	bEx := e.read(ctx, multiAccountRoleB, bReq)
	res.Exchanges = append(res.Exchanges, bEx)
	res.Requests = multiAccountRequestCount(res.Exchanges)

	// Unauthenticated control: the same URL with no credential at all.
	anonReq, err := multiAccountLegRequest(probe.Method, probe.URL, MultiAccountSubject{}, true)
	if err != nil {
		res.Outcome = MultiAccountSkipped
		res.Verdict = domain.VerdictInconclusive
		res.Reason = "not run: " + err.Error()
		return res, nil
	}
	anonEx := e.read(ctx, multiAccountRoleAnon, anonReq)
	res.Exchanges = append(res.Exchanges, anonEx)
	res.Requests = multiAccountRequestCount(res.Exchanges)
	dec := decideMultiAccount(multiAccountInput{
		Method:    probe.Method,
		A:         observeMultiAccount(aEx),
		B:         observeMultiAccount(bEx),
		Anonymous: observeMultiAccount(anonEx),
		Threshold: e.cfg.SimilarityThreshold,
	})
	res.Outcome, res.Reason, res.Signals = dec.Outcome, dec.Reason, dec.Signals
	res.Signals.BaselineSource = baselineSource(res.Exchanges)
	res.Verdict = dec.Outcome.Verdict()

	if res.Outcome == MultiAccountConfirmed && e.log != nil {
		e.log.Info("idor multi-account: confirmed cross-account exposure", "url", probe.URL, "method", probe.Method)
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	return res, nil
}

// multiAccountRequestCount reports how many legs actually reached the wire. A
// supplied baseline creates an exchange with a response but no request.
func multiAccountRequestCount(exs []MultiAccountExchange) int {
	n := 0
	for _, x := range exs {
		if x.Request != nil {
			n++
		}
	}
	return n
}

// baselineSource reads back whether the A leg was fetched or supplied.
func baselineSource(exs []MultiAccountExchange) string {
	for _, x := range exs {
		if x.Role != multiAccountRoleA {
			continue
		}
		if x.Request == nil {
			return multiAccountBaselineSup
		}
		return multiAccountBaselineGot
	}
	return ""
}

// read performs one leg. The request is cloned and given the per-leg timeout,
// so the caller's value is never mutated.
func (e *MultiAccountExecutor) read(ctx context.Context, role string, req *httpengine.Request) MultiAccountExchange {
	x := MultiAccountExchange{Role: role}
	if req == nil {
		x.Err = "no request was built"
		return x
	}
	if err := ctx.Err(); err != nil {
		x.Err = err.Error()
		return x
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	x.Request = &timed
	resp, err := e.engine.Do(ctx, &timed)
	if err != nil {
		x.Err = truncate(err.Error(), 200)
		return x
	}
	x.Response = resp
	return x
}

// multiAccountLegRequest builds one leg. The isolation flags are the whole
// point of the helper:
//
//	Jarless    the supplied Cookies are the leg's ENTIRE cookie state — no
//	           ambient jar from discovery, another scan or an earlier leg.
//	NoCookies  the control leg sends no cookie at all, and any raw Cookie
//	           header is dropped by the engine's fail-closed isolation path.
//	NoRedirects one leg = one response, so a 302 to /login is observable as
//	           such and no credential is replayed to a redirect target.
func multiAccountLegRequest(method domain.HTTPMethod, rawURL string, subj MultiAccountSubject, anonymous bool) (*httpengine.Request, error) {
	if !multiAccountReadMethod(method) {
		return nil, fmt.Errorf("method %s is not a read", method)
	}
	req := &httpengine.Request{Method: string(method), URL: rawURL, NoRedirects: true}
	if anonymous {
		req.NoCookies = true
		return req, nil
	}
	req.Jarless = true
	for _, c := range subj.Cookies {
		if c == nil {
			continue
		}
		copied := *c
		req.Cookies = append(req.Cookies, &copied)
	}
	if len(subj.Headers) > 0 {
		req.Headers = make(map[string]string, len(subj.Headers))
		for name, value := range subj.Headers {
			req.Headers[name] = value
		}
	}
	return req, nil
}

// ---------------------------------------------------------------------------
// observations and the pure decision
// ---------------------------------------------------------------------------

// multiAccountObservation is one leg reduced to what the decision needs.
type multiAccountObservation struct {
	Status   int
	Body     []byte
	Err      string
	Login    bool
	Denial   bool
	Identity idor.Identity
}

func observeMultiAccount(x MultiAccountExchange) multiAccountObservation {
	o := multiAccountObservation{Err: x.Err}
	if x.Response == nil {
		return o
	}
	o.Status = x.Response.Status
	o.Body = x.Response.Body
	o.Login = idor.LooksLikeLoginPage(o.Body)
	o.Denial = multiAccountLooksLikeDenial(o.Body)
	o.Identity = idor.ExtractIdentity(o.Body)
	return o
}

// multiAccountInput is the whole decision input, so the rule is a pure function
// of observed values and can be tested exhaustively without a server.
type multiAccountInput struct {
	Method    domain.HTTPMethod
	A         multiAccountObservation
	B         multiAccountObservation
	Anonymous multiAccountObservation
	Threshold float64
}

type multiAccountDecision struct {
	Outcome MultiAccountOutcome
	Reason  string
	Signals MultiAccountSignals
}

// decideMultiAccount is the entire verdict rule for the two-account
// differential. Ordering is deliberate: every refusal comes before every
// confirmation, and a resource that is publicly readable can never confirm.
func decideMultiAccount(in multiAccountInput) multiAccountDecision {
	dec := multiAccountDecision{Outcome: MultiAccountInconclusive}
	sig := &dec.Signals
	threshold := in.Threshold
	if threshold <= 0 || threshold > 1 {
		threshold = defaultMultiAccountSimilarity
	}
	sig.AStatus, sig.BStatus, sig.AnonymousStatus = in.A.Status, in.B.Status, in.Anonymous.Status
	sig.BDenied = in.B.Status == 401 || in.B.Status == 403
	sig.BLoginPage = in.B.Login
	sig.BRedirected = in.B.Status >= 300 && in.B.Status < 400
	if !in.A.Identity.Empty() {
		sig.AIdentity = describeIdentity(in.A.Identity)
	}

	// Transport failures: nothing was observed, so nothing can be concluded.
	if in.A.Err != "" {
		return inconclusive(dec, "the User A baseline request failed ("+in.A.Err+"); the differential has no reference")
	}
	if in.B.Err != "" {
		return inconclusive(dec, "the User B request failed ("+in.B.Err+"); its access could not be observed")
	}
	if in.Anonymous.Err != "" {
		return inconclusive(dec, "the unauthenticated control request failed ("+in.Anonymous.Err+"); whether the resource is simply public cannot be answered")
	}

	// A HEAD response always has an empty body, so a HEAD differential can
	// never prove content exposure. Stated before the body checks so the reason
	// names the real limitation instead of "body too small".
	if in.Method == domain.MethodHEAD {
		return inconclusive(dec, "a HEAD response carries no body: the content cannot be compared, rerun with GET")
	}

	// The baseline must be a real read of the resource. A denied, redirected,
	// login or error baseline cannot be the reference for a comparison.
	if in.A.Status < 200 || in.A.Status >= 300 {
		return inconclusive(dec, fmt.Sprintf("the User A baseline was not a successful read (HTTP %d); the differential has no reference", in.A.Status))
	}
	if in.A.Login {
		return inconclusive(dec, "the User A baseline is a login page: User A's session did not reach the resource")
	}
	if in.A.Denial {
		return inconclusive(dec, "the User A baseline is a denial/notice page, not the resource")
	}
	if len(bytes.TrimSpace(in.A.Body)) < minMultiAccountContentBytes {
		return inconclusive(dec, "the User A baseline body is too small to compare")
	}

	// The second account's own access. A denial is the boundary working.
	if sig.BDenied {
		return rejected(dec, fmt.Sprintf("User B was denied the resource (HTTP %d): the account boundary is enforced", in.B.Status))
	}
	if in.B.Status >= 500 {
		return inconclusive(dec, fmt.Sprintf("User B received HTTP %d: no access decision could be observed", in.B.Status))
	}
	if in.B.Status >= 400 {
		return inconclusive(dec, fmt.Sprintf("User B received HTTP %d: the resource was neither served nor clearly denied", in.B.Status))
	}
	if in.B.Login {
		return rejected(dec, "User B's session did not reach the resource (a login page was returned): the account is not authorized")
	}

	bBody := bytes.TrimSpace(in.B.Body)
	if len(bBody) < minMultiAccountContentBytes {
		if sig.BRedirected {
			return rejected(dec, fmt.Sprintf("User B was redirected (HTTP %d) instead of receiving the document", in.B.Status))
		}
		return inconclusive(dec, "User B's response body is too small to compare")
	}

	// Content signals (computed once).
	abSim, abOK := multiAccountSimilarity(in.A.Body, in.B.Body)
	anSim, anOK := multiAccountSimilarity(in.A.Body, in.Anonymous.Body)
	sig.ABContentSimilarity, sig.AAnonSimilarity = roundSimilarity(abSim), roundSimilarity(anSim)
	sig.ContentComparable = abOK

	// Identity signals between the two documents.
	sig.NamesUserA = multiAccountNamesOnlyPrincipal(in.A.Identity, in.B.Identity)
	sig.IdentityConflict = multiAccountIdentityConflict(in.A.Identity, in.B.Identity)

	// The unauthenticated control. If a request with no credential at all
	// receives the SAME document (or one naming A's principal), the resource is
	// public: that is an exposure in its own right, but it is NOT evidence that
	// one account can read another account's data, and this engine must not
	// claim it.
	//
	// The control's own document is what decides this — not B's — so a
	// generic public page served to the control cannot mask a real
	// cross-account exposure.
	anonReached := in.Anonymous.Status >= 200 && in.Anonymous.Status < 400 &&
		len(bytes.TrimSpace(in.Anonymous.Body)) >= minMultiAccountContentBytes &&
		!in.Anonymous.Login && !in.Anonymous.Denial
	anonNamesA := multiAccountNamesOnlyPrincipal(in.A.Identity, in.Anonymous.Identity)
	sig.PubliclyReadable = anonReached && (anonNamesA || (anOK && anSim >= threshold))
	if sig.PubliclyReadable {
		return inconclusive(dec, "the unauthenticated control also received this document, so the resource is publicly readable: no cross-account boundary is demonstrated by this differential")
	}

	// A denial page served with 200 is also the boundary working, provided it
	// is not simply A's own document.
	if in.B.Denial && !(abOK && abSim >= threshold) {
		return rejected(dec, "User B received a denial/notice page instead of the resource: the account boundary is enforced")
	}

	// 1. Strongest positive signal: User B's document names User A's principal
	//    (and no other principal of that kind).
	if sig.NamesUserA {
		reason := fmt.Sprintf("User B's response identifies User A's principal (%s), i.e. User B was served User A's object", sig.AIdentity)
		if sig.BRedirected {
			reason = fmt.Sprintf("the redirect response (HTTP %d) leaked User A's object instead of sending only a Location: User B's response identifies %s", in.B.Status, sig.AIdentity)
		}
		return confirmed(dec, reason)
	}

	// 2. User B's document identifies a DIFFERENT principal than User A's while
	//    the two bodies are textually the same (the classic "same template,
	//    your own row" case). That is per-account scoping, not exposure.
	if sig.IdentityConflict && abOK && abSim >= threshold {
		return rejected(dec, "User B's response identifies a different principal than User A's baseline, so the response did not reproduce User A's object")
	}

	// 3. The same document was served to User B's session.
	if abOK && abSim >= threshold {
		reason := fmt.Sprintf("User B's response is the same document as User A's baseline (content similarity %.2f), while the unauthenticated control did not receive it", roundSimilarity(abSim))
		if sig.BRedirected {
			reason = fmt.Sprintf("the redirect response (HTTP %d) carried User A's document (content similarity %.2f) instead of a bare Location", in.B.Status, roundSimilarity(abSim))
		}
		return confirmed(dec, reason)
	}

	if sig.IdentityConflict {
		return rejected(dec, "User B's response identifies a different principal and does not reproduce User A's document")
	}
	if abOK {
		return rejected(dec, fmt.Sprintf("User B received a different document from User A's baseline (content similarity %.2f): the object is scoped per account", roundSimilarity(abSim)))
	}
	if sig.BRedirected {
		return rejected(dec, fmt.Sprintf("User B was redirected (HTTP %d) instead of receiving the document", in.B.Status))
	}
	return inconclusive(dec, "the two documents carried too little comparable content to decide")
}

func confirmed(dec multiAccountDecision, reason string) multiAccountDecision {
	dec.Outcome, dec.Reason = MultiAccountConfirmed, truncate(reason, 500)
	return dec
}

func rejected(dec multiAccountDecision, reason string) multiAccountDecision {
	dec.Outcome, dec.Reason = MultiAccountRejected, truncate(reason, 500)
	return dec
}

func inconclusive(dec multiAccountDecision, reason string) multiAccountDecision {
	dec.Outcome, dec.Reason = MultiAccountInconclusive, truncate(reason, 500)
	return dec
}

// ---------------------------------------------------------------------------
// content comparison
// ---------------------------------------------------------------------------

// multiAccountTokenRE is the tokenizer used when a document has too few lines
// to compare line-by-line (minified HTML, JSON on one line). It keeps
// identifier-shaped runs together — e-mail addresses, dotted keys, UUIDs — so
// a JSON document still yields a comparable token set.
var multiAccountTokenRE = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9@._:\-]{2,}`)

// multiAccountSimilarity compares two response bodies deterministically and
// reports whether they carried enough content to be compared at all. It is a
// symmetric Jaccard score over line sets, falling back to token sets for
// documents with too few lines. Identical bodies score 1.0.
func multiAccountSimilarity(a, b []byte) (float64, bool) {
	if len(a) > maxMultiAccountCompareBytes {
		a = a[:maxMultiAccountCompareBytes]
	}
	if len(b) > maxMultiAccountCompareBytes {
		b = b[:maxMultiAccountCompareBytes]
	}
	if len(bytes.TrimSpace(a)) == 0 || len(bytes.TrimSpace(b)) == 0 {
		return 0, false
	}
	if bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b)) {
		return 1, true
	}

	if aLines, bLines := multiAccountLineSet(a), multiAccountLineSet(b); len(aLines) >= 4 && len(bLines) >= 4 {
		return multiAccountJaccard(aLines, bLines), true
	}

	aTokens, bTokens := multiAccountTokenSet(a), multiAccountTokenSet(b)
	if len(aTokens)+len(bTokens) < 8 {
		return 0, false
	}
	return multiAccountJaccard(aTokens, bTokens), true
}

func multiAccountLineSet(body []byte) map[string]struct{} {
	set := map[string]struct{}{}
	for _, line := range bytes.Split(body, []byte("\n")) {
		t := strings.TrimSpace(string(line))
		if len(t) < 2 {
			continue
		}
		set[t] = struct{}{}
	}
	return set
}

func multiAccountTokenSet(body []byte) map[string]struct{} {
	set := map[string]struct{}{}
	for _, tok := range multiAccountTokenRE.FindAll(body, -1) {
		set[strings.ToLower(string(tok))] = struct{}{}
	}
	return set
}

func multiAccountJaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// roundSimilarity keeps persisted signals stable and readable (two decimals).
func roundSimilarity(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

// ---------------------------------------------------------------------------
// identity and denial helpers
// ---------------------------------------------------------------------------

// multiAccountNamesOnlyPrincipal reports whether B's document names A's own
// principal and no other principal of the same kind. A listing page that also
// contains A's name is NOT proof that B was served A's object, so it is
// excluded here.
func multiAccountNamesOnlyPrincipal(a, b idor.Identity) bool {
	if a.Empty() || b.Empty() {
		return false
	}
	matchedKinds := 0
	for _, af := range a.Fields {
		comparable, clean := 0, true
		for _, bf := range b.Fields {
			if bf.Kind != af.Kind {
				continue
			}
			comparable++
			if !strings.EqualFold(strings.TrimSpace(bf.Value), strings.TrimSpace(af.Value)) {
				clean = false
			}
		}
		if comparable == 0 {
			continue // nothing comparable in B for this kind
		}
		if !clean {
			return false // B names another principal of this kind
		}
		matchedKinds++
	}
	return matchedKinds > 0
}

// multiAccountIdentityConflict reports whether the two documents identify
// principals that share a comparable field but disagree on every one of them.
func multiAccountIdentityConflict(a, b idor.Identity) bool {
	if a.Empty() || b.Empty() {
		return false
	}
	comparable, matchedAny := 0, false
	for _, af := range a.Fields {
		for _, bf := range b.Fields {
			if af.Kind != bf.Kind {
				continue
			}
			comparable++
			if strings.EqualFold(strings.TrimSpace(af.Value), strings.TrimSpace(bf.Value)) {
				matchedAny = true
			}
		}
	}
	return comparable > 0 && !matchedAny
}

// describeIdentity is the operator-facing, bounded description of an extracted
// identity ("username=alice").
func describeIdentity(i idor.Identity) string {
	if i.Empty() {
		return ""
	}
	f := i.Fields[0]
	return truncate(string(f.Kind)+"="+f.Value, 120)
}

// multiAccountDenialPhrases is the small, fixed vocabulary of an authorization
// refusal rendered as a normal page. It is only ever used to REFUSE a
// confirmation, never to create one.
var multiAccountDenialPhrases = []string{
	"access denied",
	"access is denied",
	"permission denied",
	"not authorized",
	"not authorised",
	"unauthorized access",
	"unauthorised access",
	"you do not have permission",
	"you don't have permission",
	"insufficient privileges",
	"insufficient permissions",
	"login required",
	"please log in",
	"please sign in",
	"session has expired",
	"session expired",
	"forbidden",
}

// multiAccountLooksLikeDenial reports whether a body is an authorization
// refusal page rather than the resource.
func multiAccountLooksLikeDenial(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	// Only the first slice of a document is inspected: a refusal is stated up
	// front, while a legitimate page may mention "forbidden" far down in prose.
	const limit = 8 << 10
	if len(body) > limit {
		body = body[:limit]
	}
	lower := strings.ToLower(string(body))
	for _, phrase := range multiAccountDenialPhrases {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

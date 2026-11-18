package scan

// Server-side request forgery (SSRF) engine.
//
// One JobSSRF is enqueued per eligible injection point. The engine sends one
// baseline request and then substitutes ONE parameter with a canary URL — a
// value whose only job is to make the server resolve or fetch something the
// scanner can observe. Nothing else about the request changes.
//
// Applicability. A parameter is a candidate when its name denotes an outbound
// URL (url/uri/href/link/callback/webhook/feed/rss/proxy/redirect/avatar/
// image/endpoint/host/target/destination/... — matched as words, so
// "callback_url", "callbackURL" and "imageUrl" all qualify) or when the crawl
// observed an absolute http(s) URL in it. Candidates are accepted in the query
// string, a urlencoded or JSON body, and request headers; structural headers
// (Host, Cookie, Authorization, Content-Type, ...) and anti-CSRF/session tokens
// are never substituted.
//
// SAFETY POLICY — this engine never probes an internal address:
//   - The canary is either the operator's configured OAST callback with a
//     unique correlation token appended, or a host under the RFC 2606 reserved
//     ".invalid" TLD, which is permanently unresolvable. Nothing is reached
//     through the latter.
//   - Cloud instance-metadata endpoints, loopback, link-local, unspecified/
//     multicast addresses, CGNAT and mDNS/private host suffixes are REFUSED
//     even when an operator configured them as the callback. Such a canary
//     would ask the target to request its own host or the operator's LAN —
//     exactly the internal-network probe (and cloud-metadata read) this engine
//     must never perform. A refused callback is recorded as a skip reason,
//     never substituted.
//   - A literal RFC 1918/ULA collaborator address (a lab OAST listener such as
//     192.168.103.1:8751 for a target at 192.168.103.20) is refused too UNLESS
//     the operator opts in with ExecutorConfig.AllowPrivateOAST
//     (`-allow-private-oast` on `indago serve`, or allow_private_oast on a
//     scan): a collaborator on the target's own private network is a
//     deliberate authorized lab deployment, and the one case where "the
//     operator's LAN" IS the thing under test. That opt-in relaxes nothing
//     else — loopback, link-local/metadata, unspecified, multicast and CGNAT
//     stay refused (see ssrfForbiddenCanaryHost).
//   - No file read, no cloud API call, no payload beyond a URL, and no
//     state-changing request without the scan's explicit opt-in.
//
// A verdict is CONFIRMED only on evidence the TARGET produced:
//   - OAST: the collaborator received the exact token of the canary this probe
//     sent. Only a request made by the target can put that token there.
//   - Error differential: over a clean 2xx baseline, TWO independent canary
//     tokens each made the response report a resolver/dial/fetch failure the
//     baseline did not have. Naming the injected token is the stronger form
//     and is conclusive on its own, but it is not required: a target that
//     answers a generic 500/502/504 or a generic connectivity message
//     ("Could not connect to external stock check service") without ever
//     echoing the URL is still confirmed, because neither canary can make an
//     otherwise-working endpoint start failing. One indicator, or any
//     differential over a baseline that was not a clean 2xx, is INCONCLUSIVE.
//
// Reflection of the canary, an ordinary redirect, a URL-validation complaint,
// one indicator or a transport error are never promoted to a finding.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const (
	ssrfEngine = "ssrf"

	// ssrfVulnClass is declared here, not in internal/domain, so this engine
	// lands without touching the shared domain model (QA/QC wires the job type
	// after merge). Its value is what the corresponding domain constant will
	// be, so the swap is a rename only.
	ssrfVulnClass domain.VulnClass = domain.VulnSSRF

	// ssrfConfirmOAST / ssrfConfirmDifferential are the two confirmation
	// methods this engine can report; ssrfModeDifferential is the matching
	// canary kind (an unresolvable ".invalid" host).
	ssrfConfirmOAST         = "oast"
	ssrfConfirmDifferential = "error-differential"
	ssrfModeDifferential    = "differential"

	// ssrfCanaryTLD is reserved by RFC 2606 and can never resolve, which is
	// what makes the differential probe harmless: even a target that fully
	// fetches the value reaches nothing.
	ssrfCanaryTLD = "invalid"

	// maxSSRFDifferentialProbes bounds the differential pass. Two independent
	// tokens are required because a single error string is weak evidence.
	maxSSRFDifferentialProbes = 2

	// ssrfPollAttempts/ssrfPollInterval bound how long the collaborator is
	// polled for one canary; ssrfPollTimeout bounds one poll request.
	ssrfPollAttempts = 8
	ssrfPollInterval = time.Second
	ssrfPollTimeout  = 10 * time.Second
	ssrfPollBodyMax  = 1 << 20
)

var (
	// ssrfFetchFailureIndicators are substrings a server's HTTP client (or its
	// language runtime) emits when IT failed to resolve or connect to a URL the
	// request supplied. Only these can confirm: each implies the server itself
	// ran a resolver or dialer on our canary.
	//
	// The last group is deliberately generic connectivity wording: many
	// applications wrap the client error in their own message ("Could not
	// connect to external stock check service") and never echo the URL. Such a
	// phrase is weak ON ITS OWN — decideSSRF only accepts it as a differential
	// over a clean 2xx baseline, from two independent canaries — but without it
	// a genuine non-echoing SSRF was reported inconclusive.
	ssrfFetchFailureIndicators = []string{
		// Resolver-level failures: the name could not be looked up at all.
		"no such host",
		"name or service not known",
		"nodename nor servname provided",
		"temporary failure in name resolution",
		"could not resolve host",
		"could not be resolved",
		"failed to resolve",
		"unable to resolve",
		"unknown host",
		"getaddrinfo",
		"eai_again",
		"enotfound",
		"dns lookup",
		// Dial-level failures: the name resolved (or was not needed) and the
		// connection itself failed.
		"dial tcp",
		"connection refused",
		"connection failed",
		"network is unreachable",
		"no route to host",
		"host unreachable",
		// Generic connectivity wording (weak on its own; see above).
		"could not connect",
		"couldn't connect",
		"failed to connect",
		"unable to connect",
		"could not be reached",
		"failed to fetch",
		"could not fetch",
		"unable to fetch",
	}

	// ssrfURLParsingIndicators are weaker: they show the value reached a URL
	// parser, which is a precondition for SSRF but not proof of a request. They
	// are recorded for triage only and never decide a verdict.
	ssrfURLParsingIndicators = []string{
		"invalid url",
		"invalid uri",
		"not a valid url",
		"malformed url",
		"unsupported protocol scheme",
	}

	// ssrfMetadataHosts are the well-known instance-metadata service names and
	// aliases. They are refused as a canary host regardless of configuration,
	// and never fetched by this scanner itself.
	ssrfMetadataHosts = map[string]bool{
		"metadata":                   true,
		"metadata.google.internal":   true,
		"metadata.goog":              true,
		"instance-data":              true,
		"instance-data.ec2.internal": true,
		"kubernetes.default":         true,
		"kubernetes.default.svc":     true,
	}

	// ssrfLoopbackHosts are the conventional loopback aliases. A target asked
	// to request one is only talking to itself, which is the canonical SSRF
	// probe and never a useful canary.
	ssrfLoopbackHosts = map[string]bool{
		"localhost":             true,
		"localhost.localdomain": true,
		"ip6-localhost":         true,
		"ip6-loopback":          true,
	}

	// ssrfPrivateHostSuffixes are DNS suffixes used for loopback/mDNS/private
	// naming. A collaborator never legitimately lives there, so a canary that
	// does is treated as an internal probe.
	ssrfPrivateHostSuffixes = []string{".localhost", ".local", ".internal", ".home.arpa"}

	// ssrfNonURLHeaders are request headers that are never an outbound-URL
	// sink: overriding them would break the request rather than test anything.
	ssrfNonURLHeaders = map[string]bool{
		"host":              true,
		"cookie":            true,
		"authorization":     true,
		"content-length":    true,
		"content-type":      true,
		"connection":        true,
		"transfer-encoding": true,
	}
)

type ssrfCanary struct {
	// URL is the exact value substituted into the parameter.
	URL string
	// Token is the unique correlation token embedded in URL.
	Token string
	// Kind is ssrfConfirmOAST or ssrfModeDifferential — which evidence channel
	// canary can produce.
	Kind string
	// Private records that URL's host is a literal RFC 1918/ULA address, which
	// only happens with the AllowPrivateOAST opt-in. Carried into the case
	// detail so a lab-confirmed finding is identifiable as such.
	Private bool
}

type ssrfAttempt struct {
	Payload    string `json:"payload"` // truncated canary URL actually substituted
	Kind       string `json:"kind,omitempty"`
	Token      string `json:"token,omitempty"`
	Status     int    `json:"status,omitempty"`
	Callback   bool   `json:"callback"`
	Indicator  string `json:"indicator,omitempty"`
	Attributed bool   `json:"attributed,omitempty"`
	// NewFailure records a fetch-failure indicator the untouched baseline did
	// not have, in a shape the differential may treat as canary-induced (see
	// ssrfNewFetchFailure). Without it a target that answers a generic
	// 500/502/504 — without echoing the URL — could never be confirmed.
	NewFailure bool `json:"new_failure,omitempty"`
	// ParsedURL records that the response complained about the value's URL
	// syntax. Triage only: it never contributes to a verdict.
	ParsedURL bool `json:"parsed_url,omitempty"`
}

type ssrfDetail struct {
	Engine          string               `json:"engine"`
	Parameter       string               `json:"parameter"`
	Location        domain.ParamLocation `json:"location"`
	BaselineStatus  int                  `json:"baseline_status,omitempty"`
	BaselineFailure string               `json:"baseline_indicator,omitempty"`
	CallbackMode    string               `json:"callback_mode,omitempty"`
	CallbackNote    string               `json:"callback_note,omitempty"`
	// PrivateCanary records that the OAST canary pointed at a literal private
	// (RFC 1918/ULA) collaborator, i.e. the AllowPrivateOAST opt-in was used.
	PrivateCanary   bool           `json:"private_canary,omitempty"`
	Attempts        []ssrfAttempt  `json:"attempts,omitempty"`
	SentCount       int            `json:"sent_count"`
	ConfirmedCount  int            `json:"confirmed_count"`
	NewFailureCount int            `json:"new_failure_count,omitempty"`
	AttributedCount int            `json:"attributed_count,omitempty"`
	ConfirmMethod   string         `json:"confirm_method,omitempty"`
	Verdict         domain.Verdict `json:"verdict"`
	Reason          string         `json:"reason,omitempty"`
	EvidenceIDs     []domain.ID    `json:"evidence_ids,omitempty"`
}

type ssrfExecutor struct {
	store      store.Store
	engine     httpengine.Engine
	evidence   evidence.Store
	cfg        ExecutorConfig
	log        *slog.Logger
	findingsMu *sync.Mutex

	callbackURL     string
	callbackPollURL string

	// pollAttempts/pollInterval bound collaborator polling. Fields (not
	// constants) so tests can shorten the wait without changing behavior.
	pollAttempts int
	pollInterval time.Duration
}

// NewSSRFExecutorForTest exposes the executor to tests without exporting
// production wiring.
func NewSSRFExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *ssrfExecutor {
	return newSSRFExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newSSRFExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *ssrfExecutor {
	if findingsMu == nil {
		findingsMu = &sync.Mutex{}
	}
	return &ssrfExecutor{
		store: st, engine: eng, evidence: ev, cfg: cfg.withDefaults(), log: log,
		findingsMu: findingsMu, pollAttempts: ssrfPollAttempts, pollInterval: ssrfPollInterval,
	}
}

// withCallback sets the operator's OAST collaborator: callbackURL is the base
// the target is asked to request, pollURL is where this engine reads received
// requests. Both are required for OAST mode. A callback host that resolves to
// loopback, an instance-metadata alias, or (without the AllowPrivateOAST
// opt-in) a private range is refused at use time and never substituted (see
// ssrfOASTCanary).
func (e *ssrfExecutor) withCallback(callbackURL, pollURL string) {
	e.callbackURL = strings.TrimSpace(callbackURL)
	e.callbackPollURL = strings.TrimSpace(pollURL)
}

var _ worker.Handler = (*ssrfExecutor)(nil)

func (e *ssrfExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve ssrf target: %w", err)
	}
	if focus == nil {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !ssrfInjectableLocation(focus.Location) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "parameter location cannot carry an outbound URL")
	}
	if focus.Location == domain.LocationHeader && ssrfNonURLHeaders[strings.ToLower(strings.TrimSpace(focus.Name))] {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "header is structural, not an outbound-URL sink")
	}
	if !ssrfCandidateParameter(focus) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "parameter is not URL-like")
	}
	if isDynamicTokenName(focus.Name) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "parameter looks like an anti-CSRF/session token")
	}
	if (focus.Location == domain.LocationForm || focus.Location == domain.LocationJSON) && !hasBody(ep.Method) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "body parameter on a method that carries no body")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}
	if isWriteLikeEndpoint(ep, params) && (!e.cfg.AllowStateChanging || e.cfg.SkipWriteEndpoints) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}

	params = ssrfFillEmptyParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build ssrf baseline: %w", err)
	}
	baseResp, outcome, reqErr := e.do(ctx, base)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishSSRFError(ctx, job, started, ep, focus, outcome, reqErr)
	}

	d := ssrfDetail{Engine: ssrfEngine, Parameter: focus.Name, Location: focus.Location, BaselineStatus: baseResp.Status}
	baselineEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "ssrf baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baselineEvidence...)
	baseBody := string(baseResp.Body)
	d.BaselineFailure = ssrfFetchFailureIndicator(baseBody)

	// Probe 1 — the operator's collaborator, when one is configured. A hit
	// naming our token is conclusive on its own: the token exists only in the
	// value the target itself was asked to fetch.
	if e.callbackURL != "" && e.callbackPollURL != "" {
		canary, canaryErr := ssrfOASTCanary(e.callbackURL, e.cfg.AllowPrivateOAST)
		poll, pollErr := ssrfPollURL(e.callbackPollURL)
		switch {
		case canaryErr != nil:
			// A misconfigured or forbidden collaborator is recorded, never
			// substituted. The safe differential pass below still runs.
			d.CallbackMode = ssrfModeDifferential
			d.CallbackNote = truncate(canaryErr.Error(), 300)
			e.log.Warn("ssrf: collaborator refused", "scan", job.ScanID, "err", canaryErr)
		case pollErr != nil:
			// The poll URL is fetched by THIS scanner. An instance-metadata
			// address is never a collaborator, so it is refused here too.
			d.CallbackMode = ssrfModeDifferential
			d.CallbackNote = truncate(pollErr.Error(), 300)
			e.log.Warn("ssrf: collaborator poll refused", "scan", job.ScanID, "err", pollErr)
		default:
			d.CallbackMode = ssrfConfirmOAST
			d.PrivateCanary = canary.Private
			attempt, sent := e.probe(ctx, job, ep, params, focus, canary, &d)
			if sent {
				d.SentCount++
			}
			if sent && e.callbackSeen(ctx, poll, canary.Token) {
				attempt.Callback = true
				d.ConfirmedCount = 1
				d.ConfirmMethod = ssrfConfirmOAST
			}
			d.Attempts = append(d.Attempts, attempt)
		}
	} else {
		d.CallbackMode = ssrfModeDifferential
	}

	// Probe 2 — the safe response differential: two independent unresolvable
	// canaries. Skipped once OAST confirmed (no extra traffic needed) and when
	// the baseline already emits a fetch-failure indicator, because then the
	// differential cannot attribute anything to us.
	if d.ConfirmMethod == "" {
		if d.BaselineFailure == "" {
			for i := 0; i < maxSSRFDifferentialProbes; i++ {
				canary, err := ssrfDifferentialCanary()
				if err != nil {
					break
				}
				attempt, sent := e.probe(ctx, job, ep, params, focus, canary, &d)
				if sent {
					d.SentCount++
				}
				if sent && attempt.Indicator != "" {
					attempt.NewFailure = ssrfNewFetchFailure(attempt, d.BaselineStatus, baseBody)
					d.ConfirmedCount++
					if attempt.NewFailure {
						d.NewFailureCount++
					}
					if attempt.Attributed {
						d.AttributedCount++
					}
				}
				d.Attempts = append(d.Attempts, attempt)
			}
		}
	}

	e.decideSSRF(&d)
	if d.Verdict == domain.VerdictConfirmed {
		e.persistSSRFCase(ctx, job, ep, focus, d, "confirmed server-side request forgery via "+d.ConfirmMethod)
		e.correlateSSRF(ctx, job, ep, focus, d)
		return nil
	}
	e.persistSSRFCase(ctx, job, ep, focus, d, ssrfNote(d))
	return nil
}

// decideSSRF fills d.Verdict and d.Reason from the attempts already recorded.
//
// The differential arm has two strengths. A response that NAMES the injected
// token is conclusive by itself. Without it, the arm still confirms when the
// untouched baseline was a clean 2xx and every independent canary turned the
// endpoint into a fetch failure the baseline did not report: applications that
// merely echo a generic error ("Could not connect to external stock check
// service") never name our token, and requiring the echo reported real
// non-echoing SSRF as inconclusive. The guards that keep that honest live in
// ssrfNewFetchFailure and ssrfBaselineSucceeded — a single indicator, a 3xx/4xx
// canary response, a baseline that already failed, or a baseline that was not
// 2xx all stay inconclusive.
//
// The non-echoing form is inherently weaker than an echoed token: an
// application that answers ANY value it cannot reach with the same generic
// connectivity message looks identical this way, which is why a differential
// confirmation stays Medium confidence and the OAST path (a callback only the
// target itself can produce) remains the authoritative one.
func (e *ssrfExecutor) decideSSRF(d *ssrfDetail) {
	switch {
	case d.ConfirmMethod == ssrfConfirmOAST:
		d.Verdict = domain.VerdictConfirmed
		d.Reason = "the target requested the canary: the collaborator received the unique correlation token"
	case d.BaselineFailure != "":
		// Every response, including the untouched baseline, reports a fetch
		// failure; nothing can be attributed to a canary.
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "the baseline response already reports a fetch failure (" + d.BaselineFailure + "), so the response differential cannot attribute one to the canary"
	case d.ConfirmedCount >= maxSSRFDifferentialProbes && d.AttributedCount > 0:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = ssrfConfirmDifferential
		d.Reason = "two independent canaries each produced a resolver/dial failure the baseline did not, attributable to the injected value"
	case d.NewFailureCount >= maxSSRFDifferentialProbes && ssrfBaselineSucceeded(*d):
		// The non-echoing form: the URL never comes back in the response, but
		// two independent canaries each turned a clean 2xx baseline into a
		// server error / fetch failure it did not have before.
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = ssrfConfirmDifferential
		d.Reason = "two independent canaries each made a clean baseline report a resolver/dial/fetch failure it did not have before; the endpoint fetches the injected URL"
	case d.ConfirmedCount >= maxSSRFDifferentialProbes:
		d.Verdict = domain.VerdictInconclusive
		if !ssrfBaselineSucceeded(*d) {
			d.Reason = fmt.Sprintf("two canaries produced a resolver/dial failure, but the baseline answered %d instead of a clean 2xx, so the failure cannot be attributed to the canary; out-of-band confirmation is required", d.BaselineStatus)
		} else {
			d.Reason = "two canaries produced a resolver/dial failure, but not as a new failure over the clean baseline (the canary response was not a server error), and the response never names the injected value; out-of-band confirmation is required"
		}
	case d.ConfirmedCount == 1:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one canary produced a resolver/dial failure; a second independent canary is required"
	case d.SentCount == 0:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "no canary could be sent; the parameter was left untouched"
	default:
		d.Verdict = domain.VerdictRejected
	}
	if d.Verdict == domain.VerdictRejected && d.Reason == "" {
		d.Reason = "no request attributable to a canary was observed"
	}
}

// ssrfNewFetchFailure reports whether one canary attempt produced a
// fetch-failure signal the untouched baseline did not have, in a shape the
// differential may treat as canary-induced: the response carries a resolver/
// dial indicator that is absent from the baseline body, and either the
// endpoint moved to a server-error status (the generic 500/502/504 a
// non-echoing target returns) or it kept a success status while now carrying
// the failure text.
//
// A 3xx/4xx canary response never qualifies: that is the application
// rejecting the value, not its HTTP client failing to reach it.
func ssrfNewFetchFailure(a ssrfAttempt, baselineStatus int, baselineBody string) bool {
	indicator := strings.ToLower(strings.TrimSpace(a.Indicator))
	if indicator == "" {
		return false
	}
	if strings.Contains(strings.ToLower(baselineBody), indicator) {
		return false
	}
	if a.Status >= 500 {
		return true
	}
	return ssrfSuccessStatus(a.Status) && ssrfSuccessStatus(baselineStatus)
}

// ssrfBaselineSucceeded reports whether the untouched baseline was a clean 2xx
// with no fetch-failure indicator — the only shape in which a canary-induced
// server error can be attributed to the canary rather than to the endpoint's
// normal error behaviour.
func ssrfBaselineSucceeded(d ssrfDetail) bool {
	return d.BaselineFailure == "" && ssrfSuccessStatus(d.BaselineStatus)
}

func ssrfSuccessStatus(status int) bool { return status >= 200 && status < 300 }

func ssrfNote(d ssrfDetail) string {
	switch {
	case d.Verdict == domain.VerdictConfirmed:
		return "confirmed server-side request forgery: the target requested a canary URL"
	case d.Verdict == domain.VerdictInconclusive:
		return "ssrf inconclusive: " + d.Reason
	default:
		return "no server-side request to the canary observed"
	}
}

// probe substitutes one canary into the focused parameter and records what the
// response says. It returns the attempt record and whether the request was
// actually sent (a build failure sends nothing).
func (e *ssrfExecutor) probe(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter, canary ssrfCanary, d *ssrfDetail) (ssrfAttempt, bool) {
	attempt := ssrfAttempt{Payload: truncate(canary.URL, 300), Kind: canary.Kind, Token: canary.Token}
	params = ssrfFillEmptyParams(e.refreshParams(ctx, ep, params, focus), focus)
	req, err := buildRequest(ep, params, &injection{param: focus, value: canary.URL})
	if err != nil {
		e.log.Warn("ssrf: build canary request", "scan", job.ScanID, "err", err)
		return attempt, false
	}
	resp, outcome, reqErr := e.do(ctx, req)
	if resp == nil {
		if reqErr != nil {
			e.log.Debug("ssrf: canary request failed", "scan", job.ScanID, "err", reqErr)
		}
		return attempt, false
	}
	attempt.Status = resp.Status
	body := string(resp.Body)
	attempt.Indicator = ssrfFetchFailureIndicator(body)
	attempt.ParsedURL = ssrfURLParsingIndicator(body) != ""
	attempt.Attributed = strings.Contains(strings.ToLower(body), strings.ToLower(canary.Token))
	ev, _ := e.persistEvidence(ctx, job.ScanID, resp, "ssrf canary "+canary.Kind)
	d.EvidenceIDs = append(d.EvidenceIDs, ev...)
	return attempt, outcome == domain.OutcomeSuccess
}

// callbackSeen polls the operator's collaborator for the exact token this
// probe carried. Only the POLL endpoint is read; the canary itself is never
// requested by this scanner.
func (e *ssrfExecutor) callbackSeen(ctx context.Context, poll, token string) bool {
	poll = strings.TrimSpace(poll)
	if poll == "" || token == "" {
		return false
	}
	attempts := e.pollAttempts
	if attempts <= 0 {
		attempts = ssrfPollAttempts
	}
	interval := e.pollInterval
	if interval <= 0 {
		interval = ssrfPollInterval
	}
	client := &http.Client{Timeout: ssrfPollTimeout}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(interval):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, poll, nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, ssrfPollBodyMax))
		resp.Body.Close()
		if strings.Contains(string(body), token) {
			return true
		}
	}
	return false
}

func (e *ssrfExecutor) do(ctx context.Context, req *httpengine.Request) (*httpengine.Response, domain.TestOutcome, error) {
	if req == nil {
		return nil, domain.OutcomeError, errors.New("nil request")
	}
	timed := *req
	timed.Timeout = e.cfg.RequestTimeout
	resp, err := e.engine.Do(ctx, &timed)
	switch {
	case err == nil:
		return resp, domain.OutcomeSuccess, nil
	case ctx.Err() != nil:
		return nil, domain.OutcomeCancelled, ctx.Err()
	default:
		return nil, domain.OutcomeError, err
	}
}

// refreshParams keeps a rotating anti-CSRF token usable for the baseline and
// every canary. It only touches parameters OTHER than the focused one.
func (e *ssrfExecutor) refreshParams(ctx context.Context, ep *domain.Endpoint, params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	if !hasDynamicParam(params, focus) {
		return params
	}
	return refreshDynamicParams(ctx, e.engine, e.cfg.RequestTimeout, ep, params, focus)
}

// ssrfFillEmptyParams gives blank required-looking fields a harmless value so a
// form reaches the code that consumes the URL. The focused parameter is left to
// the canary builder and CSRF tokens to refreshParams.
func ssrfFillEmptyParams(params []*domain.Parameter, focus *domain.Parameter) []*domain.Parameter {
	out := append([]*domain.Parameter(nil), params...)
	for i, p := range out {
		if p == nil || p == focus || strings.TrimSpace(p.Example) != "" {
			continue
		}
		if p.Location == domain.LocationHeader || p.Location == domain.LocationCookie || isDynamicTokenName(p.Name) {
			continue
		}
		cp := *p
		if ssrfURLParamName(p.Name) {
			cp.Example = "https://example.com/"
		} else {
			cp.Example = "1"
		}
		out[i] = &cp
	}
	return out
}

// ---------------------------------------------------------------------------
// applicability
// ---------------------------------------------------------------------------

func ssrfInjectableLocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationHeader:
		return true
	default:
		return false
	}
}

// ssrfCandidateParameter reports whether one parameter plausibly carries an
// outbound URL: either its name says so, or the value the crawl observed is an
// absolute http(s) URL (the "?q=https://..." shape).
func ssrfCandidateParameter(p *domain.Parameter) bool {
	if p == nil {
		return false
	}
	if ssrfURLParamName(p.Name) {
		return true
	}
	if ssrfURLValue(p.Example) {
		return true
	}
	for _, ex := range p.Examples {
		if ssrfURLValue(ex) {
			return true
		}
	}
	return false
}

// ssrfURLParamSinks are the words that make a parameter name URL-like. They are
// matched as whole words (handling snake_case/kebab-case/camelCase) and as a
// trailing sink ("targeturl", "imageUrl").
var ssrfURLParamSinks = map[string]bool{
	"url": true, "urls": true, "uri": true, "uris": true,
	"href": true, "link": true, "links": true, "src": true,
	"callback": true, "webhook": true, "feed": true, "rss": true, "atom": true,
	"proxy": true, "redirect": true, "dest": true, "destination": true,
	"avatar": true, "image": true, "img": true, "photo": true, "picture": true,
	"thumbnail": true, "thumb": true, "icon": true, "logo": true, "banner": true,
	"media": true, "video": true, "audio": true, "stream": true, "embed": true, "oembed": true,
	"endpoint": true, "host": true, "hostname": true, "domain": true,
	"site": true, "server": true, "service": true, "source": true,
	"target": true, "fetch": true, "load": true, "remote": true,
	"next": true, "return": true, "returnto": true, "continue": true,
	"forward": true, "notify": true, "import": true,
}

// ssrfTrailingSinks are matched as a suffix of the separator-stripped name, so
// "imageurl"/"targeturl" match even without a camelCase boundary.
var ssrfTrailingSinks = []string{"url", "uri", "href", "link", "src", "feed", "callback", "webhook", "proxy", "redirect"}

func ssrfURLParamName(name string) bool {
	words := paramNameWords(name)
	for _, w := range words {
		if ssrfURLParamSinks[w] {
			return true
		}
	}
	joined := strings.Join(words, "")
	for _, sink := range ssrfTrailingSinks {
		if len(joined) > len(sink) && strings.HasSuffix(joined, sink) {
			return true
		}
	}
	return false
}

// paramNameWords splits a parameter name into lowercase words on any non
// alphanumeric separator and on camelCase boundaries, so "callback_url",
// "callbackURL" and "callbackUrl" all yield ["callback","url"]. Splitting (as
// opposed to substring matching) is what keeps "security" from looking like it
// contains "uri". Shared by the URL-sink and file-path-sink applicability
// checks.
func paramNameWords(name string) []string {
	var b strings.Builder
	prevLower := false
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				b.WriteByte(' ')
			}
			b.WriteRune(r + ('a' - 'A'))
			prevLower = false
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevLower = r >= 'a' && r <= 'z'
		default:
			b.WriteByte(' ')
			prevLower = false
		}
	}
	return strings.Fields(b.String())
}

// ssrfURLValue reports whether an observed value is an absolute http(s) URL or
// a protocol-relative reference — the shapes a URL sink receives.
func ssrfURLValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "//") {
		return len(v) > 2
	}
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

// ---------------------------------------------------------------------------
// canaries
// ---------------------------------------------------------------------------

func ssrfNewToken() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate correlation token: %w", err)
	}
	return "indago-ssrf-" + hex.EncodeToString(buf[:]), nil
}

// ssrfDifferentialCanary builds a canary under the reserved ".invalid" TLD.
// Nothing can resolve it, so even a target that fully fetches the value reaches
// no host at all.
func ssrfDifferentialCanary() (ssrfCanary, error) {
	token, err := ssrfNewToken()
	if err != nil {
		return ssrfCanary{}, err
	}
	host := token + "." + ssrfCanaryTLD
	return ssrfCanary{URL: "http://" + host + "/" + token, Token: token, Kind: ssrfModeDifferential}, nil
}

// ssrfOASTCanary builds a canary from the operator's collaborator, refusing any
// base whose host is a loopback/instance-metadata address — a canary there
// would turn the target into a probe of its own host. A private (RFC 1918/ULA)
// host is refused too unless allowPrivate (ExecutorConfig.AllowPrivateOAST) is
// set, which is the explicit opt-in for a lab collaborator on the target's own
// private network.
func ssrfOASTCanary(callbackURL string, allowPrivate bool) (ssrfCanary, error) {
	raw := strings.TrimSpace(callbackURL)
	if raw == "" {
		return ssrfCanary{}, errors.New("no OAST callback configured")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ssrfCanary{}, fmt.Errorf("invalid OAST callback: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ssrfCanary{}, fmt.Errorf("OAST callback %q is not an http(s) URL", truncate(raw, 120))
	}
	host := u.Hostname()
	if host == "" {
		return ssrfCanary{}, fmt.Errorf("OAST callback %q has no host", truncate(raw, 120))
	}
	if reason, forbidden := ssrfForbiddenCanaryHost(host, allowPrivate); forbidden {
		return ssrfCanary{}, fmt.Errorf("OAST callback host %q is %s; refusing to make the target request it", host, reason)
	}
	token, err := ssrfNewToken()
	if err != nil {
		return ssrfCanary{}, err
	}
	u.User = nil // never leak operator credentials into a value the target sees
	u.Path = strings.TrimRight(u.Path, "/") + "/" + token
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	return ssrfCanary{URL: u.String(), Token: token, Kind: ssrfConfirmOAST, Private: ssrfHostIsPrivate(host)}, nil
}

// ssrfForbiddenCanaryHost reports whether host must never be used as a canary,
// and why. It is deliberately purely syntactic: resolving a name here would
// itself be a network probe, and the refusal has to be deterministic.
//
// allowPrivate is ExecutorConfig.AllowPrivateOAST. It relaxes exactly ONE rule:
// a literal RFC 1918/ULA address is accepted, because a lab OAST listener on
// the target's own private network (192.168.103.1 for a target at
// 192.168.103.20) is a deliberate authorized deployment — the operator says the
// LAN IS the lab. Everything else stays absolute, with or without the opt-in:
// instance-metadata names and addresses, loopback (127.0.0.0/8, ::1), link-local
// (169.254.0.0/16, fe80::/10), unspecified, multicast, 0.0.0.0/8, CGNAT
// (100.64.0.0/10 — where Alibaba's metadata service lives) and the
// mDNS/private host suffixes (.local/.internal/.localhost/.home.arpa).
func ssrfForbiddenCanaryHost(host string, allowPrivate bool) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[") // [::1] -> ::1
	if h == "" {
		return "an empty host", true
	}
	if ssrfMetadataHosts[h] {
		return "a loopback/instance-metadata host name", true
	}
	if ssrfLoopbackHosts[h] {
		return "a loopback host name", true
	}
	for _, suffix := range ssrfPrivateHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return "a loopback/private host name (" + suffix + ")", true
		}
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return "", false
	}
	switch {
	case ip.IsUnspecified():
		return "the unspecified address", true
	case ip.IsLoopback():
		return "a loopback address", true
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "a link-local/instance-metadata address", true
	case ip.IsPrivate():
		if !allowPrivate {
			return "a private (RFC 1918/ULA) address (set -allow-private-oast for a lab collaborator on that network)", true
		}
	case ip.IsMulticast():
		return "a multicast address", true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return "the 0.0.0.0/8 \"this network\" range", true
		}
		// 100.64.0.0/10 (CGNAT) is where Alibaba's metadata service lives.
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return "a carrier-grade NAT (100.64.0.0/10) address", true
		}
	}
	return "", false
}

// ssrfHostIsPrivate reports whether host is a literal RFC 1918/ULA address —
// the case AllowPrivateOAST exists for. Used to LABEL evidence (a finding
// confirmed through a lab collaborator), never to decide a verdict.
func ssrfHostIsPrivate(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	ip := net.ParseIP(h)
	return ip != nil && ip.IsPrivate()
}

// ssrfPollURL validates the collaborator's read API. This URL is fetched by the
// SCANNER, not by the target, so it is also the one place this engine could
// itself read a cloud instance-metadata service: a metadata/link-local address
// is refused outright. Loopback and private addresses are accepted here (an
// operator's collaborator normally lives there in a lab) because the scanner
// reading its own operator's endpoint is not a probe of a third party.
func ssrfPollURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("no collaborator poll URL configured")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid collaborator poll URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("collaborator poll URL %q is not an http(s) URL", truncate(raw, 120))
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("collaborator poll URL %q has no host", truncate(raw, 120))
	}
	if reason, refused := ssrfForbiddenPollHost(host); refused {
		return "", fmt.Errorf("collaborator poll host %q is %s; refusing to fetch it", host, reason)
	}
	return u.String(), nil
}

// ssrfForbiddenPollHost restricts what the SCANNER may connect to when it reads
// a collaborator: only the instance-metadata service and link-local space are
// off limits (see ssrfPollURL for why loopback/private are allowed here).
func ssrfForbiddenPollHost(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if h == "" {
		return "an empty host", true
	}
	if ssrfMetadataHosts[h] {
		return "an instance-metadata host name", true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return "", false
	}
	switch {
	case ip.IsUnspecified():
		return "the unspecified address", true
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "a link-local/instance-metadata address", true
	case ip.IsMulticast():
		return "a multicast address", true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// response analysis
// ---------------------------------------------------------------------------

func ssrfFetchFailureIndicator(body string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, indicator := range ssrfFetchFailureIndicators {
		if strings.Contains(lower, indicator) {
			return indicator
		}
	}
	return ""
}

func ssrfURLParsingIndicator(body string) string {
	if body == "" {
		return ""
	}
	lower := strings.ToLower(body)
	for _, indicator := range ssrfURLParsingIndicators {
		if strings.Contains(lower, indicator) {
			return indicator
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// persistence
// ---------------------------------------------------------------------------

func (e *ssrfExecutor) persistEvidence(ctx context.Context, scanID domain.ID, resp *httpengine.Response, role string) ([]domain.ID, error) {
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

func (e *ssrfExecutor) persistSSRFCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d ssrfDetail, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: ssrfVulnClass,
		Status: domain.TestCaseCompleted, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: note,
		EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("ssrf: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *ssrfExecutor) finishSSRFUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: ssrfVulnClass, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "ssrf skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped ssrf case: %w", err)
	}
	return nil
}

func (e *ssrfExecutor) finishSSRFError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "redirect target is outside the scan scope")
	}
	if isTLSRedirectMismatch(reqErr) {
		return e.finishSSRFUnavailable(ctx, job, started, ep, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: ssrfVulnClass, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "ssrf baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("ssrf baseline failed: %s", msg)
}

func ssrfSummary(d ssrfDetail) string {
	switch d.ConfirmMethod {
	case ssrfConfirmOAST:
		return "The server requested an operator-supplied canary URL: the collaborator received a request carrying the unique correlation token injected into the parameter."
	case ssrfConfirmDifferential:
		return "Two independent canary URLs each produced a resolver/dial/fetch failure that a clean baseline did not (the response need not echo the URL), showing the server attempted a request to an attacker-controlled URL."
	default:
		return "Evidence is insufficient for a verdict."
	}
}

func (e *ssrfExecutor) correlateSSRF(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d ssrfDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	confidence := domain.ConfidenceHigh
	if d.ConfirmMethod != ssrfConfirmOAST {
		confidence = domain.ConfidenceMedium
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: ssrfVulnClass, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: confidence,
		Title:      "Server-side request forgery in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    ssrfSummary(d),
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: ssrfEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("ssrf: persist finding", "scan", job.ScanID, "err", err)
	}
}

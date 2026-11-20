package scan

// SQL injection engine.
//
// One JobSQLi is enqueued per eligible injection point. The engine sends a
// baseline request and then a small, bounded set of probes through the HTTP
// engine. Nothing here is an exploit: no UNION, stacked query, comment, file
// access or write is ever sent. The only delay-bearing payload is a read-only
// boolean expression built from SLEEP()/pg_sleep(); it changes neither data
// nor schema and runs only as the bounded blind fallback described below.
//
// Three deterministic signals are used:
//
//   - Error-based. Harmless syntax-breaking probes ("'", "\"", "'))") look for
//     a recognized database error signature that the BASELINE response did not
//     already carry. A reflected payload that merely contains a quote is not
//     evidence, and a target that always renders a database error is not
//     evidence either: only a signature absent from the baseline counts.
//   - Boolean differential. A TRUE condition ("' AND '1'='1", " AND 1=1") must
//     reproduce the baseline response while the matching FALSE condition
//     ("' AND '1'='2", " AND 1=2") must diverge. A reflected payload cannot
//     pass this: the echo carries the extra bytes, so the TRUE response no
//     longer matches the baseline's size or status.
//   - Timing differential (blind fallback). A read-only boolean expression that
//     calls SLEEP()/pg_sleep() must delay the response while its matched
//     control (the same expression with a zero delay) stays as fast as the
//     sampled baseline. Baseline latency is measured first because a single
//     slow response proves nothing: the delay must reproduce across two
//     independent rounds, each with its own fast control. The phase runs only
//     after the error/boolean phases failed to confirm, is bounded by
//     maxSQLiTimingProbes, and never adds a statement separator, comment or
//     mutating keyword.
//
// A verdict is CONFIRMED only with two independent observations: two distinct
// syntax probes each producing a new signature, one signature plus one boolean
// pair, two independent boolean pairs, one other signal plus one reproduced
// timing differential, or one timing differential reproduced across two
// independent rounds with matched fast controls. A single signal is
// INCONCLUSIVE, and transport errors or an ordinary page are never promoted to
// a finding.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/store"
	"github.com/indago/indago/internal/worker"
)

const sqliEngine = "sqli"

// maxSQLiProbes bounds target requests per injection point: one baseline, at
// most three syntax probes and at most four boolean pairs of two requests each.
// The engine stops as soon as two signals are confirmed, so a vulnerable point
// usually costs far fewer.
const maxSQLiProbes = 12

// maxSQLiTimingProbes bounds the blind timing phase separately from the
// error/boolean phases: two extra baseline latency samples plus four
// technique/context combinations, each sending one control and one delay probe
// in at most two rounds. The table itself is fixed, so this is a hard ceiling
// and not just a scheduling hint.
const maxSQLiTimingProbes = 18

// Timing differential tuning. The delay is deliberately small (two seconds):
// long enough to separate from ordinary jitter, short enough that the bounded
// probe count cannot load a target. A delay counts only when it is at least
// 60% of the nominal value over BOTH its own control and the measured baseline
// median; the control must stay within half a second of that median, otherwise
// the round has no trustworthy fast reference and cannot confirm. Each probe is
// also bounded by ExecutorConfig.RequestTimeout, so a target that multiplies
// the delay per row times out instead of holding a worker indefinitely.
const (
	sqliTimingDelaySeconds = 2
	sqliTimingSamples      = 2
	sqliTimingMinDelta     = 1200 * time.Millisecond
	sqliTimingControlSlack = 500 * time.Millisecond
)

// A TRUE response must reproduce the baseline and a FALSE response must
// diverge. Size is compared instead of bytes on purpose: a page may carry a
// timestamp or a CSRF token that changes on every request, and a byte diff
// would then call every pair a divergence and invent findings. The gap between
// the two thresholds keeps an ambiguous middle case from confirming.
const (
	sqlSameResponseThreshold = 0.98
	sqlDifferentThreshold    = 0.90
)

type sqliExecutor struct {
	*commandInjectionExecutor
}

// NewSQLiExecutorForTest exposes the executor to tests without exporting the
// production constructor.
func NewSQLiExecutorForTest(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sqliExecutor {
	return newSQLiExecutor(st, eng, ev, cfg, log, findingsMu)
}

func newSQLiExecutor(st store.Store, eng httpengine.Engine, ev evidence.Store, cfg ExecutorConfig, log *slog.Logger, findingsMu *sync.Mutex) *sqliExecutor {
	return &sqliExecutor{commandInjectionExecutor: newCommandInjectionExecutor(st, eng, ev, cfg, log, findingsMu)}
}

var _ worker.Handler = (*sqliExecutor)(nil)

type sqliAttempt struct {
	Payload         string `json:"payload"`
	Kind            string `json:"kind,omitempty"` // syntax, boolean-true, boolean-false, timing-control or timing-delay
	Pair            string `json:"bool_pair,omitempty"`
	Round           int    `json:"round,omitempty"` // timing confirmation round (1 or 2)
	Status          int    `json:"status,omitempty"`
	BodyLength      int    `json:"body_length,omitempty"`
	ElapsedMS       int64  `json:"elapsed_ms,omitempty"`
	ErrorSignature  string `json:"error_signature,omitempty"`
	Database        string `json:"database,omitempty"`
	MatchesBaseline bool   `json:"matches_baseline,omitempty"`
	Diverges        bool   `json:"diverges,omitempty"`
	Delayed         bool   `json:"delayed,omitempty"`
}

// sqliPoC is the exact request shape that produced a confirmed signal, recorded
// so a triager can reproduce it without reconstructing the parameter set.
type sqliPoC struct {
	Method  string `json:"method"`
	URL     string `json:"url"`
	Body    string `json:"body,omitempty"`
	Payload string `json:"payload"`
}

type sqliDetail struct {
	Engine         string               `json:"engine"`
	Parameter      string               `json:"parameter"`
	Location       domain.ParamLocation `json:"location"`
	BaselineStatus int                  `json:"baseline_status,omitempty"`
	BaselineLength int                  `json:"baseline_length,omitempty"`
	// BaselineLatencyMS is the median of the baseline samples taken by the
	// timing phase. Zero when the timing phase never ran.
	BaselineLatencyMS int64         `json:"baseline_latency_ms,omitempty"`
	Attempts          []sqliAttempt `json:"attempts,omitempty"`
	// ErrorSignals counts distinct syntax probes that produced a database
	// error signature the baseline did not contain. BooleanSignals counts
	// pairs whose TRUE response matched the baseline while the FALSE response
	// diverged. TimingSignals counts technique/context combinations whose
	// delay reproduced in two independent rounds with a fast matched control
	// in each; TimingTechnique names the first one that did.
	ErrorSignals    int            `json:"error_signals"`
	BooleanSignals  int            `json:"boolean_signals"`
	TimingSignals   int            `json:"timing_signals"`
	TimingTechnique string         `json:"timing_technique,omitempty"`
	ConfirmedCount  int            `json:"confirmed_count"`
	IdentifiedDB    string         `json:"identified_db,omitempty"`
	PoC             *sqliPoC       `json:"poc,omitempty"`
	Verdict         domain.Verdict `json:"verdict"`
	ConfirmMethod   string         `json:"confirm_method,omitempty"` // error, error_boolean, boolean, error_timing, boolean_timing or timing
	Reason          string         `json:"reason,omitempty"`
	EvidenceIDs     []domain.ID    `json:"evidence_ids,omitempty"`
}

// sqlErrorSignature is one recognized database error message. Matching is
// case-insensitive because vendors differ in capitalization and drivers prefix
// the message differently.
type sqlErrorSignature struct {
	db      string
	label   string
	pattern *regexp.Regexp
}

func sqlSignature(db, label, expr string) sqlErrorSignature {
	return sqlErrorSignature{db: db, label: label, pattern: regexp.MustCompile("(?i)" + expr)}
}

// sqlErrorSignatures is the bounded recognition table. Every entry is a real
// message a database driver emits when a statement cannot be parsed; a generic
// page that merely mentions SQL never matches.
var sqlErrorSignatures = []sqlErrorSignature{
	// SQLite.
	sqlSignature("SQLite", "SQLITE_ERROR", `SQLITE_ERROR`),
	sqlSignature("SQLite", "unrecognized token", `unrecognized token`),
	sqlSignature("SQLite", "near <token>: syntax error", `near "[^"\r\n]{0,80}": syntax error`),

	// MySQL / MariaDB.
	sqlSignature("MySQL", "You have an error in your SQL syntax", `You have an error in your SQL syntax`),
	sqlSignature("MySQL", "SQL syntax ... MySQL", `SQL syntax[^\r\n]{0,80}MySQL`),
	sqlSignature("MySQL", "mysql_ warning", `Warning[^\r\n]{0,40}mysql_`),
	sqlSignature("MariaDB", "MariaDB server version", `MariaDB server version`),

	// PostgreSQL.
	sqlSignature("PostgreSQL", "syntax error at or near", `ERROR:\s+syntax error at or near`),
	sqlSignature("PostgreSQL", "pg_query()", `pg_query\(\)`),
	sqlSignature("PostgreSQL", "PSQLException", `PSQLException`),
	sqlSignature("PostgreSQL", "unterminated quoted string", `unterminated quoted string`),

	// Microsoft SQL Server.
	sqlSignature("MSSQL", "Unclosed quotation mark", `Unclosed quotation mark`),
	sqlSignature("MSSQL", "Microsoft OLE DB Provider for SQL Server", `Microsoft OLE DB Provider for SQL Server`),
	sqlSignature("MSSQL", "Incorrect syntax near", `Incorrect syntax near`),

	// Oracle.
	sqlSignature("Oracle", "ORA-00933", `ORA-00933`),
	sqlSignature("Oracle", "ORA-01756", `ORA-01756`),
	sqlSignature("Oracle", "quoted string not properly terminated", `quoted string not properly terminated`),

	// HSQLDB / JDBC.
	sqlSignature("HSQLDB", "SQLSyntaxErrorException", `SQLSyntaxErrorException`),
	sqlSignature("HSQLDB", "HsqlException", `HsqlException`),
	sqlSignature("HSQLDB", "malformed string", `malformed string:`),
	sqlSignature("HSQLDB", "unexpected token", `unexpected token:`),
	sqlSignature("HSQLDB", "unexpected end of statement", `unexpected end of statement`),

	// Generic PDO/DBAL wrapper.
	sqlSignature("generic", "SQLSTATE", `SQLSTATE\[`),
}

// sqlErrorSignaturesIn returns the labels of every recognized signature present
// in body. It is used to learn what the baseline page already says, so a page
// that always shows a database error can never be confirmed by a probe.
func sqlErrorSignaturesIn(body []byte) map[string]bool {
	found := map[string]bool{}
	for _, sig := range sqlErrorSignatures {
		if sig.pattern.Match(body) {
			found[sig.label] = true
		}
	}
	return found
}

// sqlNewErrorSignature returns the first recognized signature present in body
// that the baseline did not already produce.
func sqlNewErrorSignature(body []byte, baseline map[string]bool) (sqlErrorSignature, bool) {
	for _, sig := range sqlErrorSignatures {
		if baseline[sig.label] {
			continue
		}
		if sig.pattern.Match(body) {
			return sig, true
		}
	}
	return sqlErrorSignature{}, false
}

// sqlBodyRatio compares two bodies by size (shorter/longer), so the comparison
// ignores per-request tokens while still noticing a list that gained or lost
// rows.
func sqlBodyRatio(a, b []byte) float64 {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 1
	case len(a) == 0 || len(b) == 0:
		return 0
	case len(a) < len(b):
		return float64(len(a)) / float64(len(b))
	default:
		return float64(len(b)) / float64(len(a))
	}
}

// sqlMatchesBaseline reports whether resp looks like the same page the baseline
// returned: same status and essentially the same size.
func sqlMatchesBaseline(base, resp *httpengine.Response) bool {
	if base == nil || resp == nil || resp.Status != base.Status {
		return false
	}
	return sqlBodyRatio(base.Body, resp.Body) >= sqlSameResponseThreshold
}

// sqlDivergesFromBaseline reports whether resp is clearly a different page from
// the baseline: a different status, or a size well outside the baseline's.
func sqlDivergesFromBaseline(base, resp *httpengine.Response) bool {
	if base == nil || resp == nil {
		return false
	}
	if resp.Status != base.Status {
		return true
	}
	return sqlBodyRatio(base.Body, resp.Body) < sqlDifferentThreshold
}

// sqlSyntaxProbes is the bounded quote-breaking set. The observed value is kept
// in front so the probe continues the expression the application expects; the
// delimiter itself is what makes the statement unparseable.
func sqlSyntaxProbes(baseValue string) []string {
	return []string{
		baseValue + "'",
		baseValue + `"`,
		baseValue + "'))",
	}
}

// sqlBooleanPair is one TRUE/FALSE pair. Pairs come in two independent variants
// per context so the same context can confirm twice: a single variant could
// never satisfy the two-signal rule on its own.
type sqlBooleanPair struct {
	Name  string
	True  string
	False string
}

func sqlBooleanPairs(baseValue string) []sqlBooleanPair {
	return []sqlBooleanPair{
		// Single-quoted string or numeric context.
		{Name: "string-single-quote/1", True: baseValue + `' AND '1'='1`, False: baseValue + `' AND '1'='2`},
		{Name: "string-single-quote/2", True: baseValue + `' AND '2'='2`, False: baseValue + `' AND '2'='3`},
		// Unquoted numeric context.
		{Name: "numeric/1", True: baseValue + ` AND 1=1`, False: baseValue + ` AND 1=2`},
		{Name: "numeric/2", True: baseValue + ` AND 2=2`, False: baseValue + ` AND 2=3`},
	}
}

// sqlTimingTechnique is one read-only delay/control pair. The suffixes are
// appended to the parameter's observed value, so the surrounding expression
// stays intact; DelaySuffix adds a pure delay function, ControlSuffix uses the
// same expression with a zero delay so a slow response can be attributed to
// the argument and not to the extra syntax.
//
// Both suffixes intentionally close their own string literal and stay inside a
// single boolean expression: no semicolon, comment or stacked statement is
// needed or allowed. SLEEP/pg_sleep sit in an uncorrelated scalar subquery
// rather than a bare per-row predicate, which keeps the induced delay to a
// single evaluation on the usual planners.
type sqlTimingTechnique struct {
	Name          string
	DB            string
	DelaySuffix   string
	ControlSuffix string
}

func sqlTimingTechniques() []sqlTimingTechnique {
	delay := sqliTimingDelaySeconds
	return []sqlTimingTechnique{
		{
			Name:          "mysql-sleep/string",
			DB:            "MySQL",
			DelaySuffix:   fmt.Sprintf(`' AND (SELECT SLEEP(%d))=0 AND '1'='1`, delay),
			ControlSuffix: `' AND (SELECT SLEEP(0))=0 AND '1'='1`,
		},
		{
			Name:          "mysql-sleep/numeric",
			DB:            "MySQL",
			DelaySuffix:   fmt.Sprintf(` AND (SELECT SLEEP(%d))=0 AND 1=1`, delay),
			ControlSuffix: ` AND (SELECT SLEEP(0))=0 AND 1=1`,
		},
		{
			Name:          "postgres-pg-sleep/string",
			DB:            "PostgreSQL",
			DelaySuffix:   fmt.Sprintf(`' AND (SELECT 1 FROM pg_sleep(%d))=1 AND '1'='1`, delay),
			ControlSuffix: `' AND (SELECT 1 FROM pg_sleep(0))=1 AND '1'='1`,
		},
		{
			Name:          "postgres-pg-sleep/numeric",
			DB:            "PostgreSQL",
			DelaySuffix:   fmt.Sprintf(` AND (SELECT 1 FROM pg_sleep(%d))=1 AND 1=1`, delay),
			ControlSuffix: ` AND (SELECT 1 FROM pg_sleep(0))=1 AND 1=1`,
		},
	}
}

// sqlForbiddenTimingTokens rejects a timing suffix that could ever stop being
// a pure read-only expression. It is defence in depth around a hard-coded
// table: the engine fails closed and skips a technique rather than sending it.
var sqlForbiddenTimingTokens = regexp.MustCompile(`(?i)\b(ALTER|ATTACH|CALL|COPY|CREATE|DELETE|DETACH|DROP|DUMPFILE|EXEC|EXECUTE|GRANT|INSERT|LOAD|MERGE|OUTFILE|PRAGMA|REPLACE|REVOKE|SET|TRUNCATE|UNION|UPDATE|VACUUM)\b`)

// sqlReadOnlyTimingSuffix reports whether a timing suffix is provably a single
// read-only expression: no statement separator, no comment, no mutating keyword
// and no UNION exfiltration shape. It is checked before every send, not just in
// tests.
func sqlReadOnlyTimingSuffix(suffix string) bool {
	if strings.ContainsAny(suffix, ";#") {
		return false
	}
	if strings.Contains(suffix, "--") || strings.Contains(suffix, "/*") || strings.Contains(suffix, "*/") {
		return false
	}
	return !sqlForbiddenTimingTokens.MatchString(suffix)
}

// sqlMedianDuration returns the median of the samples, copying so the caller's
// slice keeps its request order for the evidence trail.
func sqlMedianDuration(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

// sqlDurationSpread is max-min. A target whose own latency varies by more than
// the detection window has no trustworthy baseline, so the timing phase stops
// instead of guessing.
func sqlDurationSpread(samples []time.Duration) time.Duration {
	if len(samples) < 2 {
		return 0
	}
	return slices.Max(samples) - slices.Min(samples)
}

// sqliObservedValue is the parameter's observed value as plain text. A
// browser-network JSON example is stored as a serialized literal (`"alice"`
// including the quotes), and gluing that quoting into a SQL payload would
// change the context around it; sstiObservedValue already unquotes exactly
// that shape, so reuse it rather than duplicate the rule. An empty value falls
// back to the same harmless placeholder the other marker engines use.
func sqliObservedValue(p *domain.Parameter) string {
	value := strings.TrimSpace(sstiObservedValue(p))
	if value == "" {
		value = commandInjectionBaseValue(p.Name)
	}
	return value
}

func isSQLiLocation(loc domain.ParamLocation) bool {
	switch loc {
	case domain.LocationQuery, domain.LocationForm, domain.LocationJSON, domain.LocationPath:
		return true
	default:
		return false
	}
}

func (e *sqliExecutor) Handle(ctx context.Context, job *domain.TestJob) error {
	started := time.Now()
	ep, params, focus, err := resolveJobTarget(ctx, e.store, job)
	if err != nil {
		return fmt.Errorf("resolve sqli target: %w", err)
	}
	if focus == nil {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "no focused parameter")
	}
	if !isSQLiLocation(focus.Location) || isDynamicTokenName(focus.Name) {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "parameter location is not SQL-injectable")
	}
	if e.cfg.SkipDownloadEndpoints && isDownloadLikeEndpoint(ep) {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "download endpoint skipped by policy")
	}
	if isWriteLikeEndpoint(ep, params) && (!e.cfg.AllowStateChanging || e.cfg.SkipWriteEndpoints) {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "state-changing endpoint skipped by policy")
	}

	baseValue := sqliObservedValue(focus)
	params = fillEmptyCommandParams(e.refreshParams(ctx, ep, params, focus), focus)
	base, err := buildRequest(ep, params, nil)
	if err != nil {
		return fmt.Errorf("build sqli baseline: %w", err)
	}
	baseStarted := time.Now()
	baseResp, outcome, reqErr := e.do(ctx, base)
	baseElapsed := time.Since(baseStarted)
	if outcome != domain.OutcomeSuccess || baseResp == nil {
		return e.finishSQLiError(ctx, job, started, ep, focus, outcome, reqErr)
	}

	d := sqliDetail{Engine: sqliEngine, Parameter: focus.Name, Location: focus.Location,
		BaselineStatus: baseResp.Status, BaselineLength: len(baseResp.Body)}
	baseEvidence, _ := e.persistEvidence(ctx, job.ScanID, baseResp, "sqli baseline")
	d.EvidenceIDs = append(d.EvidenceIDs, baseEvidence...)

	p := &sqliProber{
		e: e, job: job, ep: ep, focus: focus, params: params, baseValue: baseValue,
		base: baseResp, baseElapsed: baseElapsed, baseErrors: sqlErrorSignaturesIn(baseResp.Body), d: &d,
	}
	// Phase 1: a new database error signature on at least two distinct syntax
	// probes is enough on its own, so stop there.
	p.runSyntax(ctx)
	// Phase 2: boolean pairs. With one error signal already in hand a single
	// pair confirms; otherwise two independent pairs are required.
	if d.ErrorSignals < 2 {
		p.runBoolean(ctx)
	}
	// Phase 3: blind timing fallback. It is the slowest phase, so it runs only
	// when the deterministic error/boolean evidence did not already confirm.
	if !sqlConfirmedWithoutTiming(d) {
		p.runTiming(ctx)
	}

	d.ConfirmedCount = d.ErrorSignals + d.BooleanSignals + d.TimingSignals
	if d.PoC == nil && p.pocPayload != "" {
		if req, err := buildRequest(ep, p.params, &injection{param: focus, value: p.pocPayload}); err == nil {
			d.PoC = &sqliPoC{Method: req.Method, URL: req.URL, Body: string(req.Body), Payload: p.pocPayload}
		}
	}

	switch {
	case d.ErrorSignals >= 2:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "error"
		d.Reason = "two independent syntax probes produced a database error signature the baseline did not contain"
	case d.ErrorSignals >= 1 && d.BooleanSignals >= 1:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "error_boolean"
		d.Reason = "a new database error signature and an independent boolean differential agree"
	case d.BooleanSignals >= 2:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "boolean"
		d.Reason = "two independent boolean pairs reproduced the baseline for a TRUE condition and diverged for the FALSE condition"
	case d.ErrorSignals >= 1 && d.TimingSignals >= 1:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "error_timing"
		d.Reason = "a new database error signature and a reproduced timing differential agree"
	case d.BooleanSignals >= 1 && d.TimingSignals >= 1:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "boolean_timing"
		d.Reason = "a boolean differential and a reproduced timing differential agree"
	case d.TimingSignals >= 1:
		d.Verdict = domain.VerdictConfirmed
		d.ConfirmMethod = "timing"
		d.Reason = "a read-only delay differential reproduced across two independent rounds with a fast matched control in each"
	case d.ErrorSignals == 1:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one new database error signature was observed; a second independent signal is required"
	case d.BooleanSignals == 1:
		d.Verdict = domain.VerdictInconclusive
		d.Reason = "one boolean pair diverged consistently; a second independent pair is required"
	default:
		d.Verdict = domain.VerdictRejected
	}

	note := "no SQL injection signal observed"
	if d.Verdict == domain.VerdictConfirmed {
		note = "confirmed SQL injection: " + d.Reason
		e.persistSQLiCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
		e.correlateSQLi(ctx, job, ep, focus, d)
		return nil
	}
	if d.Verdict == domain.VerdictInconclusive {
		note = d.Reason
	}
	e.persistSQLiCase(ctx, job, ep, focus, d, domain.TestCaseCompleted, domain.OutcomeSuccess, note)
	return nil
}

// sqliProber carries one job's probe state so both phases share the same
// request construction, evidence persistence and refreshed-parameter handling.
type sqliProber struct {
	e               *sqliExecutor
	job             *domain.TestJob
	ep              *domain.Endpoint
	focus           *domain.Parameter
	params          []*domain.Parameter
	baseValue       string
	base            *httpengine.Response
	baseElapsed     time.Duration
	baseErrors      map[string]bool
	d               *sqliDetail
	pocPayload      string
	sent            int
	timingSent      int
	baselineLatency time.Duration
}

// budgetLeft reports whether another target request still fits inside
// maxSQLiProbes. Both phases consult it, so the per-injection-point request
// count is bounded by construction and not just by the tables above.
func (p *sqliProber) budgetLeft() bool { return p.sent < maxSQLiProbes }

// send refreshes rotating tokens, rebuilds the request with the payload in the
// focused parameter only, sends it, and persists the exchange. A request that
// cannot be built is reported as a transport error with a nil response.
func (p *sqliProber) send(ctx context.Context, payload, role string) (*httpengine.Response, domain.TestOutcome) {
	p.sent++
	p.params = fillEmptyCommandParams(p.e.refreshParams(ctx, p.ep, p.params, p.focus), p.focus)
	req, err := buildRequest(p.ep, p.params, &injection{param: p.focus, value: payload})
	if err != nil {
		return nil, domain.OutcomeError
	}
	resp, outcome, _ := p.e.do(ctx, req)
	if outcome == domain.OutcomeSuccess && resp != nil {
		ids, _ := p.e.persistEvidence(ctx, p.job.ScanID, resp, role)
		p.d.EvidenceIDs = append(p.d.EvidenceIDs, ids...)
	}
	return resp, outcome
}

// runSyntax sends the bounded quote-breaking probes and counts the distinct
// probes that produced a signature the baseline did not contain.
func (p *sqliProber) runSyntax(ctx context.Context) {
	for _, payload := range sqlSyntaxProbes(p.baseValue) {
		if !p.budgetLeft() {
			return
		}
		attempt := sqliAttempt{Payload: truncate(payload, 200), Kind: "syntax"}
		resp, outcome := p.send(ctx, payload, "sqli syntax probe")
		if resp != nil {
			attempt.Status = resp.Status
			attempt.BodyLength = len(resp.Body)
		}
		if outcome == domain.OutcomeSuccess && resp != nil {
			if sig, ok := sqlNewErrorSignature(resp.Body, p.baseErrors); ok {
				attempt.ErrorSignature = sig.label
				attempt.Database = sig.db
				p.d.IdentifiedDB = sig.db
				p.d.ErrorSignals++
				if p.pocPayload == "" {
					p.pocPayload = payload
				}
			}
		}
		p.d.Attempts = append(p.d.Attempts, attempt)
		if p.d.ErrorSignals >= 2 {
			return
		}
	}
}

// runBoolean sends TRUE/FALSE pairs and counts the pairs where TRUE reproduced
// the baseline while FALSE diverged. One error signal halves the number of
// pairs needed; otherwise two are required.
func (p *sqliProber) runBoolean(ctx context.Context) {
	needed := 2
	if p.d.ErrorSignals >= 1 {
		needed = 1
	}
	for _, pair := range sqlBooleanPairs(p.baseValue) {
		if p.d.BooleanSignals >= needed || !p.budgetLeft() {
			return
		}
		trueAttempt := sqliAttempt{Payload: truncate(pair.True, 200), Kind: "boolean-true", Pair: pair.Name}
		trueResp, trueOutcome := p.send(ctx, pair.True, "sqli boolean true "+pair.Name)
		if trueResp != nil {
			trueAttempt.Status = trueResp.Status
			trueAttempt.BodyLength = len(trueResp.Body)
		}
		// A transport error means this pair proves nothing; never count it.
		if trueOutcome != domain.OutcomeSuccess || trueResp == nil {
			p.d.Attempts = append(p.d.Attempts, trueAttempt)
			continue
		}
		trueAttempt.MatchesBaseline = sqlMatchesBaseline(p.base, trueResp)
		if !p.budgetLeft() {
			p.d.Attempts = append(p.d.Attempts, trueAttempt)
			return
		}

		falseAttempt := sqliAttempt{Payload: truncate(pair.False, 200), Kind: "boolean-false", Pair: pair.Name}
		falseResp, falseOutcome := p.send(ctx, pair.False, "sqli boolean false "+pair.Name)
		if falseResp != nil {
			falseAttempt.Status = falseResp.Status
			falseAttempt.BodyLength = len(falseResp.Body)
		}
		if falseOutcome != domain.OutcomeSuccess || falseResp == nil {
			p.d.Attempts = append(p.d.Attempts, trueAttempt, falseAttempt)
			continue
		}
		falseAttempt.Diverges = sqlDivergesFromBaseline(p.base, falseResp)
		p.d.Attempts = append(p.d.Attempts, trueAttempt, falseAttempt)

		if trueAttempt.MatchesBaseline && falseAttempt.Diverges {
			p.d.BooleanSignals++
			if p.pocPayload == "" {
				p.pocPayload = pair.True
			}
		}
	}
}

// timingBudgetLeft bounds the timing phase independently of the error/boolean
// budget, so the slow probes can never crowd out or extend the fast ones.
func (p *sqliProber) timingBudgetLeft() bool { return p.timingSent < maxSQLiTimingProbes }

// runTiming is the blind fallback. It first measures the target's own latency
// with a few clean baseline samples, then tries a fixed table of read-only
// delay/control techniques. A technique confirms only when its delay shows up
// in two independent rounds and each round's matched control stayed fast; a
// single slow response (jitter, rate limiting, a random stall) is discarded.
func (p *sqliProber) runTiming(ctx context.Context) {
	// A request timeout shorter than the delay plus a reasonable margin can
	// only ever turn the probe into a timeout, so do not spend requests on it.
	if p.e.cfg.RequestTimeout < time.Duration(sqliTimingDelaySeconds)*time.Second+2*time.Second {
		return
	}

	samples := []time.Duration{p.baseElapsed}
	for i := 0; i < sqliTimingSamples; i++ {
		if !p.timingBudgetLeft() {
			return
		}
		started := time.Now()
		resp, outcome := p.send(ctx, p.baseValue, "sqli timing baseline sample")
		if outcome != domain.OutcomeSuccess || resp == nil {
			return
		}
		samples = append(samples, time.Since(started))
	}
	p.baselineLatency = sqlMedianDuration(samples)
	p.d.BaselineLatencyMS = p.baselineLatency.Milliseconds()
	// The baseline itself must be stable enough for a differential. When its
	// own spread already exceeds the detection window, every reading below
	// would be a guess, so stop rather than risk a false positive.
	if sqlDurationSpread(samples) >= sqliTimingMinDelta {
		return
	}

	for _, tech := range sqlTimingTechniques() {
		// Fail closed: a suffix that is not provably a single read-only
		// expression is never sent, even though the table is hard-coded.
		if !sqlReadOnlyTimingSuffix(tech.DelaySuffix) || !sqlReadOnlyTimingSuffix(tech.ControlSuffix) {
			continue
		}
		if !p.timingBudgetLeft() {
			return
		}
		if !p.timingRound(ctx, tech, 1) {
			continue
		}
		if !p.timingBudgetLeft() {
			return
		}
		if !p.timingRound(ctx, tech, 2) {
			continue
		}
		p.d.TimingSignals++
		p.d.TimingTechnique = tech.Name
		if p.d.IdentifiedDB == "" {
			p.d.IdentifiedDB = tech.DB
		}
		if p.pocPayload == "" {
			p.pocPayload = p.baseValue + tech.DelaySuffix
		}
		return
	}
}

// timingRound sends one control and one delay probe and reports whether the
// pair produced a trustworthy fast-then-slow differential. The control is
// sent first so the round has a local fast reference taken immediately before
// the delay, not just the older baseline median.
func (p *sqliProber) timingRound(ctx context.Context, tech sqlTimingTechnique, round int) bool {
	control, ok := p.timingProbe(ctx, tech, tech.ControlSuffix, "timing-control", round)
	if !ok {
		return false
	}
	delay, ok := p.timingProbe(ctx, tech, tech.DelaySuffix, "timing-delay", round)
	if !ok {
		return false
	}
	if control > p.baselineLatency+sqliTimingControlSlack {
		return false
	}
	return delay >= p.baselineLatency+sqliTimingMinDelta && delay >= control+sqliTimingMinDelta
}

// timingProbe sends one payload and records its status and elapsed time. It
// returns false on any transport error, timeout or missing response: a broken
// exchange is never evidence.
func (p *sqliProber) timingProbe(ctx context.Context, tech sqlTimingTechnique, suffix, kind string, round int) (time.Duration, bool) {
	if !p.timingBudgetLeft() {
		return 0, false
	}
	p.timingSent++
	payload := p.baseValue + suffix
	attempt := sqliAttempt{Payload: truncate(payload, 200), Kind: kind, Pair: tech.Name, Round: round}
	started := time.Now()
	resp, outcome := p.send(ctx, payload, "sqli "+kind+" "+tech.Name)
	elapsed := time.Since(started)
	attempt.ElapsedMS = elapsed.Milliseconds()
	if resp != nil {
		attempt.Status = resp.Status
		attempt.BodyLength = len(resp.Body)
	}
	if outcome != domain.OutcomeSuccess || resp == nil {
		p.d.Attempts = append(p.d.Attempts, attempt)
		return 0, false
	}
	// Delayed marks the delay-bearing probe only; a slow control is recorded
	// through its elapsed time and invalidates the round instead.
	if kind == "timing-delay" && elapsed >= p.baselineLatency+sqliTimingMinDelta {
		attempt.Delayed = true
	}
	p.d.Attempts = append(p.d.Attempts, attempt)
	return elapsed, true
}

// sqlConfirmedWithoutTiming reports whether the error/boolean evidence already
// satisfies the confirmation rule, making the slower timing phase unnecessary.
func sqlConfirmedWithoutTiming(d sqliDetail) bool {
	if d.ErrorSignals >= 2 || d.BooleanSignals >= 2 {
		return true
	}
	return d.ErrorSignals >= 1 && d.BooleanSignals >= 1
}

func (e *sqliExecutor) persistSQLiCase(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sqliDetail, status domain.TestCaseStatus, outcome domain.TestOutcome, note string) {
	now := time.Now()
	detail, _ := json.Marshal(d)
	tc := &domain.TestCase{
		ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		InjectionPointID: job.Target.InjectionPointID, VulnClass: domain.VulnSQLi,
		Status: status, Outcome: outcome, Method: string(ep.Method), URL: job.Target.URL,
		Note: note, EvidenceIDs: d.EvidenceIDs, Detail: detail, StartedAt: &now, FinishedAt: &now,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		e.log.Warn("sqli: persist test case", "scan", job.ScanID, "err", err)
	}
}

func (e *sqliExecutor) finishSQLiUnavailable(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, reason string) error {
	now := time.Now()
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSQLi, Status: domain.TestCaseSkipped, Outcome: domain.OutcomeSuccess,
		Method: string(ep.Method), URL: job.Target.URL, Note: "sqli skipped: " + reason,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	if err := e.store.TestCases().Create(ctx, tc); err != nil {
		return fmt.Errorf("persist skipped sqli case: %w", err)
	}
	return nil
}

func (e *sqliExecutor) finishSQLiError(ctx context.Context, job *domain.TestJob, started time.Time, ep *domain.Endpoint, focus *domain.Parameter, outcome domain.TestOutcome, reqErr error) error {
	if isOutOfScopeRedirectError(reqErr) {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "redirect target is outside the scan scope")
	}
	if isTLSRedirectMismatch(reqErr) {
		return e.finishSQLiUnavailable(ctx, job, started, ep, "HTTP/HTTPS redirect points at a service that does not speak TLS on this port")
	}
	now := time.Now()
	msg := "request failed"
	if reqErr != nil {
		msg = truncate(reqErr.Error(), 200)
	}
	tc := &domain.TestCase{ID: domain.NewID(), ScanID: job.ScanID, JobID: job.ID, Attempt: job.Attempts,
		VulnClass: domain.VulnSQLi, Status: domain.TestCaseFailed, Outcome: outcome,
		Method: string(ep.Method), URL: job.Target.URL, Error: msg, Note: "sqli baseline failed: " + msg,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started, UpdatedAt: now}
	_ = e.store.TestCases().Create(ctx, tc)
	if outcome == domain.OutcomeCancelled {
		return context.Canceled
	}
	return fmt.Errorf("sqli baseline failed: %s", msg)
}

func sqliFindingSummary(d sqliDetail) string {
	switch d.ConfirmMethod {
	case "error_boolean":
		return "A new database error signature and an independent boolean differential both confirm SQL injection."
	case "boolean":
		return "Two independent boolean pairs reproduced the baseline for a TRUE condition and diverged for a FALSE condition; SQL injection is confirmed."
	case "error_timing":
		return "A new database error signature and a read-only delay differential reproduced across two independent rounds with matched fast controls; SQL injection is confirmed."
	case "boolean_timing":
		return "A boolean differential and a read-only delay differential reproduced across two independent rounds with matched fast controls; SQL injection is confirmed."
	case "timing":
		return "A read-only delay differential reproduced across two independent rounds with a fast matched control in each; blind SQL injection is confirmed."
	default:
		return "Two independent syntax probes produced a database error signature the baseline did not contain."
	}
}

func (e *sqliExecutor) correlateSQLi(ctx context.Context, job *domain.TestJob, ep *domain.Endpoint, focus *domain.Parameter, d sqliDetail) {
	scan, err := e.store.Scans().Get(ctx, job.ScanID)
	if err != nil {
		return
	}
	now := time.Now()
	detail, _ := json.Marshal(d)
	f := &domain.Finding{
		ID: domain.NewID(), ScanID: job.ScanID, ProjectID: scan.ProjectID,
		VulnClass: domain.VulnSQLi, Verdict: domain.VerdictConfirmed,
		Severity: domain.SeverityHigh, Confidence: domain.ConfidenceHigh,
		Title:      "SQL injection in parameter " + fmt.Sprintf("%q", focus.Name),
		Summary:    sqliFindingSummary(d),
		EndpointID: ep.ID, InjectionPointID: job.Target.InjectionPointID, ParameterID: focus.ID, Location: focus.Location,
		EvidenceIDs: d.EvidenceIDs, Detail: detail,
		Provenance: domain.Provenance{Engine: sqliEngine, DiscoverySource: ep.Source, DetectedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}
	e.findingsMu.Lock()
	defer e.findingsMu.Unlock()
	if err := e.store.Findings().Create(ctx, f); err != nil {
		e.log.Warn("sqli: persist finding", "scan", job.ScanID, "err", err)
	}
}

// enqueueSQLiProbes queues one bounded job per eligible injection point.
func (c *Controller) enqueueSQLiProbes(ctx context.Context, scanID domain.ID) {
	sc, err := c.store.Scans().Get(ctx, scanID)
	if err != nil || !sc.Config.EnableSQLi {
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
		if err != nil || ep == nil || !isSQLiLocation(ip.Location) {
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
		job := &domain.TestJob{ID: domain.NewID(), ScanID: scanID, Type: domain.JobSQLi,
			State: domain.JobQueued, Priority: 47, Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL},
			Payload: payload, MaxAttempts: 2, AvailableAt: now, CreatedAt: now, UpdatedAt: now}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			c.log.Warn("sqli: enqueue", "scan", scanID, "err", err)
		}
	}
}

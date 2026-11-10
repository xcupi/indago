package domain

import (
	"net/url"
	"strings"
	"time"
)

// Project is the top-level container for an operator's work against a target
// application: scope, scans, findings, and reports all hang off a project.
type Project struct {
	ID    ID     `json:"id"`
	Name  string `json:"name"`
	Notes string `json:"notes,omitempty"`
	// AuthStatePath is the saved Playwright storage state used when a scan
	// chooses auth_mode "existing". Empty means the project has no saved
	// login. It is a server-side path, never a credential itself.
	AuthStatePath string `json:"auth_state_path,omitempty"`
	// HuntingUserAgent is the program-specific traffic identifier, e.g. the
	// suffix a YesWeHack program requires on every request. Empty means the
	// engine's own User-Agent. HuntingUserAgentReplace selects whether the
	// value replaces that default or is appended to it.
	HuntingUserAgent        string    `json:"hunting_user_agent,omitempty"`
	HuntingUserAgentReplace bool      `json:"hunting_user_agent_replace,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// AuthProfile is a reusable authenticated session for a project. Many targets
// can point at one profile (SSO), while a target that needs a different account
// points at a different profile. The state is a Playwright storage-state file.
type AuthProfile struct {
	ID         ID        `json:"id"`
	ProjectID  ID        `json:"project_id"`
	Name       string    `json:"name"`
	LoginURL   string    `json:"login_url,omitempty"`
	SuccessURL string    `json:"success_url,omitempty"`
	StatePath  string    `json:"state_path,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Target is a web application (identified by a base URL) belonging to a project.
type Target struct {
	ID        ID     `json:"id"`
	ProjectID ID     `json:"project_id"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	// AuthProfileID is optional. Empty means anonymous (or the project-level
	// legacy fallback); a profile is shared by as many targets as needed.
	AuthProfileID ID        `json:"auth_profile_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Scope defines the explicit boundary of what may be tested. Scope enforcement
// is a core safety control: it fails closed (deny by default) so that nothing
// outside the operator's declared boundary is ever touched.
type Scope struct {
	ID        ID `json:"id"`
	ProjectID ID `json:"project_id"`

	// IncludeHosts lists hosts that are in scope. A leading dot ("example.com"
	// vs ".example.com") combined with AllowSubdomains controls subdomains.
	IncludeHosts []string `json:"include_hosts"`
	// ExcludeHosts lists hosts that are always out of scope (takes precedence).
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`
	// IncludePathPrefixes, when non-empty, restricts in-scope URLs to those
	// whose path starts with one of these prefixes.
	IncludePathPrefixes []string `json:"include_path_prefixes,omitempty"`
	// ExcludePathPrefixes lists path prefixes that are always out of scope.
	ExcludePathPrefixes []string `json:"exclude_path_prefixes,omitempty"`
	// AllowSubdomains permits subdomains of included hosts.
	AllowSubdomains bool `json:"allow_subdomains"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScopeDecision is the result of a scope check, including a human-readable
// reason suitable for logging and audit.
type ScopeDecision struct {
	Allowed bool
	Reason  string
}

// Permits reports whether the given raw URL is within this scope. It FAILS
// CLOSED: unparseable URLs, empty scopes, and anything not explicitly included
// are denied. Exclusions always win over inclusions.
//
// This is pure matching logic (no network access) and is safe in Phase 0.
func (s Scope) Permits(rawURL string) ScopeDecision {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ScopeDecision{false, "unparseable or hostless URL"}
	}
	host := strings.ToLower(u.Hostname())
	path := u.Path
	if path == "" {
		path = "/"
	}

	if len(s.IncludeHosts) == 0 {
		return ScopeDecision{false, "empty scope denies all (fail closed)"}
	}

	// Exclusions take precedence.
	for _, ex := range s.ExcludeHosts {
		if hostMatches(host, strings.ToLower(ex), s.AllowSubdomains) {
			return ScopeDecision{false, "host excluded: " + ex}
		}
	}
	for _, ep := range s.ExcludePathPrefixes {
		if strings.HasPrefix(path, ep) {
			return ScopeDecision{false, "path excluded: " + ep}
		}
	}

	// Host must be included.
	hostOK := false
	for _, in := range s.IncludeHosts {
		if hostMatches(host, strings.ToLower(in), s.AllowSubdomains) {
			hostOK = true
			break
		}
	}
	if !hostOK {
		return ScopeDecision{false, "host not in scope: " + host}
	}

	// If path-prefix inclusion is configured, the path must match one.
	if len(s.IncludePathPrefixes) > 0 {
		for _, ip := range s.IncludePathPrefixes {
			if strings.HasPrefix(path, ip) {
				return ScopeDecision{true, "in scope"}
			}
		}
		return ScopeDecision{false, "path not in scope: " + path}
	}

	return ScopeDecision{true, "in scope"}
}

// hostMatches reports whether host matches pattern, honoring subdomain rules.
// A pattern with a leading dot (".example.com") always matches subdomains.
func hostMatches(host, pattern string, allowSubdomains bool) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, ".") {
		base := strings.TrimPrefix(pattern, ".")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	if host == pattern {
		return true
	}
	if allowSubdomains && strings.HasSuffix(host, "."+pattern) {
		return true
	}
	return false
}

// ProfileName identifies a scan concurrency/rate preset.
type ProfileName string

const (
	ProfileConservative ProfileName = "conservative"
	ProfileBalanced     ProfileName = "balanced"
	ProfileFast         ProfileName = "fast"
	ProfileCustom       ProfileName = "custom"
)

// IsValid reports whether the profile name is a known value.
func (p ProfileName) IsValid() bool {
	switch p {
	case ProfileConservative, ProfileBalanced, ProfileFast, ProfileCustom:
		return true
	default:
		return false
	}
}

// ScanConfig holds a scan's concurrency, rate, and crawl-extent controls.
//
// The concurrency and rate controls are runtime-tunable: all four may be
// changed while a scan is running (see Controller.Reconfigure). The crawl
// controls (QuickScan, MaxDepth, MaxPages, MaxEndpoints) are read when
// discovery starts, so changing them only affects a subsequent discovery run —
// exactly like DiscoveryConcurrency's effect on the crawl fan-out.
type ScanConfig struct {
	DiscoveryConcurrency int `json:"discovery_concurrency"`
	HTTPConcurrency      int `json:"http_concurrency"`
	BrowserConcurrency   int `json:"browser_concurrency"`
	// HuntingUserAgent/HuntingUserAgentReplace are copied from the project at
	// scan creation/start so every raw request and browser context carries the
	// program's required traffic identifier.
	HuntingUserAgent        string `json:"hunting_user_agent,omitempty"`
	HuntingUserAgentReplace bool   `json:"hunting_user_agent_replace,omitempty"`
	// AuthProfileID records which reusable session supplied this scan's auth,
	// when it came from a target profile rather than a manual path.
	AuthProfileID ID `json:"auth_profile_id,omitempty"`

	// SkipGlobalInjection omits the location-agnostic header and cookie
	// injection points from discovery. Those points are useful on a small
	// application, but on a WAF-fronted site they mostly generate CAPTCHA
	// inconclusive findings and consume the request budget before the
	// endpoint's own query/form parameters are tested. Off by default so
	// existing scans keep their previous coverage; new imports opt in.
	SkipGlobalInjection bool `json:"skip_global_injection,omitempty"`
	// SkipStaticAssets drops crawler/browser-discovered CSS, JavaScript,
	// images, fonts and similar resources before they become test targets.
	// Operator-supplied seeds are never dropped. Off by default for
	// backward compatibility.
	SkipStaticAssets bool `json:"skip_static_assets,omitempty"`

	// Capability switches. False keeps the engine enabled (the historical
	// behavior for every existing scan); true omits that engine's jobs while
	// leaving discovery and the other engines intact. OMIT the DOM switch to
	// also omit the client-side open-redirect probe, which rides that pass.
	SkipReflectedXSS   bool `json:"skip_reflected_xss,omitempty"`
	SkipDOMXSS         bool `json:"skip_dom_xss,omitempty"`
	SkipAccessControl  bool `json:"skip_access_control,omitempty"`
	SkipIDOR           bool `json:"skip_idor,omitempty"`
	SkipInfoDisclosure bool `json:"skip_info_disclosure,omitempty"`

	// SkipWriteEndpoints keeps payload-bearing engines away from endpoints
	// that look like writes: non-GET/HEAD/OPTIONS methods, Laravel-style
	// `_method` overrides, and path verbs such as store/update/delete/upload.
	// A reflected-XSS probe must not create or mutate records merely because a
	// form was in crawl scope. Off by default for backward compatibility; new
	// imports and the UI default to on.
	SkipWriteEndpoints bool `json:"skip_write_endpoints,omitempty"`

	// RequestsPerSecond is ONE budget for all of the scan's target-facing
	// requests: discovery fetches (crawl, sitemap, robots, content), redirect
	// hops, raw test requests, and browser discovery/verification navigations.
	// 0 = unlimited (discouraged).
	RequestsPerSecond float64 `json:"requests_per_second"`

	// QuickScan limits discovery to the seeds themselves (crawl depth 0): the
	// seed endpoints and their own parameters are tested, but no links are
	// followed. It overrides MaxDepth. A full ("crawl") scan leaves it false.
	QuickScan bool `json:"quick_scan,omitempty"`
	// MaxDepth is the crawl depth for a full scan (links followed from the
	// seeds). 0 means "use the server default"; QuickScan forces seeds-only
	// regardless. Ignored when QuickScan is set.
	MaxDepth int `json:"max_depth,omitempty"`
	// MaxPages caps pages fetched by the crawler (0 = server default).
	MaxPages int `json:"max_pages,omitempty"`
	// MaxEndpoints caps endpoints discovered (0 = server default).
	MaxEndpoints int `json:"max_endpoints,omitempty"`

	// ReconLevel selects the opt-in wordlist content/parameter discovery:
	// "off" (default), "safe", "standard", or "aggressive". Empty means off,
	// which keeps every pre-existing scan byte-identical (no wordlist
	// requests). Read when discovery starts, like the crawl controls. See
	// discovery.Config.ReconLevel and docs/recon-wordlists.md.
	ReconLevel string `json:"recon_level,omitempty"`

	// CandidateProfile selects how many/which of the planner's candidates are
	// sent per injection point: "minimal", "standard" (default when empty), or
	// "thorough" (see internal/detection/profile.go). MaxCandidates, when > 0,
	// overrides the profile's per-injection-point cap (hard ceiling in
	// detection.MaxCandidatesCeiling). Like the crawl controls, both are set at
	// creation and read when a reflection step plans its candidates; they
	// select among the built-in candidates and never affect verification.
	CandidateProfile string `json:"candidate_profile,omitempty"`
	MaxCandidates    int    `json:"max_candidates,omitempty"`

	// EnableEvasion requests EAGER WAF/filter-bypass candidate variants (case
	// variation, alternate whitespace/separators, HTML-entity/double-URL
	// encoding of the breakout characters) IN ADDITION TO the canonical
	// candidates — never instead of them. Without it, the scan controller may
	// still run one separately bounded, evidence-gated Technique-only fallback
	// after canonical candidates at the same reflected-XSS injection point finish
	// without confirmation; see internal/scan/evasion_escalation.go. Every
	// evasion candidate is still a benign-marker detection probe (never
	// alert/cookie/exfiltration) and is still sent only through the SAME
	// scope-enforcing engine as every other request — this widens the candidate
	// SHAPES tried, not what may be targeted. See docs/reflection-candidates.md.
	EnableEvasion bool `json:"enable_evasion,omitempty"`

	// RawQueryInjection opts into testing the WHOLE query string as one
	// injection point, for endpoints that echo their entire query string
	// (a canonical <link href>, some 404/search/error pages) and therefore
	// have no named parameter to test. "" / "off" (the default) adds nothing
	// and keeps every existing scan byte-identical; "auto" probes only GET
	// endpoints with no named query parameters; "always" also probes
	// endpoints that do have them. Bounded (2 probe shapes per endpoint,
	// 40 probes per scan) and GET-only; every request goes through the same
	// scope-enforcing engine, limiter and session as a named parameter, and
	// the probe flows through the same reflection → context → candidate →
	// browser-verification pipeline. See docs/raw-query-injection.md.
	RawQueryInjection string `json:"raw_query_injection,omitempty"`

	// ProxyPool, when non-empty, routes every outbound request this scan
	// makes — raw HTTP engine requests AND browser verification navigation
	// alike — through one of the listed proxies ("http://host:port",
	// "socks5://host:port", optionally with embedded "user:pass@" creds),
	// picked round-robin per request/context. Empty (the default) means a
	// direct connection: no proxy, Indago's real network identity.
	//
	// This is entirely operator-supplied infrastructure — Indago never
	// discovers, purchases, or manages proxies itself, and never silently
	// rotates through anything the operator did not explicitly list here.
	// Off by default (AGENTS.md §2.3: aggressive/identity-concealing
	// behavior is opt-in and operator-configured, never silent). Pairs with
	// EnableEvasion for an engagement where the target's own anti-automation
	// defenses (rate limiting, IP-based blocking) are themselves in scope —
	// it does not widen WHAT may be targeted, only hides WHICH network
	// identity is doing the targeting.
	ProxyPool []string `json:"proxy_pool,omitempty"`

	// RandomizeTLSFingerprint: see httpengine.Config.RandomizeTLSFingerprint
	// for the full mechanism and its one real limitation (HTTP/1.1 only).
	// Off by default, same AGENTS.md §2.3 contract as ProxyPool/EnableEvasion
	// above. MUTUALLY EXCLUSIVE with ProxyPool (validated at scan-create
	// time, see controller.go) — Go's http.Transport only consults a custom
	// TLS dialer for a DIRECT connection, never a proxied one, so combining
	// both would silently drop the fingerprint override instead of erroring.
	// Browser verification is unaffected either way: a real Chromium
	// context has its own, genuine (unspoofed) TLS stack that this setting
	// has no way to reach into.
	RandomizeTLSFingerprint bool `json:"randomize_tls_fingerprint,omitempty"`

	// The IDOR engine (object-identifier differential, see internal/idor and
	// docs/idor.md) has no enable switch: it runs automatically for any scan
	// that carries a real caller identity, because the differential needs
	// exactly that — an authenticated session to establish the caller from and
	// an object-identifier-shaped parameter to vary. An anonymous scan plans
	// nothing, since it has no identity to compare against.
	//
	// IDORCandidates are operator-supplied foreign object identifiers, e.g.
	// the victim username a lab brief names ("carlos") or an unpredictable id.
	// They are only ever tried as read-only GET/HEAD object lookups inside the
	// scan's scope; the engine never invents them. Empty leaves derivation to
	// bounded numeric neighbours of the caller's own identifier.
	IDORCandidates []string `json:"idor_candidates,omitempty"`

	// EnableIDOREnumeration opts into the bounded enumeration pass: when a
	// parameter's observed identifier is numeric (7), try 6, 8 and 1..N; when
	// it is a short slug, try the fixed common neighbours admin/test/demo/
	// guest. It is a separate, explicit switch ON TOP of the automatic engine,
	// OFF by default, and never a wordlist (see internal/idor/enumerate.go and
	// docs/idor.md). Requires an authenticated session.
	EnableIDOREnumeration bool `json:"idor_enumerate,omitempty"`
	// IDOREnumerationNeighbours is N: how many low integers 1..N are tried for
	// a numeric baseline. 0 means the engine default (5); the hard ceiling is
	// internal/idor.MaxEnumerationNeighbours (10).
	IDOREnumerationNeighbours int `json:"idor_enumerate_n,omitempty"`

	// EnableRoleParam opts this scan into the access-control engine's
	// client-controlled-flag differential (case 20): the SAME privileged
	// endpoint is fetched with a role-shaped query parameter or cookie absent
	// and then set to an admin-like value, and a finding is made only when the
	// privileged admin action surface becomes reachable. GET only, same-origin,
	// bounded, OFF by default (the engine may propose the conventional /admin
	// path when discovery found no privileged endpoint). See
	// docs/access-control.md.
	EnableRoleParam bool `json:"enable_role_param,omitempty"`

	// EnableAccessControlPages opts this scan into the access-control engine's
	// page-disclosure pass (case 19's "unpredictable path" source): discovered
	// HTML pages are re-fetched, the administrative path literals their OWN
	// inline/same-origin scripts contain are extracted, and each disclosed
	// path is probed anonymously for administrative actions. Off by default
	// so a pre-existing scan sends exactly the same requests as before; the
	// robots.txt/sitemap path pass needs no opt-in because discovery already
	// registered those paths. Never a wordlist: only literals the target's own
	// bytes contain. See docs/access-control.md.
	EnableAccessControlPages bool `json:"enable_access_control_pages,omitempty"`

	// EnableRoleWrite opts this scan into the access-control engine's
	// role-field slice (case 21): the caller's OWN profile update is sent with
	// one client-supplied role field, and a finding is made only when a
	// privileged surface that was denied BEFORE the write is reachable AFTER
	// it. It is state-changing, so it ALSO requires the server's explicit
	// AllowStateChanging opt-in and an authenticated session — both are
	// refused at scan creation, never enabled implicitly. It never targets
	// another principal's profile.
	EnableRoleWrite bool `json:"enable_role_write,omitempty"`

	// EnableAdminStepProbe opts this scan into the admin-action step probes
	// (cases 35 and 36): the role-change endpoint is called with a username
	// that does NOT exist, once with the confirmation flag and once with the
	// administrative Referer, and a finding needs the caller to be refused on
	// the ordinary request while the variant reaches the application handler
	// and the anonymous control is refused too. Nothing can change: the named
	// user never exists. Off by default; requires an authenticated session.
	EnableAdminStepProbe bool `json:"enable_admin_step_probe,omitempty"`

	// EnableObjectFamilyProbe opts this scan into the object-family slice
	// (case 34): a page's own scripts name an endpoint that CREATES an object
	// and the field that carries it, so the scan submits its own marker, reads
	// the object the server names, and probes the two neighbouring ids. It
	// POSTs a document the scan authored, so it is off by default and requires
	// an authenticated session. A finding needs a sibling that differs from the
	// caller's own document AND discloses a credential.
	EnableObjectFamilyProbe bool `json:"enable_object_family_probe,omitempty"`

	// EnableXSSLibrary opts this scan into the cheat-sheet library families
	// (see internal/detection/library.go): MathML-adjacent tags, media source
	// errors, autofocus handlers, srcdoc, form javascript: actions. They are
	// planned ON TOP OF the canonical candidates and still capped by the
	// candidate profile, and a finding still needs a browser execution signal.
	EnableXSSLibrary bool `json:"enable_xss_library,omitempty"`
}

// StopMode controls when a scan stops relative to confirmed findings.
type StopMode string

const (
	StopContinueAll     StopMode = "continue_all"
	StopFirstConfirmed  StopMode = "first_confirmed"
	StopAfterNConfirmed StopMode = "after_n_confirmed"
	StopPauseAndAsk     StopMode = "pause_and_ask"
)

// IsValid reports whether the stop mode is a known value.
func (m StopMode) IsValid() bool {
	switch m {
	case StopContinueAll, StopFirstConfirmed, StopAfterNConfirmed, StopPauseAndAsk:
		return true
	default:
		return false
	}
}

// StopPolicy expresses the operator's stop condition for a scan.
type StopPolicy struct {
	Mode           StopMode `json:"mode"`
	ConfirmedLimit int      `json:"confirmed_limit,omitempty"` // used when Mode == after_n_confirmed
}

// ScanStats is a lightweight rollup of scan progress for the UI/CLI.
type ScanStats struct {
	EndpointsDiscovered  int `json:"endpoints_discovered"`
	ParametersDiscovered int `json:"parameters_discovered"`
	JobsQueued           int `json:"jobs_queued"`
	JobsCompleted        int `json:"jobs_completed"`
	JobsFailed           int `json:"jobs_failed"`
	JobsCanceled         int `json:"jobs_canceled"`
	// JobsTotal is every job ever queued for the scan, including jobs that
	// failed, were canceled, or are still pending. Progress uses this fixed
	// denominator: canceling queued work must not make 1200/1400 jump to
	// 1200/1200.
	JobsTotal            int `json:"jobs_total"`
	FindingsConfirmed    int `json:"findings_confirmed"`
	FindingsRejected     int `json:"findings_rejected"`
	FindingsInconclusive int `json:"findings_inconclusive"`
	// AskedAtConfirmed is the confirmed-finding count at which a
	// StopPauseAndAsk policy last paused the scan for operator review.
	// Persisted (not just kept in memory) so a restart does not forget it and
	// immediately re-pause for findings the operator already saw before the
	// crash — see docs/e2e-validation.md.
	AskedAtConfirmed int `json:"asked_at_confirmed,omitempty"`
}

// Scan is a single hunting run against a target, using one reused auth session.
type Scan struct {
	ID        ID          `json:"id"`
	ProjectID ID          `json:"project_id"`
	TargetID  ID          `json:"target_id"`
	Name      string      `json:"name"`
	State     ScanState   `json:"state"`
	Profile   ProfileName `json:"profile"`
	Config    ScanConfig  `json:"config"`
	Stop      StopPolicy  `json:"stop"`
	SessionID ID          `json:"session_id,omitempty"`
	// SeedURLs are the operator-provided discovery seeds. When empty, the
	// target's base URL is the seed.
	SeedURLs []string `json:"seed_urls,omitempty"`
	// Discovery is the persisted state of the scan's discovery run. It lets a
	// restarted scan know whether discovery still has to run.
	Discovery DiscoveryState `json:"discovery"`
	Stats     ScanStats      `json:"stats"`
	Error     string         `json:"error,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

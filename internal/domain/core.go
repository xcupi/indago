package domain

import (
	"net/url"
	"strings"
	"time"
)

// Project is the top-level container for an operator's work against a target
// application: scope, scans, findings, and reports all hang off a project.
type Project struct {
	ID        ID        `json:"id"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Target is a web application (identified by a base URL) belonging to a project.
type Target struct {
	ID        ID        `json:"id"`
	ProjectID ID        `json:"project_id"`
	Name      string    `json:"name"`
	BaseURL   string    `json:"base_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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

// ScanConfig holds the runtime-tunable concurrency and rate controls. All of
// these may be changed while a scan is running.
type ScanConfig struct {
	DiscoveryConcurrency int     `json:"discovery_concurrency"`
	HTTPConcurrency      int     `json:"http_concurrency"`
	BrowserConcurrency   int     `json:"browser_concurrency"`
	RequestsPerSecond    float64 `json:"requests_per_second"` // 0 = unlimited (discouraged)
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
	FindingsConfirmed    int `json:"findings_confirmed"`
	FindingsRejected     int `json:"findings_rejected"`
	FindingsInconclusive int `json:"findings_inconclusive"`
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
	Stats     ScanStats   `json:"stats"`
	Error     string      `json:"error,omitempty"`

	CreatedAt time.Time  `json:"created_at"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

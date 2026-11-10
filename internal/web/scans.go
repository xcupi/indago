package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/idor"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
)

// Upper bounds for operator-supplied concurrency, so a typo cannot spawn an
// unbounded number of workers against a target.
const (
	maxConcurrency = 64
	maxRPS         = 1000
)

// --- targets ---

type createTargetReq struct {
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), id); err != nil {
		s.writeLookupError(w, err)
		return
	}
	targets, err := s.store.Targets().ListByProject(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, "list targets", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(targets))
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req createTargetReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	u, err := url.Parse(strings.TrimSpace(req.BaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		writeError(w, http.StatusBadRequest, "base_url must be an absolute http(s) URL")
		return
	}
	now := time.Now()
	t := &domain.Target{ID: domain.NewID(), ProjectID: projectID, Name: req.Name, BaseURL: u.String(), CreatedAt: now, UpdatedAt: now}
	if err := s.store.Targets().Create(r.Context(), t); err != nil {
		s.writeInternalError(w, "create target", err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	t, err := s.store.Targets().Get(r.Context(), domain.ID(r.PathValue("tid")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	if t.ProjectID != projectID {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// --- scope ---

type scopeReq struct {
	IncludeHosts        []string `json:"include_hosts"`
	ExcludeHosts        []string `json:"exclude_hosts"`
	IncludePathPrefixes []string `json:"include_path_prefixes"`
	ExcludePathPrefixes []string `json:"exclude_path_prefixes"`
	AllowSubdomains     bool     `json:"allow_subdomains"`
}

func (s *Server) handleGetScope(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.Scopes().GetByProject(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// handlePutScope creates or replaces a project's scope. Scope is the safety
// boundary for every scan, so an empty include list is rejected outright rather
// than stored (an empty scope would deny everything anyway).
func (s *Server) handlePutScope(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req scopeReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	include := cleanList(req.IncludeHosts)
	if len(include) == 0 {
		writeError(w, http.StatusBadRequest, "include_hosts must contain at least one host")
		return
	}
	exclude := cleanList(req.ExcludeHosts)
	includePaths := cleanList(req.IncludePathPrefixes)
	excludePaths := cleanList(req.ExcludePathPrefixes)
	// An entry that can never match is not an error at match time: it just makes
	// the scope silently deny the host the operator meant. Reject it here, before
	// anything is stored, so a rejected replacement leaves the old scope intact.
	if msg := validateScopeLists(include, exclude, includePaths, excludePaths); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	now := time.Now()
	existing, err := s.store.Scopes().GetByProject(r.Context(), projectID)
	switch {
	case err == nil:
		existing.IncludeHosts = include
		existing.ExcludeHosts = exclude
		existing.IncludePathPrefixes = includePaths
		existing.ExcludePathPrefixes = excludePaths
		existing.AllowSubdomains = req.AllowSubdomains
		existing.UpdatedAt = now
		if err := s.store.Scopes().Update(r.Context(), existing); err != nil {
			s.writeInternalError(w, "update scope", err)
			return
		}
		writeJSON(w, http.StatusOK, existing)
	case errors.Is(err, store.ErrNotFound):
		sc := &domain.Scope{
			ID: domain.NewID(), ProjectID: projectID,
			IncludeHosts: include, ExcludeHosts: exclude,
			IncludePathPrefixes: includePaths,
			ExcludePathPrefixes: excludePaths,
			AllowSubdomains:     req.AllowSubdomains,
			CreatedAt:           now, UpdatedAt: now,
		}
		if err := s.store.Scopes().Create(r.Context(), sc); err != nil {
			s.writeInternalError(w, "create scope", err)
			return
		}
		writeJSON(w, http.StatusCreated, sc)
	default:
		s.writeInternalError(w, "load scope", err)
	}
}

// --- scans ---

type stopReq struct {
	Mode           string `json:"mode"`
	ConfirmedLimit int    `json:"confirmed_limit"`
}

type createScanReq struct {
	ProjectID     string `json:"project_id"`
	TargetID      string `json:"target_id"`
	Name          string `json:"name"`
	Profile       string `json:"profile"`
	AuthMode      string `json:"auth_mode"`
	AuthProfileID string `json:"auth_profile_id,omitempty"`
	// AuthStatePath is the absolute, server-side path of saved session
	// material (Playwright storage state) for auth_mode "existing".
	AuthStatePath string `json:"auth_state_path"`
	// LoginURL/SuccessURL/Login*Selector drive the login itself for auth_mode
	// "interactive", "mfa", or "password" — see CreateScanParams.LoginURL
	// and friends for the full contract (success_url is REQUIRED for all
	// three; password mode also needs INDAGO_AUTH_USER/INDAGO_AUTH_PASS set
	// in the SERVER's own environment, never in this request body).
	LoginURL              string             `json:"login_url"`
	SuccessURL            string             `json:"success_url"`
	LoginUsernameSelector string             `json:"login_username_selector"`
	LoginPasswordSelector string             `json:"login_password_selector"`
	LoginSubmitSelector   string             `json:"login_submit_selector"`
	SeedURLs              []string           `json:"seed_urls"`
	Stop                  *stopReq           `json:"stop"`
	Config                *domain.ScanConfig `json:"config"`

	// Crawl extent, applied on top of the chosen profile (any profile). Quick
	// limits discovery to the seeds (no link following); a full "crawl" scan
	// leaves it false. MaxDepth/MaxPages/MaxEndpoints override server defaults
	// when > 0.
	QuickScan    bool `json:"quick_scan"`
	MaxDepth     int  `json:"max_depth"`
	MaxPages     int  `json:"max_pages"`
	MaxEndpoints int  `json:"max_endpoints"`
	// ReconLevel selects opt-in wordlist content/parameter discovery:
	// "off" (default) | "safe" | "standard" | "aggressive". See
	// domain.ScanConfig.ReconLevel and docs/recon-wordlists.md.
	ReconLevel string `json:"recon_level"`

	// Candidate selection: "minimal" | "standard" (default) | "thorough", and an
	// optional per-injection-point cap overriding the profile's. Validated by
	// the controller (unknown profile / cap above the ceiling → 400).
	CandidateProfile string `json:"candidate_profile"`
	MaxCandidates    int    `json:"max_candidates"`

	// EnableEvasion asks for eager WAF/filter-bypass candidate variants. Without
	// it, the scan controller may still run the separately bounded automatic
	// fallback after canonical misses; see domain.ScanConfig.EnableEvasion.
	EnableEvasion bool `json:"enable_evasion"`

	// RawQueryInjection opts this scan into testing the WHOLE query string as
	// one injection point ("off" default, "auto", or "always") — see
	// domain.ScanConfig.RawQueryInjection and docs/raw-query-injection.md.
	RawQueryInjection string `json:"raw_query_injection"`

	// ProxyPool, when non-empty, routes this scan's outbound traffic (raw HTTP
	// and browser verification alike) through one of the listed proxies,
	// round-robin. See domain.ScanConfig.ProxyPool. Empty (the default) means
	// a direct connection.
	ProxyPool []string `json:"proxy_pool"`

	// RandomizeTLSFingerprint — see domain.ScanConfig.RandomizeTLSFingerprint.
	// Off by default; the server rejects this combined with ProxyPool (see
	// Controller.CreateScan) rather than silently no-op the override.
	RandomizeTLSFingerprint bool `json:"randomize_tls_fingerprint"`

	// The IDOR engine (object-identifier differential) has no enable switch:
	// it runs automatically for a scan that carries a real caller identity.
	// IDORCandidates are operator-supplied foreign object identifiers, e.g.
	// the victim username an authorized lab brief names. Bounded/validated by
	// the controller; explicit values always come first and are merged ahead
	// of identifiers the engine harvests from the scan's own data. Empty means
	// "use the harvested set" — no candidate is ever guessed.
	IDORCandidates []string `json:"idor_candidates"`
	// EnableIDOREnumeration opts into the IDOR engine's bounded enumeration
	// pass (numeric neighbours + a fixed short-slug set). Requires an
	// authenticated session; off by default. IDOREnumerationNeighbours is N
	// (0 = engine default 5, ceiling 10). See docs/idor.md.
	EnableIDOREnumeration     bool `json:"idor_enumerate"`
	IDOREnumerationNeighbours int  `json:"idor_enumerate_n"`

	// EnableRoleParam opts into the access-control engine's client-controlled
	// flag differential (case 20). Off by default; GET only, bounded.
	EnableRoleParam bool `json:"enable_role_param"`
	// EnableAccessControlPages opts into page-script path disclosure (case
	// 19's unpredictable path). Off by default; GET only, bounded.
	EnableAccessControlPages bool `json:"enable_access_control_pages"`
	// EnableRoleWrite opts into the access-control engine's role-field slice
	// (case 21). Off by default; the server rejects it for an anonymous scan
	// or when it was not started with -allow-state-changing.
	EnableRoleWrite bool `json:"enable_role_write"`
	// EnableAdminStepProbe opts into the cases 35/36 admin-action probes (a
	// non-existent username, so no role can change). Requires a session.
	EnableAdminStepProbe bool `json:"enable_admin_step_probe"`
	// EnableObjectFamilyProbe opts into the case 34 object-family slice: the
	// scan submits its own object and probes the neighbouring ids.
	EnableObjectFamilyProbe bool `json:"enable_object_family_probe"`
	// EnableXSSLibrary opts into the cheat-sheet library families.
	EnableXSSLibrary bool `json:"enable_xss_library"`
	// SkipGlobalInjection omits header/cookie injection points.
	SkipGlobalInjection bool `json:"skip_global_injection"`
	// SkipStaticAssets drops crawler/browser-discovered static resources.
	SkipStaticAssets bool `json:"skip_static_assets"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	if req.ProjectID == "" || req.TargetID == "" {
		writeError(w, http.StatusBadRequest, "project_id and target_id are required")
		return
	}

	// Reject explicit-but-invalid values instead of silently defaulting them.
	profile := domain.ProfileName(req.Profile)
	if req.Profile != "" && !profile.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown profile "+req.Profile)
		return
	}
	mode := domain.AuthMode(req.AuthMode)
	if req.AuthMode != "" && !mode.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown auth_mode "+req.AuthMode)
		return
	}
	var stop domain.StopPolicy
	if req.Stop != nil {
		stop = domain.StopPolicy{Mode: domain.StopMode(req.Stop.Mode), ConfirmedLimit: req.Stop.ConfirmedLimit}
		if !stop.Mode.IsValid() {
			writeError(w, http.StatusBadRequest, "unknown stop mode "+req.Stop.Mode)
			return
		}
		if stop.Mode == domain.StopAfterNConfirmed && stop.ConfirmedLimit < 1 {
			writeError(w, http.StatusBadRequest, "after_n_confirmed requires confirmed_limit >= 1")
			return
		}
	}
	if req.Config != nil {
		if profile != domain.ProfileCustom {
			writeError(w, http.StatusBadRequest, "config is only valid with profile \"custom\"")
			return
		}
		if msg := validateConfig(*req.Config); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}

	sc, err := s.ctrl.CreateScan(r.Context(), scan.CreateScanParams{
		ProjectID:             domain.ID(req.ProjectID),
		TargetID:              domain.ID(req.TargetID),
		Name:                  strings.TrimSpace(req.Name),
		Profile:               profile,
		Config:                req.Config,
		Stop:                  stop,
		AuthMode:              mode,
		AuthProfileID:         domain.ID(req.AuthProfileID),
		AuthStatePath:         req.AuthStatePath,
		LoginURL:              req.LoginURL,
		SuccessURL:            req.SuccessURL,
		LoginUsernameSelector: req.LoginUsernameSelector,
		LoginPasswordSelector: req.LoginPasswordSelector,
		LoginSubmitSelector:   req.LoginSubmitSelector,
		SeedURLs:              req.SeedURLs,
		QuickScan:             req.QuickScan,
		MaxDepth:              req.MaxDepth,
		MaxPages:              req.MaxPages,
		MaxEndpoints:          req.MaxEndpoints,
		ReconLevel:            req.ReconLevel,

		CandidateProfile:          req.CandidateProfile,
		MaxCandidates:             req.MaxCandidates,
		EnableEvasion:             req.EnableEvasion,
		RawQueryInjection:         req.RawQueryInjection,
		ProxyPool:                 cleanList(req.ProxyPool),
		RandomizeTLSFingerprint:   req.RandomizeTLSFingerprint,
		IDORCandidates:            req.IDORCandidates,
		EnableIDOREnumeration:     req.EnableIDOREnumeration,
		IDOREnumerationNeighbours: req.IDOREnumerationNeighbours,
		EnableRoleParam:           req.EnableRoleParam,
		EnableAccessControlPages:  req.EnableAccessControlPages,
		EnableRoleWrite:           req.EnableRoleWrite,
		EnableAdminStepProbe:      req.EnableAdminStepProbe,
		EnableObjectFamilyProbe:   req.EnableObjectFamilyProbe,
		EnableXSSLibrary:          req.EnableXSSLibrary,
		SkipGlobalInjection:       req.SkipGlobalInjection,
		SkipStaticAssets:          req.SkipStaticAssets,
	})
	if err != nil {
		s.writeScanError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.ctrl.Status(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleScanAction routes start/pause/resume/cancel to the scan controller and
// returns the scan's fresh status.
func (s *Server) handleScanAction(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	var do func() error
	switch r.PathValue("action") {
	case "start":
		do = func() error { return s.ctrl.Start(r.Context(), id) }
	case "pause":
		do = func() error { return s.ctrl.Pause(r.Context(), id) }
	case "resume":
		do = func() error { return s.ctrl.Resume(r.Context(), id) }
	case "cancel":
		do = func() error { return s.ctrl.Cancel(r.Context(), id) }
	default:
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	if err := do(); err != nil {
		s.writeScanError(w, err)
		return
	}
	st, err := s.ctrl.Status(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// reconfigureReq carries the runtime-tunable controls only. Crawl extent
// (quick/depth/limits) is fixed at creation and is preserved here.
type reconfigureReq struct {
	DiscoveryConcurrency int     `json:"discovery_concurrency"`
	HTTPConcurrency      int     `json:"http_concurrency"`
	BrowserConcurrency   int     `json:"browser_concurrency"`
	RequestsPerSecond    float64 `json:"requests_per_second"`
}

// handleReconfigureScan changes a scan's concurrency/rate at runtime. It reads
// the scan's current config and overlays only the four runtime fields, so the
// crawl-extent controls set at creation are never clobbered.
func (s *Server) handleReconfigureScan(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req reconfigureReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	cfg := sc.Config // preserve QuickScan/MaxDepth/MaxPages/MaxEndpoints
	cfg.DiscoveryConcurrency = req.DiscoveryConcurrency
	cfg.HTTPConcurrency = req.HTTPConcurrency
	cfg.BrowserConcurrency = req.BrowserConcurrency
	cfg.RequestsPerSecond = req.RequestsPerSecond
	if msg := validateConfig(cfg); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if err := s.ctrl.Reconfigure(r.Context(), id, cfg); err != nil {
		s.writeScanError(w, err)
		return
	}
	st, err := s.ctrl.Status(r.Context(), id)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// loginReq is the interactive-login request.
type loginReq struct {
	ProjectID  domain.ID `json:"project_id"`
	LoginURL   string    `json:"login_url"`
	SuccessURL string    `json:"success_url"`
	// A login either creates a new reusable profile (ProfileName) or refreshes
	// an existing one (AuthProfileID). With neither, it keeps the legacy
	// project-level fallback session.
	AuthProfileID domain.ID `json:"auth_profile_id,omitempty"`
	ProfileName   string    `json:"profile_name,omitempty"`
}

// handleInteractiveLogin drives a visible-browser login and returns the saved
// session file's PATH only — never its contents (cookies/tokens). The operator
// then uses that path as auth_state_path with auth_mode "existing". It blocks
// until the login completes, times out, or the request is canceled, so the UI
// shows a waiting/MFA state meanwhile.
func (s *Server) handleInteractiveLogin(w http.ResponseWriter, r *http.Request) {
	if s.login == nil {
		writeError(w, http.StatusNotImplemented, "interactive login is not available (start the server with a browser configured: indago serve -browser)")
		return
	}
	var req loginReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	u, err := url.Parse(strings.TrimSpace(req.LoginURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		writeError(w, http.StatusBadRequest, "login_url must be an absolute http(s) URL")
		return
	}
	if req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required for login; select a project and configure Projects → Scope, including explicitly authorized SSO hosts")
		return
	}
	project, err := s.store.Projects().Get(r.Context(), req.ProjectID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeInternalError(w, "login project", err)
			return
		}
		writeError(w, http.StatusBadRequest, "login project not found; select an existing project")
		return
	}
	var profile *domain.AuthProfile
	if req.AuthProfileID != "" {
		profile, err = s.projectAuthProfile(r, req.ProjectID, req.AuthProfileID)
		if err != nil {
			s.writeLookupError(w, err)
			return
		}
	}
	if req.ProfileName != "" && len(strings.TrimSpace(req.ProfileName)) > 120 {
		writeError(w, http.StatusBadRequest, "profile_name must be at most 120 characters")
		return
	}
	scope, err := s.store.Scopes().GetByProject(r.Context(), req.ProjectID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeInternalError(w, "login scope", err)
			return
		}
		writeError(w, http.StatusBadRequest, "login requires project scope; configure Projects → Scope, including explicitly authorized SSO hosts")
		return
	}
	if !scope.Permits(u.String()).Allowed {
		writeError(w, http.StatusBadRequest, "login_url is outside project scope; explicitly include authorized login/SSO hosts and paths in Projects → Scope")
		return
	}
	allow := func(raw string) bool { return scope.Permits(raw).Allowed }
	ua := strings.TrimSpace(project.HuntingUserAgent)
	if ua != "" && !project.HuntingUserAgentReplace {
		ua = httpengine.DefaultUserAgent + " " + ua
	}
	statePath, finalURL, err := s.login(r.Context(), LoginParams{
		AllowRequest: allow,
		LoginURL:     u.String(),
		SuccessURL:   strings.TrimSpace(req.SuccessURL),
		UserAgent:    ua,
	})
	if err != nil {
		if r.Context().Err() != nil {
			// Operator navigated away / canceled: not a server fault.
			writeError(w, http.StatusRequestTimeout, "login canceled or timed out")
			return
		}
		s.writeInternalError(w, "interactive login", err)
		return
	}
	profileID := ""
	switch {
	case profile != nil:
		profile.StatePath = statePath
		profile.LoginURL = u.String()
		profile.SuccessURL = strings.TrimSpace(req.SuccessURL)
		profile.UpdatedAt = time.Now()
		if err := s.store.AuthProfiles().Update(r.Context(), profile); err != nil {
			s.writeInternalError(w, "save auth profile session", err)
			return
		}
		profileID = string(profile.ID)
	case strings.TrimSpace(req.ProfileName) != "":
		now := time.Now()
		created := &domain.AuthProfile{
			ID: domain.NewID(), ProjectID: req.ProjectID, Name: strings.TrimSpace(req.ProfileName),
			LoginURL: u.String(), SuccessURL: strings.TrimSpace(req.SuccessURL), StatePath: statePath,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.store.AuthProfiles().Create(r.Context(), created); err != nil {
			s.writeInternalError(w, "create auth profile session", err)
			return
		}
		profileID = string(created.ID)
	default:
		project.AuthStatePath = statePath
		project.UpdatedAt = time.Now()
		if err := s.store.Projects().Update(r.Context(), project); err != nil {
			s.writeInternalError(w, "save project session", err)
			return
		}
	}
	// Return the path and final URL only. No session material crosses the API.
	out := map[string]string{"state_path": statePath, "final_url": finalURL}
	if profileID != "" {
		out["auth_profile_id"] = profileID
	}
	writeJSON(w, http.StatusOK, out)
}

// writeScanError maps controller errors to HTTP statuses: bad input → 400,
// wrong lifecycle state → 409, missing → 404, shutting down → 503.
func (s *Server) writeScanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, scan.ErrScopeRequired), errors.Is(err, scan.ErrScopeEmpty),
		errors.Is(err, scan.ErrOutOfScope), errors.Is(err, scan.ErrInvalidSeed),
		errors.Is(err, scan.ErrAuth), errors.Is(err, scan.ErrBadConfig):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, scan.ErrBadState), errors.Is(err, scan.ErrNotRunning):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, scan.ErrShutdown):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	default:
		s.log.Error("scan operation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "scan operation failed")
	}
}

// --- helpers ---

func validateConfig(c domain.ScanConfig) string {
	for name, v := range map[string]int{
		"discovery_concurrency": c.DiscoveryConcurrency,
		"http_concurrency":      c.HTTPConcurrency,
		"browser_concurrency":   c.BrowserConcurrency,
	} {
		if v < 0 || v > maxConcurrency {
			return name + " must be between 0 and " + strconv.Itoa(maxConcurrency)
		}
	}
	if c.RequestsPerSecond < 0 || c.RequestsPerSecond > maxRPS {
		return "requests_per_second must be between 0 and " + strconv.Itoa(maxRPS)
	}
	if _, err := discovery.ParseRawQueryMode(c.RawQueryInjection); err != nil {
		return "raw_query_injection: " + err.Error()
	}
	return ""
}

// cleanList trims entries and drops empties.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// validateScopeLists returns "" when every entry could match something, else a
// message naming the first bad entry's field and how to fix it.
func validateScopeLists(include, exclude, includePaths, excludePaths []string) string {
	for _, f := range []struct {
		name    string
		entries []string
		check   func(string) error
	}{
		{"include_hosts", include, domain.ValidateScopeHost},
		{"exclude_hosts", exclude, domain.ValidateScopeHost},
		{"include_path_prefixes", includePaths, domain.ValidateScopePathPrefix},
		{"exclude_path_prefixes", excludePaths, domain.ValidateScopePathPrefix},
	} {
		for i, e := range f.entries {
			if err := f.check(e); err != nil {
				return fmt.Sprintf("%s[%d]: %v", f.name, i, err)
			}
		}
	}
	return ""
}

// nonNil returns an empty slice instead of nil so JSON encodes [] not null.
func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

// --- IDOR harvested candidates (read-only) ---

// idorCandidateDTO is one identifier the IDOR engine harvested from data the
// scan already held. Origin is what lets a report say "tested carlos harvested
// from /admin/users".
type idorCandidateDTO struct {
	Value  string      `json:"value"`
	Shape  string      `json:"shape"`
	Origin idor.Origin `json:"origin"`
	Count  int         `json:"observed_count,omitempty"`
}

type idorCandidatesResp struct {
	ScanID     domain.ID          `json:"scan_id"`
	Candidates []idorCandidateDTO `json:"candidates"`
	Total      int                `json:"total"`
	Note       string             `json:"note,omitempty"`
}

// handleIDORCandidates surfaces the harvested candidate set, read-only. The
// engine persists it on the identity-baseline TestCase; this endpoint never
// probes anything and never triggers harvesting.
func (s *Server) handleIDORCandidates(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), id); err != nil {
		s.writeLookupError(w, err)
		return
	}
	cases, err := s.store.TestCases().ListByScan(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, "list test cases", err)
		return
	}
	resp := idorCandidatesResp{ScanID: id, Candidates: []idorCandidateDTO{}}
	for _, tc := range cases {
		if tc.VulnClass != domain.VulnIDOR || len(tc.Detail) == 0 {
			continue
		}
		var d struct {
			Harvest []idor.Harvest `json:"harvested_candidates"`
			Note    string         `json:"harvest_note"`
		}
		if json.Unmarshal(tc.Detail, &d) != nil {
			continue
		}
		if d.Note != "" && resp.Note == "" {
			resp.Note = d.Note
		}
		if len(d.Harvest) > len(resp.Candidates) {
			resp.Candidates = resp.Candidates[:0]
			for _, h := range d.Harvest {
				resp.Candidates = append(resp.Candidates, idorCandidateDTO{
					Value: h.Value, Shape: string(h.Shape), Origin: h.Origin, Count: h.Count,
				})
			}
		}
	}
	if len(resp.Candidates) == 0 && resp.Note == "" {
		resp.Note = "the IDOR engine has not harvested any identifier for this scan"
	}
	resp.Total = len(resp.Candidates)
	writeJSON(w, http.StatusOK, resp)
}

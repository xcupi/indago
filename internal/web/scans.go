package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
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
		writeError(w, http.StatusBadRequest, "invalid JSON body")
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
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	include := cleanList(req.IncludeHosts)
	if len(include) == 0 {
		writeError(w, http.StatusBadRequest, "include_hosts must contain at least one host")
		return
	}
	now := time.Now()
	existing, err := s.store.Scopes().GetByProject(r.Context(), projectID)
	switch {
	case err == nil:
		existing.IncludeHosts = include
		existing.ExcludeHosts = cleanList(req.ExcludeHosts)
		existing.IncludePathPrefixes = cleanList(req.IncludePathPrefixes)
		existing.ExcludePathPrefixes = cleanList(req.ExcludePathPrefixes)
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
			IncludeHosts: include, ExcludeHosts: cleanList(req.ExcludeHosts),
			IncludePathPrefixes: cleanList(req.IncludePathPrefixes),
			ExcludePathPrefixes: cleanList(req.ExcludePathPrefixes),
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
	ProjectID string `json:"project_id"`
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	AuthMode  string `json:"auth_mode"`
	// AuthStatePath is the absolute, server-side path of saved session
	// material (Playwright storage state) for auth_mode "existing".
	AuthStatePath string             `json:"auth_state_path"`
	SeedURLs      []string           `json:"seed_urls"`
	Stop          *stopReq           `json:"stop"`
	Config        *domain.ScanConfig `json:"config"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanReq
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
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
		ProjectID:     domain.ID(req.ProjectID),
		TargetID:      domain.ID(req.TargetID),
		Name:          strings.TrimSpace(req.Name),
		Profile:       profile,
		Config:        req.Config,
		Stop:          stop,
		AuthMode:      mode,
		AuthStatePath: req.AuthStatePath,
		SeedURLs:      req.SeedURLs,
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

// writeScanError maps controller errors to HTTP statuses: bad input → 400,
// wrong lifecycle state → 409, missing → 404, shutting down → 503.
func (s *Server) writeScanError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, scan.ErrScopeRequired), errors.Is(err, scan.ErrScopeEmpty),
		errors.Is(err, scan.ErrOutOfScope), errors.Is(err, scan.ErrInvalidSeed),
		errors.Is(err, scan.ErrAuth):
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

// nonNil returns an empty slice instead of nil so JSON encodes [] not null.
func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

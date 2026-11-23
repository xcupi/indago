package web

// Reusable authentication profiles. A profile is one saved browser session
// (SSO or a normal login) that any number of targets in the project may point
// at. In target read-only mode, the operator supplies an existing local
// session file from a read-only account.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/indago/indago/internal/auth"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

type authProfileReq struct {
	Name       string  `json:"name"`
	LoginURL   string  `json:"login_url"`
	SuccessURL string  `json:"success_url"`
	StatePath  *string `json:"state_path"`
}

func (s *Server) handleListAuthProfiles(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	profiles, err := s.store.AuthProfiles().ListByProject(r.Context(), projectID)
	if err != nil {
		s.writeInternalError(w, "list auth profiles", err)
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (s *Server) handleCreateAuthProfile(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	if _, err := s.store.Projects().Get(r.Context(), projectID); err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req authProfileReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	statePath, valid := importedStatePath(req.StatePath)
	if !valid {
		writeError(w, http.StatusBadRequest, "state_path must point to a valid local browser session file")
		return
	}
	now := time.Now()
	p := &domain.AuthProfile{
		ID: domain.NewID(), ProjectID: projectID, Name: name, StatePath: statePath,
		LoginURL: strings.TrimSpace(req.LoginURL), SuccessURL: strings.TrimSpace(req.SuccessURL),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.AuthProfiles().Create(r.Context(), p); err != nil {
		s.writeInternalError(w, "create auth profile", err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) projectAuthProfile(r *http.Request, projectID, profileID domain.ID) (*domain.AuthProfile, error) {
	p, err := s.store.AuthProfiles().Get(r.Context(), profileID)
	if err != nil {
		return nil, err
	}
	if p.ProjectID != projectID {
		return nil, store.ErrNotFound
	}
	return p, nil
}

func (s *Server) handleUpdateAuthProfile(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	p, err := s.projectAuthProfile(r, projectID, domain.ID(r.PathValue("profileID")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	var req authProfileReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	if req.StatePath != nil {
		statePath, valid := importedStatePath(req.StatePath)
		if !valid {
			writeError(w, http.StatusBadRequest, "state_path must point to a valid local browser session file")
			return
		}
		p.StatePath = statePath
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		p.Name = name
	}
	p.LoginURL = strings.TrimSpace(req.LoginURL)
	p.SuccessURL = strings.TrimSpace(req.SuccessURL)
	p.UpdatedAt = time.Now()
	if err := s.store.AuthProfiles().Update(r.Context(), p); err != nil {
		s.writeInternalError(w, "update auth profile", err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// importedStatePath accepts only a local storage-state file. Invalid input
// never replaces the saved profile or echoes the file path.
func importedStatePath(raw *string) (string, bool) {
	if raw == nil {
		return "", true
	}
	path := filepath.Clean(strings.TrimSpace(*raw))
	return path, filepath.IsAbs(path) && auth.ValidateStateFile(path) == nil
}

func (s *Server) handleDeleteAuthProfile(w http.ResponseWriter, r *http.Request) {
	projectID := domain.ID(r.PathValue("id"))
	p, err := s.projectAuthProfile(r, projectID, domain.ID(r.PathValue("profileID")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	// References go first: a target must never point at a deleted profile.
	targets, _ := s.store.Targets().ListByProject(r.Context(), projectID)
	for _, t := range targets {
		if t.AuthProfileID == p.ID {
			t.AuthProfileID = ""
			t.UpdatedAt = time.Now()
			_ = s.store.Targets().Update(r.Context(), t)
		}
	}
	if !s.ctrl.ReadOnlyTargets() && p.StatePath != "" {
		_ = os.Remove(p.StatePath)
	}
	if err := s.store.AuthProfiles().Delete(r.Context(), p.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeLookupError(w, err)
			return
		}
		s.writeInternalError(w, "delete auth profile", err)
		return
	}
	s.log.Info("auth profile deleted", "project", projectID, "profile", p.ID)
	w.WriteHeader(http.StatusNoContent)
}

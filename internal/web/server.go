// Package web exposes Indago's local HTTP API and a minimal single-page UI.
//
// Phase 0 provides read endpoints (health, version, projects, scans, stats),
// project creation, and a static dashboard. It performs no scanning itself; scan
// control is delegated to the scan.Controller. The server binds to localhost by
// default (local-first, single-user).
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store"
)

//go:embed assets/*
var assetsFS embed.FS

// Server wires HTTP handlers to the store and scan controller.
type Server struct {
	store   store.Store
	ctrl    *scan.Controller
	log     *slog.Logger
	version string

	// evidence opens evidence blob content for handleGetEvidenceContent. Nil
	// disables that one endpoint (evidence metadata still works via the store).
	evidence evidence.Store
	// reportsDir is where generated reports are written. Empty disables report
	// generation (listing/reading already-generated reports still works).
	reportsDir string

	// allowedHosts, when non-nil, is the set of acceptable Host header values
	// (DNS-rebinding protection). ListenAndServe sets it from the bind address.
	allowedHosts map[string]bool

	// login, when non-nil, performs an interactive browser login and returns
	// the path to the saved session file. Nil disables the interactive-login
	// endpoint (it then reports the feature is unavailable). Wired by
	// cmd/indago only when a browser is configured (-browser).
	login LoginFunc
}

// LoginFunc runs an interactive browser login: it opens a visible browser at
// LoginParams.LoginURL, lets the operator authenticate (including any MFA),
// waits for success, and saves the resulting session material to disk. It
// returns the saved file's path and the final URL reached. The path is a
// server-side filename, not session material — implementations must never
// return cookies, tokens, or storage-state contents.
type LoginFunc func(ctx context.Context, p LoginParams) (statePath, finalURL string, err error)

// LoginParams are the inputs to an interactive login.
type LoginParams struct {
	LoginURL   string // page to open for the operator to log in on
	SuccessURL string // optional glob; login is considered done when the browser reaches it
}

// SetLoginFunc installs the interactive-login implementation. A nil fn (the
// default) leaves the endpoint reporting the feature unavailable.
func (s *Server) SetLoginFunc(fn LoginFunc) { s.login = fn }

// NewServer builds a Server. A nil logger uses slog.Default. evStore and
// reportsDir are optional (nil/"" disables evidence content serving and
// report generation respectively, e.g. in tests that don't need them).
func NewServer(st store.Store, ctrl *scan.Controller, version string, log *slog.Logger, evStore evidence.Store, reportsDir string) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, ctrl: ctrl, log: log, version: version, evidence: evStore, reportsDir: reportsDir}
}

// Handler returns the configured HTTP handler (routes + static UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/version", s.handleVersion)

	mux.HandleFunc("GET /api/projects", s.handleListProjects)
	mux.HandleFunc("POST /api/projects", s.handleCreateProject)
	mux.HandleFunc("GET /api/projects/{id}", s.handleGetProject)
	mux.HandleFunc("GET /api/projects/{id}/targets", s.handleListTargets)
	mux.HandleFunc("POST /api/projects/{id}/targets", s.handleCreateTarget)
	mux.HandleFunc("GET /api/projects/{id}/targets/{tid}", s.handleGetTarget)
	mux.HandleFunc("GET /api/projects/{id}/scope", s.handleGetScope)
	mux.HandleFunc("PUT /api/projects/{id}/scope", s.handlePutScope)

	// Interactive login: drives a visible browser to capture a session file an
	// operator can then use via auth_mode "existing". Available only when the
	// server was given a login function (indago serve -browser).
	mux.HandleFunc("POST /api/auth/login", s.handleInteractiveLogin)

	mux.HandleFunc("GET /api/scans", s.handleListScans)
	mux.HandleFunc("POST /api/scans", s.handleCreateScan)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	mux.HandleFunc("GET /api/scans/{id}/stats", s.handleScanStats)
	mux.HandleFunc("GET /api/scans/{id}/status", s.handleScanStatus)
	mux.HandleFunc("GET /api/scans/{id}/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/scans/{id}/findings/{fid}", s.handleGetFinding)
	mux.HandleFunc("GET /api/scans/{id}/reports", s.handleListReports)
	mux.HandleFunc("POST /api/scans/{id}/reports", s.handleCreateReport)
	// A specific pattern takes precedence over {action}, so runtime reconfigure
	// has its own route rather than going through handleScanAction.
	mux.HandleFunc("POST /api/scans/{id}/config", s.handleReconfigureScan)
	mux.HandleFunc("POST /api/scans/{id}/{action}", s.handleScanAction)

	mux.HandleFunc("GET /api/evidence/{id}", s.handleGetEvidence)
	mux.HandleFunc("GET /api/evidence/{id}/content", s.handleGetEvidenceContent)
	mux.HandleFunc("GET /api/reports/{id}", s.handleGetReport)
	mux.HandleFunc("GET /api/reports/{id}/content", s.handleGetReportContent)

	// Static UI.
	sub, _ := fs.Sub(assetsFS, "assets")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	return s.withLogging(s.guard(mux))
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version, "name": "indago"})
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.store.Projects().List(r.Context())
	if err != nil {
		s.writeInternalError(w, "list projects", err)
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

type createProjectReq struct {
	Name  string `json:"name"`
	Notes string `json:"notes"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectReq
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	now := time.Now()
	p := &domain.Project{ID: domain.NewID(), Name: req.Name, Notes: req.Notes, CreatedAt: now, UpdatedAt: now}
	if err := s.store.Projects().Create(r.Context(), p); err != nil {
		s.writeInternalError(w, "create project", err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.Projects().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.Scans().List(r.Context())
	if err != nil {
		s.writeInternalError(w, "list scans", err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	sc, err := s.store.Scans().Get(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) handleScanStats(w http.ResponseWriter, r *http.Request) {
	id := domain.ID(r.PathValue("id"))
	if _, err := s.store.Scans().Get(r.Context(), id); err != nil {
		s.writeLookupError(w, err)
		return
	}
	stats, err := s.ctrl.Stats(r.Context(), id)
	if err != nil {
		s.writeInternalError(w, "scan stats", err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// --- helpers ---

func (s *Server) writeLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.writeInternalError(w, "lookup", err)
}

// writeInternalError logs the real error server-side — which may include
// internal detail (a file path, a raw DB error) not meant for an API
// caller — and returns a generic message instead of err.Error() itself.
func (s *Server) writeInternalError(w http.ResponseWriter, context string, err error) {
	s.log.Error(context, "err", err)
	writeError(w, http.StatusInternalServerError, context+" failed")
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ListenAndServe starts the HTTP server and blocks until ctx is canceled, then
// shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	s.allowedHosts = hostsForListenAddr(addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("web server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

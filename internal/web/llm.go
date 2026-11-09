package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/indago/indago/internal/llm"
)

// llmStore is the subset of *llm.Store these handlers need. Keeping it an
// interface defined in this package means server.go needs no import of
// internal/llm just to declare the field, and a Server built without a store
// (most tests, embedding) degrades cleanly instead of panicking.
type llmStore interface {
	Load() (llm.Config, error)
	Set(llm.SetRequest) (llm.Config, error)
	Clear() error
}

// SetLLMStore wires the LLM provider settings store. cmd/indago calls it once
// with a store rooted in the data directory; not calling it leaves the
// /api/llm/* routes reporting that settings are unavailable.
func (s *Server) SetLLMStore(st *llm.Store) { s.llm = st; s.llmRegistry = llm.NewRegistry(st) }

// requireLLMStore answers the request itself when no store is configured and
// reports whether the handler may continue.
func (s *Server) requireLLMStore(w http.ResponseWriter) bool {
	// The config view is small and contains a masked hint; never let a shared
	// cache retain it.
	w.Header().Set("Cache-Control", "no-store")
	if s.llm == nil {
		writeError(w, http.StatusServiceUnavailable, "LLM settings are not available on this server")
		return false
	}
	return true
}

// handleGetLLMConfig returns the non-secret view of the stored configuration.
//
// It reads a local file only: it never contacts the configured provider, so
// opening the settings screen cannot leak the fact of a scan or probe to a
// third party. The response contains a masked key hint, never the key.
func (s *Server) handleGetLLMConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireLLMStore(w) {
		return
	}
	cfg, err := s.llm.Load()
	switch {
	case errors.Is(err, llm.ErrNotConfigured):
		writeJSON(w, http.StatusOK, llm.Config{}.Status())
	case err != nil:
		s.writeInternalError(w, "read LLM settings", err)
	default:
		writeJSON(w, http.StatusOK, cfg.Status())
	}
}

// handlePutLLMConfig creates or updates the configuration. An empty api_key
// keeps the stored key, so the UI never has to round-trip a secret through the
// browser to change the model. Validation errors are 400s and contain no
// submitted value; storage errors are 500s with a generic message.
func (s *Server) handlePutLLMConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireLLMStore(w) {
		return
	}
	var req llm.SetRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	cfg, err := s.llm.Set(req)
	if err != nil {
		if errors.Is(err, llm.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeInternalError(w, "save LLM settings", err)
		return
	}
	// Audit line: provider and model only. No key, no masked hint, no base URL
	// (a base URL can name a private gateway).
	s.log.Info("LLM provider configured", "provider", cfg.Provider, "model", cfg.Model, "key_set", cfg.HasKey())
	writeJSON(w, http.StatusOK, cfg.Status())
}

// handleDeleteLLMConfig clears both the stored settings and the stored key.
func (s *Server) handleDeleteLLMConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireLLMStore(w) {
		return
	}
	if err := s.llm.Clear(); err != nil {
		s.writeInternalError(w, "clear LLM settings", err)
		return
	}
	s.log.Info("LLM provider configuration cleared")
	writeJSON(w, http.StatusOK, llm.Config{}.Status())
}

// handleTestLLM performs the same single bounded probe as
// `indago config llm test`. A provider failure is a valid probe outcome, so it
// is a 200 with ok=false and a redacted error; only an unconfigured or
// unreadable local configuration is an HTTP error.
//
// The response and the log line both pass through cfg.Redact: an upstream
// "401 invalid key sk-..." must not leave this handler intact. The key itself
// is never part of the result type.
func (s *Server) handleTestLLM(w http.ResponseWriter, r *http.Request) {
	if !s.requireLLMStore(w) {
		return
	}
	cfg, err := s.llm.Load()
	if errors.Is(err, llm.ErrNotConfigured) {
		writeError(w, http.StatusBadRequest, "LLM provider is not configured")
		return
	}
	if err != nil {
		s.writeInternalError(w, "read LLM settings", err)
		return
	}

	// ?provider= probes that provider instead of the stored one, using the
	// same resolution a scan/report call would use (settings or env, and the
	// ChatGPT OAuth session).
	prober := llm.NewProber(0)
	var res llm.ProbeResult
	if provider := strings.TrimSpace(r.URL.Query().Get("provider")); provider != "" {
		if s.llmRegistry == nil {
			writeError(w, http.StatusServiceUnavailable, "LLM settings are not available on this server")
			return
		}
		cred, err := s.llmRegistry.Resolve(provider, "")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if cred.Provider == llm.ProviderChatGPT {
			res = prober.ProbeChatGPT(r.Context())
		} else {
			res = prober.Test(r.Context(), cred.Config())
		}
		res.Error = cred.Redact(res.Error)
	} else {
		res = prober.Test(r.Context(), cfg)
		res.Error = cfg.Redact(res.Error) // defense in depth at the HTTP boundary
	}
	if res.OK {
		s.log.Info("LLM connection test succeeded",
			"provider", res.Provider, "model", res.Model, "latency_ms", res.LatencyMS)
	} else {
		s.log.Warn("LLM connection test failed",
			"provider", res.Provider, "model", res.Model, "latency_ms", res.LatencyMS, "err", res.Error)
	}
	writeJSON(w, http.StatusOK, res)
}

// handleListLLMModels asks the provider for its model list (one bounded GET,
// only when the operator explicitly asks). A provider that does not implement
// /models degrades to an empty list plus a redacted message: the model field
// stays free text, which is the primary input either way.
func (s *Server) handleListLLMModels(w http.ResponseWriter, r *http.Request) {
	if !s.requireLLMStore(w) {
		return
	}
	cfg, err := s.llm.Load()
	if errors.Is(err, llm.ErrNotConfigured) {
		writeError(w, http.StatusBadRequest, "LLM provider is not configured")
		return
	}
	if err != nil {
		s.writeInternalError(w, "read LLM settings", err)
		return
	}

	models, err := llm.NewProber(0).Models(r.Context(), cfg)
	if err != nil {
		msg := cfg.Redact(err.Error())
		s.log.Info("LLM model list unavailable", "provider", cfg.Provider, "err", msg)
		writeJSON(w, http.StatusOK, map[string]any{"models": []string{}, "error": msg})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

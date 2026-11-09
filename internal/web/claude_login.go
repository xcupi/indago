package web

// Claude OAuth endpoints. Same shape as the ChatGPT device flow: the operator
// authorizes in their own browser, Indago stores the tokens 0600 and refreshes
// them on demand. No password and no API key pass through Indago.

import (
	"net/http"
	"time"
)

type claudeLoginStartResp struct {
	URL   string `json:"url"`
	State string `json:"state"`
}

func (s *Server) handleClaudeLoginStart(w http.ResponseWriter, r *http.Request) {
	if s.claudeLogin == nil {
		writeError(w, http.StatusServiceUnavailable, "Claude OAuth is not configured on this server")
		return
	}
	url, state, err := s.claudeLogin.Start()
	if err != nil {
		s.writeInternalError(w, "start Claude login", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, claudeLoginStartResp{URL: url, State: state})
}

func (s *Server) handleClaudeLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.claudeLogin == nil {
		writeError(w, http.StatusServiceUnavailable, "Claude OAuth is not configured on this server")
		return
	}
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	cred, err := s.claudeLogin.Finish(r.Context(), req.Code, req.State)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("Claude OAuth connected", "expires_at", cred.ExpiresAt.UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]any{
		"connected": true, "expires_at": cred.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleClaudeSession(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"connected": false}
	if s.claudeStore != nil {
		if c, err := s.claudeStore.Load(); err == nil && c.AccessToken != "" {
			out["connected"] = true
			out["expires_at"] = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleClaudeLogout(w http.ResponseWriter, r *http.Request) {
	if s.claudeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Claude OAuth is not configured on this server")
		return
	}
	if err := s.claudeStore.Clear(); err != nil {
		s.writeInternalError(w, "clear Claude session", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": false})
}

// claudeOAuthToken returns a valid token or "" when the flow is not connected.
func (s *Server) claudeOAuthToken(r *http.Request) (string, error) {
	if s.claudeLogin == nil {
		return "", nil
	}
	tok, err := s.claudeLogin.Token(r.Context())
	if err != nil {
		return "", err
	}
	return tok, nil
}

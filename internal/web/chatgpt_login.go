package web

// ChatGPT OAuth device-code login for Indago's own session, exposed over the
// local API so both the Settings screen and a script can use it.
//
// Flow: POST /login returns a user code and URL; the operator enters the code
// at the OpenAI page; POST /login/poll is called until it answers done, at which
// point the tokens are stored under s.chatgptDir (0600). Nothing here touches
// the Hermes auth store.

import (
	"net/http"
	"sync"
	"time"

	"github.com/indago/indago/internal/chatgpt"
)

// pendingLogins holds in-flight device codes. They are short-lived and local;
// one entry per login attempt, pruned on every start.
type pendingLogins struct {
	mu   sync.Mutex
	byID map[string]chatgpt.DeviceAuth
}

func (p *pendingLogins) put(d chatgpt.DeviceAuth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byID == nil {
		p.byID = map[string]chatgpt.DeviceAuth{}
	}
	now := time.Now()
	for id, v := range p.byID {
		if now.After(v.ExpiresAt) {
			delete(p.byID, id)
		}
	}
	p.byID[d.DeviceAuthID] = d
}

func (p *pendingLogins) get(id string) (chatgpt.DeviceAuth, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.byID[id]
	return d, ok
}

func (p *pendingLogins) drop(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byID, id)
}

func (s *Server) requireChatGPTStore(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	if s.chatgptDir == "" {
		writeError(w, http.StatusServiceUnavailable, "ChatGPT login is not available on this server")
		return false
	}
	return true
}

// handleChatGPTStatus reports which session would be used, without a token.
func (s *Server) handleChatGPTStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	out := map[string]any{"logged_in": false, "source": "none"}
	if s.chatgptDir != "" {
		if c, err := chatgpt.NewStore(s.chatgptDir).Load(); err == nil {
			out["logged_in"] = true
			out["source"] = "indago"
			out["account"] = maskAccount(c.AccountID)
			out["plan"] = c.Plan
			out["expires_at"] = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	if out["source"] == "none" {
		if c, err := chatgpt.Load(""); err == nil {
			out["logged_in"] = true
			out["source"] = "hermes"
			out["account"] = maskAccount(c.AccountID)
			out["plan"] = c.Plan
			out["expires_at"] = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleChatGPTLoginStart requests a device code.
func (s *Server) handleChatGPTLoginStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireChatGPTStore(w) {
		return
	}
	d, err := chatgpt.StartLogin(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.pendingLogins.put(*d)
	s.log.Info("chatgpt login started", "expires", d.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, d)
}

// handleChatGPTLoginPoll checks once. done=true means the credential was stored.
func (s *Server) handleChatGPTLoginPoll(w http.ResponseWriter, r *http.Request) {
	if !s.requireChatGPTStore(w) {
		return
	}
	var req struct {
		DeviceAuthID string `json:"device_auth_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	d, ok := s.pendingLogins.get(req.DeviceAuthID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown or expired login attempt; start again")
		return
	}
	cred, done, err := chatgpt.PollOnce(r.Context(), d)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !done {
		writeJSON(w, http.StatusOK, map[string]any{"state": "pending"})
		return
	}
	if err := chatgpt.NewStore(s.chatgptDir).Save(*cred); err != nil {
		s.writeInternalError(w, "store ChatGPT session", err)
		return
	}
	s.pendingLogins.drop(req.DeviceAuthID)
	s.log.Info("chatgpt login completed", "account", maskAccount(cred.AccountID), "plan", cred.Plan)
	writeJSON(w, http.StatusOK, map[string]any{
		"state": "done", "account": maskAccount(cred.AccountID), "plan": cred.Plan,
		"expires_at": cred.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleChatGPTLogout removes Indago's own session (never the Hermes one).
func (s *Server) handleChatGPTLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireChatGPTStore(w) {
		return
	}
	if err := chatgpt.NewStore(s.chatgptDir).Clear(); err != nil {
		s.writeInternalError(w, "clear ChatGPT session", err)
		return
	}
	s.log.Info("chatgpt session cleared")
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func maskAccount(id string) string {
	if len(id) <= 6 {
		return "***"
	}
	return id[:4] + "…" + id[len(id)-2:]
}

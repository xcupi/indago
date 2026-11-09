package web

// Bug-bounty integration endpoints.
//
// Design constraints, in order of importance:
//
//  1. No credential ever comes back out. The token is written once, stored
//     0600, and the API only ever reports configured true/false.
//  2. Program browsing is an explicit action. The UI has a "Load" button and
//     the client caches for ten minutes; a page that re-renders must not turn
//     into repeated platform calls.
//  3. Import is scope-first. A program becomes a project whose scope is the
//     program's own web-application assets; out-of-scope hosts never reach a
//     scan because the normal scope enforcement rejects them, not because the
//     importer remembered to filter.
//  4. The platform is a source of truth for the scope, not for the verdict:
//     nothing here confirms, scores or reports a finding.

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
)

// SetBountyStore wires the token store and its client. INDAGO_YESWEHACK_API
// overrides the API base (mirror or test server).
func (s *Server) SetBountyStore(st *bounty.Store) {
	s.bountyStore = st
	s.bountyClient = bounty.NewClient(os.Getenv("INDAGO_YESWEHACK_API"), st.Token)
}

type bountyProvider struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Configured   bool   `json:"configured"`
	PublicBrowse bool   `json:"public_browse"`
	Note         string `json:"note"`
}

func (s *Server) handleListBountyProviders(w http.ResponseWriter, r *http.Request) {
	configured := s.bountyStore != nil && s.bountyStore.Configured()
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": []bountyProvider{{
			ID: "yeswehack", Label: "YesWeHack", Configured: configured, PublicBrowse: true,
			Note: "Browsing programs works without a token; importing a program's scope needs a personal access token (X-AUTH-TOKEN).",
		}},
	})
}

type setBountyTokenReq struct {
	Token string `json:"token"`
}

// handleSetBountyToken validates the token against the API before storing it,
// so "saved" always means "the platform accepted it".
func (s *Server) handleSetBountyToken(w http.ResponseWriter, r *http.Request) {
	if s.bountyStore == nil || s.bountyClient == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	var req setBountyTokenReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	// Validate: a scopes call is the cheapest endpoint that requires auth.
	probe := bounty.NewClient(s.bountyClient.BaseURL, func() string { return token })
	if _, err := probe.Scopes(r.Context(), "nonexistent-program-for-auth-probe"); err != nil {
		if errors.Is(err, bounty.ErrUnauthorized) {
			writeError(w, http.StatusBadRequest, "YesWeHack rejected the token (401). Check that it is a personal access token.")
			return
		}
		// A 404 means the token was accepted and the program simply does not
		// exist — that is a successful authentication.
		if !strings.Contains(err.Error(), "404") {
			writeError(w, http.StatusBadGateway, "could not verify the token: "+err.Error())
			return
		}
	}
	if err := s.bountyStore.Set(token); err != nil {
		s.writeInternalError(w, "store bounty token", err)
		return
	}
	s.log.Info("bounty token configured", "provider", "yeswehack")
	writeJSON(w, http.StatusOK, map[string]any{"configured": true})
}

func (s *Server) handleClearBountyToken(w http.ResponseWriter, r *http.Request) {
	if s.bountyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	if err := s.bountyStore.Clear(); err != nil {
		s.writeInternalError(w, "clear bounty token", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": false})
}

// handleBountyPrograms lists programs. refresh=1 bypasses the ten-minute
// cache; without it the cached page is served, which is what the Load button's
// normal path uses.
func (s *Server) handleBountyPrograms(w http.ResponseWriter, r *http.Request) {
	if s.bountyClient == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	q := bounty.Query{
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		ScopeTypes: splitCSV(r.URL.Query().Get("scope_type")),
		Types:      splitCSV(r.URL.Query().Get("type")),
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	items, cached, err := s.bountyClient.ListPrograms(r.Context(), q, refresh)
	if err != nil {
		writeError(w, http.StatusBadGateway, "listing programs failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": "yeswehack", "items": items, "cached": cached, "count": len(items),
		"fetched_at": time.Now().Format(time.RFC3339),
	})
}

// handleBountyProgram returns one program with its rules and — when a token is
// configured — its scopes and report templates.
func (s *Server) handleBountyProgram(w http.ResponseWriter, r *http.Request) {
	if s.bountyClient == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	slug := r.PathValue("slug")
	detail, err := s.bountyClient.Detail(r.Context(), slug)
	if err != nil {
		writeError(w, http.StatusBadGateway, "loading program failed: "+err.Error())
		return
	}
	resp := map[string]any{"program": detail, "scopes": []bounty.Scope{}, "templates": []bounty.ReportTemplate{}}
	if s.bountyStore != nil && s.bountyStore.Configured() {
		if scopes, err := s.bountyClient.Scopes(r.Context(), slug); err == nil {
			resp["scopes"] = scopes
		} else {
			resp["scopes_error"] = err.Error()
		}
		if tpl, err := s.bountyClient.ReportTemplates(r.Context(), slug); err == nil {
			resp["templates"] = tpl
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type importProgramsReq struct {
	Slugs []string `json:"slugs"`
}

type importedProgram struct {
	Slug      string   `json:"slug"`
	Title     string   `json:"title"`
	ProjectID string   `json:"project_id"`
	Targets   []string `json:"targets"`
	Hosts     []string `json:"hosts"`
	Skipped   []string `json:"skipped,omitempty"`
}

// handleImportBountyPrograms turns selected programs into projects with an
// explicit scope. It never creates a scan: the operator checks the targets they
// want tested, and the existing scan form (with its rate/profile controls)
// stays the place where a test is started.
func (s *Server) handleImportBountyPrograms(w http.ResponseWriter, r *http.Request) {
	if s.bountyClient == nil || s.bountyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	if !s.bountyStore.Configured() {
		writeError(w, http.StatusBadRequest, "importing needs a YesWeHack personal access token: scopes are only available to authenticated hunters")
		return
	}
	var req importProgramsReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	if len(req.Slugs) == 0 {
		writeError(w, http.StatusBadRequest, "pick at least one program")
		return
	}

	var out []importedProgram
	for _, slug := range req.Slugs {
		slug = strings.TrimSpace(slug)
		if slug == "" {
			continue
		}
		detail, err := s.bountyClient.Detail(r.Context(), slug)
		if err != nil {
			writeError(w, http.StatusBadGateway, "loading "+slug+" failed: "+err.Error())
			return
		}
		scopes, err := s.bountyClient.Scopes(r.Context(), slug)
		if err != nil {
			writeError(w, http.StatusBadGateway, "loading scopes for "+slug+" failed: "+err.Error())
			return
		}
		hosts, targets, skipped := webScopeTargets(scopes)
		if len(hosts) == 0 {
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, Skipped: []string{"no web-application scope asset"}})
			continue
		}
		now := time.Now()
		p := &domain.Project{ID: domain.NewID(), Name: detail.Title, Notes: "Imported from YesWeHack (" + slug + ")", CreatedAt: now, UpdatedAt: now}
		if err := s.store.Projects().Create(r.Context(), p); err != nil {
			s.writeInternalError(w, "create project", err)
			return
		}
		sc := &domain.Scope{
			ID: domain.NewID(), ProjectID: p.ID,
			IncludeHosts: hosts, AllowSubdomains: true,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := s.store.Scopes().Create(r.Context(), sc); err != nil {
			s.writeInternalError(w, "create scope", err)
			return
		}
		for _, raw := range targets {
			t := &domain.Target{ID: domain.NewID(), ProjectID: p.ID, Name: raw, BaseURL: raw, CreatedAt: now, UpdatedAt: now}
			if err := s.store.Targets().Create(r.Context(), t); err != nil {
				s.writeInternalError(w, "create target", err)
				return
			}
		}
		out = append(out, importedProgram{Slug: slug, Title: detail.Title, ProjectID: string(p.ID), Targets: targets, Hosts: hosts, Skipped: skipped})
		s.log.Info("bounty program imported", "provider", "yeswehack", "slug", slug, "hosts", len(hosts), "targets", len(targets))
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": out})
}

// webScopeTargets converts platform scopes into (hosts, seed targets, skipped).
// Only web-application assets become targets: an API host or a wildcard is a
// scope entry, not a seed URL the crawler can start from.
func webScopeTargets(scopes []bounty.Scope) (hosts, targets, skipped []string) {
	hostSeen := map[string]bool{}
	targetSeen := map[string]bool{}
	for _, sc := range scopes {
		if sc.ScopeType != "web-application" {
			skipped = append(skipped, sc.ScopeType+":"+sc.Scope)
			continue
		}
		raw := strings.TrimSpace(sc.AssetValue)
		if raw == "" {
			raw = strings.TrimSpace(sc.Scope)
		}
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "*.") {
			raw = strings.TrimPrefix(raw, "*.")
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			skipped = append(skipped, "unparseable:"+sc.Scope)
			continue
		}
		host := strings.ToLower(u.Hostname())
		if !hostSeen[host] {
			hostSeen[host] = true
			hosts = append(hosts, host)
		}
		// One seed per host root: the crawler discovers the rest.
		seed := u.Scheme + "://" + u.Host + "/"
		if !targetSeen[seed] {
			targetSeen[seed] = true
			targets = append(targets, seed)
		}
	}
	sort.Strings(hosts)
	sort.Strings(targets)
	return hosts, targets, skipped
}

func splitCSV(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

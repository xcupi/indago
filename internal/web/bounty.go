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
	if web := os.Getenv("INDAGO_YESWEHACK_WEB"); web != "" {
		s.bountyClient.WebBase = web
	}
}

type bountyProvider struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Configured   bool   `json:"configured"`
	PublicBrowse bool   `json:"public_browse"`
	Credential   string `json:"credential,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Note         string `json:"note"`
}

func (s *Server) handleListBountyProviders(w http.ResponseWriter, r *http.Request) {
	configured := s.bountyStore != nil && s.bountyStore.Configured()
	kind, expires := "", time.Time{}
	if configured {
		kind, expires = bounty.CredentialInfo(s.bountyStore.Token())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": []bountyProvider{{
			ID: "yeswehack", Label: "YesWeHack", Configured: configured, PublicBrowse: true,
			Credential: kind, ExpiresAt: expires.Format(time.RFC3339),
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
	// Validate against an endpoint every credential can read; 401 means the
	// credential is bad, anything else means it was accepted.
	if err := s.bountyClient.Validate(r.Context(), token); err != nil {
		if errors.Is(err, bounty.ErrUnauthorized) {
			writeError(w, http.StatusBadRequest, "YesWeHack rejected this credential (401). Paste the session token from a logged-in yeswehack.com tab, or a personal access token.")
			return
		}
		writeError(w, http.StatusBadGateway, "could not verify the credential: "+err.Error())
		return
	}
	if err := s.bountyStore.Set(token); err != nil {
		s.writeInternalError(w, "store bounty token", err)
		return
	}
	s.log.Info("bounty token configured", "provider", "yeswehack")
	kind, expires := bounty.CredentialInfo(token)
	out := map[string]any{"configured": true, "kind": kind}
	if !expires.IsZero() {
		out["expires_at"] = expires.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
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
		} else if scopes, err := s.bountyClient.PublicScopes(r.Context(), slug); err == nil {
			resp["scopes"] = scopes
		} else {
			resp["scopes_error"] = err.Error()
		}
		if tpl, err := s.bountyClient.ReportTemplates(r.Context(), slug); err == nil {
			resp["templates"] = tpl
		}
	} else if scopes, err := s.bountyClient.PublicScopes(r.Context(), slug); err == nil {
		// Without a credential, the program page still lists the scope table —
		// enough for a preview before importing.
		resp["scopes"] = scopes
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
		// Authenticated accounts read scopes from the API; hunter accounts
		// cannot create a token, so they fall back to the public program page,
		// which ships the same table in its transfer state.
		scopes, err := s.bountyClient.Scopes(r.Context(), slug)
		if err != nil {
			if !errors.Is(err, bounty.ErrNoToken) && !errors.Is(err, bounty.ErrUnauthorized) {
				writeError(w, http.StatusBadGateway, "loading scopes for "+slug+" failed: "+err.Error())
				return
			}
			scopes, err = s.bountyClient.PublicScopes(r.Context(), slug)
			if err != nil {
				writeError(w, http.StatusBadGateway, "loading public scopes for "+slug+" failed: "+err.Error())
				return
			}
		}
		// Importing the same program twice would create a second project with
		// the same scope; skip it and say so.
		existing, _ := s.store.Projects().List(r.Context())
		already := false
		for _, p := range existing {
			if strings.Contains(p.Notes, "YesWeHack ("+slug+")") {
				already = true
				break
			}
		}
		if already {
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, Skipped: []string{"already imported"}})
			continue
		}
		hosts, targets, prefixes, skipped := webScopeTargets(scopes)
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
			IncludeHosts: hosts, IncludePathPrefixes: prefixes,
			AllowSubdomains: true,
			CreatedAt:       now, UpdatedAt: now,
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
func webScopeTargets(scopes []bounty.Scope) (hosts, targets, prefixes, skipped []string) {
	hostSeen := map[string]bool{}
	targetSeen := map[string]bool{}
	prefixSeen := map[string]bool{}
	for _, sc := range scopes {
		if sc.ScopeType != "web-application" {
			skipped = append(skipped, sc.ScopeType+":"+sc.Scope)
			continue
		}
		// The API schema puts the asset in asset_value, but the public page's
		// transfer state puts the severity there and the asset in scope. Pick
		// the first field that actually looks like a host, and never accept a
		// severity word.
		raw := ""
		// API schema: asset_value is the asset (scope may be a wildcard).
		// Public page: asset_value is the severity, scope is the asset. Try the
		// asset field first and fall back to scope when it is not host-like.
		for _, cand := range []string{sc.AssetValue, sc.Scope} {
			if looksLikeHost(cand) {
				raw = strings.TrimSpace(cand)
				break
			}
		}
		if raw == "" {
			skipped = append(skipped, "no host in scope:"+sc.Scope)
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
		// A scope can be a specific path (…/challenge-of-the-month/dojo-56),
		// not just a host. Seed the asset itself and restrict the scope to its
		// path, otherwise the crawler would start at / and happily leave the
		// program's authorized area.
		seed := u.Scheme + "://" + u.Host + u.Path
		if u.Path == "" || u.Path == "/" {
			seed = u.Scheme + "://" + u.Host + "/"
		} else if !prefixSeen[u.Path] {
			prefixSeen[u.Path] = true
			prefixes = append(prefixes, u.Path)
		}
		if !targetSeen[seed] {
			targetSeen[seed] = true
			targets = append(targets, seed)
		}
	}
	sort.Strings(hosts)
	sort.Strings(targets)
	sort.Strings(prefixes)
	return hosts, targets, prefixes, skipped
}

// looksLikeHost rejects the severity words that occupy asset_value on the
// public page and accepts a URL or a bare domain.
func looksLikeHost(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " \t") {
		return false
	}
	switch strings.ToUpper(v) {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "NONE":
		return false
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		return err == nil && u.Hostname() != ""
	}
	return strings.Contains(v, ".") && !strings.HasPrefix(v, ".")
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

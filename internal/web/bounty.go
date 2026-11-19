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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/indago/indago/internal/bounty"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
	"github.com/indago/indago/internal/scan"
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
	Expired      bool   `json:"expired,omitempty"`
	Note         string `json:"note"`
}

func (s *Server) handleListBountyProviders(w http.ResponseWriter, r *http.Request) {
	configured := s.bountyStore != nil && s.bountyStore.Configured()
	kind, expires := "", time.Time{}
	if configured {
		kind, expires = bounty.CredentialInfo(s.bountyStore.Token())
	}
	p := bountyProvider{
		ID: "yeswehack", Label: "YesWeHack", Configured: configured, PublicBrowse: true,
		Credential: kind,
		Note:       "Hunter session token: copy localStorage.access_token from a logged-in yeswehack.com tab. It expires with that browser session. Managers can use a personal access token instead.",
	}
	if !expires.IsZero() {
		p.ExpiresAt = expires.Format(time.RFC3339)
		p.Expired = time.Now().After(expires)
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": []bountyProvider{p}})
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
	client := s.bountyClient
	if s.bountyStore != nil && s.bountyStore.Configured() {
		_, expires := bounty.CredentialInfo(s.bountyStore.Token())
		if !expires.IsZero() && time.Now().After(expires) {
			// Program browsing is public. An expired hunter session must not
			// turn that into a 401: show the public list and let the UI ask
			// for a replacement token for scopes/templates.
			client = bounty.NewClient(client.BaseURL, nil)
			client.WebBase = s.bountyClient.WebBase
		}
	}
	q := bounty.Query{
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		ScopeTypes: splitCSV(r.URL.Query().Get("scope_type")),
		Types:      splitCSV(r.URL.Query().Get("type")),
		Page:       atoiDefault(r.URL.Query().Get("page"), 1),
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	items, total, cached, err := client.ListPrograms(r.Context(), q, refresh)
	if err != nil {
		writeError(w, http.StatusBadGateway, "listing programs failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": "yeswehack", "items": items, "cached": cached, "count": len(items),
		"total": total, "page": q.Page, "per_page": 50,
		"has_more":   q.Page*50 < total,
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
	// SubdomainOnlyHosts lists the wildcard assets imported as "subdomains of
	// this host, not the host itself" (domain.Scope.SubdomainOnlyHosts). It is
	// reported separately from Hosts because the two authorize different
	// things: a wildcard asset never authorizes its own apex.
	SubdomainOnlyHosts []string `json:"subdomain_only_hosts,omitempty"`
	ScanID             string   `json:"scan_id,omitempty"`
	ScanIDs            []string `json:"scan_ids,omitempty"`
	ScanError          string   `json:"scan_error,omitempty"`
	UserAgent          string   `json:"hunting_user_agent,omitempty"`
	Skipped            []string `json:"skipped,omitempty"`
}

// handleImportBountyPrograms turns selected programs into projects with an
// explicit scope and one draft scan for the first target, using anonymous auth.
// The scan is created but not started: the operator reviews the target/scope,
// sets the program's hunting User-Agent when required, then starts it.
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
		existingProjectID := ""
		for _, p := range existing {
			if strings.Contains(p.Notes, "YesWeHack ("+slug+")") {
				already = true
				existingProjectID = string(p.ID)
				break
			}
		}
		if already {
			// A repeated import is not an error: keep one project per program
			// and point the operator at the existing one instead.
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, ProjectID: existingProjectID, Skipped: []string{"already imported"}})
			continue
		}
		hosts, subdomainOnly, targets, prefixes, origins, skipped, blocked := webScopeTargets(scopes)
		if blocked != "" {
			// Fail closed: the program binds different paths to different
			// hosts/origins, and a project scope has one global prefix list.
			// Nothing is created rather than a scope that authorizes the
			// cross product of host, scheme/port and path.
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, Skipped: append(skipped, blocked)})
			continue
		}
		if len(hosts) == 0 && len(subdomainOnly) == 0 {
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, Skipped: append(skipped, "no web-application scope asset")})
			continue
		}
		// Fail closed: an empty origin list means "every scheme and port" to
		// the matcher, so an import never creates a scope without one. Every
		// kept asset row states its own scheme, so this only fires if the
		// asset parsing above let a host through without an origin.
		if len(origins) == 0 {
			out = append(out, importedProgram{Slug: slug, Title: detail.Title, Skipped: append(skipped, "no asset states an http(s) scheme; an imported scope never authorizes every scheme and port")})
			continue
		}
		now := time.Now()
		p := &domain.Project{ID: domain.NewID(), Name: detail.Title, Notes: "Imported from YesWeHack (" + slug + ")", CreatedAt: now, UpdatedAt: now}
		// Some programs put the hunting User-Agent only in the public page's
		// "User agent" section (the API rules field is often abbreviated).
		// Best effort: a failed lookup must not fail the import.
		ruleText := strings.ToLower(detail.Rules + " " + detail.RulesHTML)
		if strings.Contains(ruleText, "user-agent") || strings.Contains(ruleText, "user agent") || strings.Contains(ruleText, "hunting requirement") {
			if ua, replace, err := s.bountyClient.PublicHuntingUserAgent(r.Context(), slug); err == nil && ua != "" {
				p.HuntingUserAgent = ua
				p.HuntingUserAgentReplace = replace
				s.log.Info("bounty hunting user-agent imported", "slug", slug, "value", ua, "replace", replace)
			} else if err != nil {
				s.log.Warn("bounty hunting user-agent lookup failed", "slug", slug, "error", err)
			}
		}
		if err := s.store.Projects().Create(r.Context(), p); err != nil {
			s.writeInternalError(w, "create project", err)
			return
		}
		sc := &domain.Scope{
			ID: domain.NewID(), ProjectID: p.ID,
			IncludeHosts:        hosts,
			SubdomainOnlyHosts:  subdomainOnly,
			IncludePathPrefixes: prefixes,
			// The program's assets state scheme and port, so the imported
			// scope is origin-restricted from the first scan: a host listed as
			// https://app.example.com does not authorize http, nor :8443, nor
			// an internal service on another port. This is the fail-closed
			// default for a new (imported) scope.
			AllowedOrigins: origins,
			// Imports never widen. Every asset row is either an exact host or
			// an explicit wildcard ("*.example.com"), and the wildcard is
			// carried by SubdomainOnlyHosts, so the blanket "subdomains of
			// every included host" flag stays off: an exact asset must not
			// authorize hosts the program never listed.
			AllowSubdomains: false,
			CreatedAt:       now, UpdatedAt: now,
		}
		if err := s.store.Scopes().Create(r.Context(), sc); err != nil {
			s.writeInternalError(w, "create scope", err)
			return
		}
		var targetIDs []domain.ID
		targetURLs := map[domain.ID]string{}
		for _, raw := range targets {
			t := &domain.Target{ID: domain.NewID(), ProjectID: p.ID, Name: raw, BaseURL: raw, CreatedAt: now, UpdatedAt: now}
			if err := s.store.Targets().Create(r.Context(), t); err != nil {
				s.writeInternalError(w, "create target", err)
				return
			}
			// Keep every seed the imported scope actually permits. Some
			// programs scope only a path prefix, so a host-root target can be
			// out of scope and would make CreateScan fail.
			if sc.Permits(t.BaseURL).Allowed {
				targetIDs = append(targetIDs, t.ID)
				targetURLs[t.ID] = t.BaseURL
			}
		}
		var scanIDs []string
		var scanErr string
		if len(targetIDs) == 0 && len(targets) > 0 {
			scanErr = "no imported target is permitted by the program scope"
		}
		if s.ctrl != nil {
			for _, targetID := range targetIDs {
				created, err := s.ctrl.CreateScan(r.Context(), scan.CreateScanParams{
					ProjectID: p.ID,
					TargetID:  targetID,
					Name:      "Imported: " + detail.Title + " — " + targetURLs[targetID],
					// Conservative, not balanced: the operator did not choose
					// this program's rate, and docs/bounty.md promises the
					// quiet preset. The crawl controls are explicit so the
					// imported scan does not look like an empty 0/0 job and
					// can discover something without tuning.
					Profile:          domain.ProfileConservative,
					QuickScan:        false,
					MaxDepth:         3,
					MaxPages:         200,
					MaxEndpoints:     500,
					CandidateProfile: "standard",
					MaxCandidates:    8,
					// A WAF-fronted program otherwise spends its budget on
					// header/cookie reflections before testing the pages'
					// own parameters; imports start with the quieter,
					// query/form-first plan and can be tuned later.
					SkipGlobalInjection:   true,
					SkipStaticAssets:      true,
					SkipWriteEndpoints:    true,
					SkipDownloadEndpoints: true,
					MaxDOMXSSEndpoints:    25,
					AuthMode:              domain.AuthAnonymous,
				})
				if err != nil {
					scanErr = err.Error()
					s.log.Warn("bounty import: draft scan not created", "slug", slug, "target", targetID, "error", err)
					continue
				}
				scanIDs = append(scanIDs, string(created.ID))
			}
		}
		scanID := ""
		if len(scanIDs) > 0 {
			scanID = scanIDs[0]
		}
		out = append(out, importedProgram{Slug: slug, Title: detail.Title, ProjectID: string(p.ID), Targets: targets, Hosts: hosts, SubdomainOnlyHosts: subdomainOnly, ScanID: scanID, ScanIDs: scanIDs, ScanError: scanErr, UserAgent: p.HuntingUserAgent, Skipped: skipped})
		s.log.Info("bounty program imported", "provider", "yeswehack", "slug", slug, "hosts", len(hosts), "targets", len(targets))
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": out})
}

// bountyAsset is one concrete host an asset row points at.
type bountyAsset struct {
	Scheme string
	Host   string
	Port   int    // effective port (80/443 when the asset row omitted one)
	Path   string // "" when the asset has no path (its host root)
}

// origin is the scope-origin spelling of this asset: scheme, host and port.
func (a bountyAsset) origin() string {
	return domain.ScopeOrigin{Scheme: a.Scheme, Host: a.Host, Port: a.Port}.String()
}

// targetURL is the seed URL for this asset: the asset itself when it carries a
// path, otherwise the host root.
func (a bountyAsset) targetURL() string {
	host := a.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	base := a.Scheme + "://" + host
	if a.Port != 0 && a.Port != defaultPortForScheme(a.Scheme) {
		base += ":" + strconv.Itoa(a.Port)
	}
	if a.Path == "" || a.Path == "/" {
		return base + "/"
	}
	return base + a.Path
}

func defaultPortForScheme(scheme string) int {
	if strings.EqualFold(scheme, "http") {
		return 80
	}
	return 443
}

// importedPathIsSafe reports whether an asset's path can be stored as a scope
// prefix. An empty path and "/" mean the host root and need no prefix. Every
// other path must pass the same save-time validator a manual scope PUT uses;
// import never stores a path whose decoding or segment boundary is ambiguous.
func importedPathIsSafe(path string) bool {
	if path == "" || path == "/" {
		return true
	}
	return domain.ValidateScopePathPrefix(path) == nil
}

// importedAssetURLPathSafe checks the raw asset URL before its path is decoded
// into a scope prefix. It is what catches an encoded slash or dot that would
// look harmless after url.Parse: the decoded prefix is not the URL the program
// actually declared, so the asset is skipped.
func importedAssetURLPathSafe(raw string) bool {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		return true // wildcardAsset/concreteAsset handle the missing-scheme case.
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return true // let the existing shape checks report the malformed asset.
	}
	_, err = domain.SafeScopePath(u)
	return err == nil
}

// scopePathBinding is one authorization an imported asset row states: the
// origin it was declared for and the path prefix the program scoped it to
// (empty means the whole origin).
//
// It exists because domain.Scope.IncludePathPrefixes is GLOBAL: Scope.Permits
// compares a URL's path against every stored prefix without looking at the
// host, so two path-scoped assets on different origins would otherwise
// authorize the cross product — assets https://a.test/app and
// https://b.test/api would also permit https://a.test/api and
// https://b.test/app.
type scopePathBinding struct {
	Origin string // canonical scope-origin spelling, wildcard included
	Path   string // "" = the whole origin
}

// reduceScopePathPrefixes returns the minimal spelling of a set of path
// prefixes, comparing them exactly the way Scope.Permits does (through
// domain.ScopePathWithinPrefix: "/app" covers "/app" and "/app/x", not
// "/application"). An empty or "/" entry means the whole origin and collapses
// the set to "no restriction".
//
// The result is sorted, so the same input always produces the same list (and
// two origins can be compared with slices.Equal).
func reduceScopePathPrefixes(paths []string) []string {
	for _, p := range paths {
		if p == "" || p == "/" {
			return nil
		}
	}
	sorted := append([]string(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) < len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})
	out := make([]string, 0, len(sorted))
	for _, p := range sorted {
		covered := false
		for _, kept := range out {
			if domain.ScopePathWithinPrefix(p, kept) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// normalizeScopePathBindings drops a path restriction that another binding
// already authorizes more broadly. The one such case is an exact asset under a
// wildcard the program left UNRESTRICTED: the wildcard authorizes every path of
// that subdomain, so its own "/app" restriction adds nothing and keeping it
// would narrow the wildcard's scope. Everything else is left untouched — a
// restriction is only ever dropped when the same program states the wider
// authorization explicitly.
func normalizeScopePathBindings(bindings []scopePathBinding) []scopePathBinding {
	out := make([]scopePathBinding, len(bindings))
	copy(out, bindings)
	for i, b := range out {
		if b.Path == "" {
			continue
		}
		exact, ok := domain.ParseScopeOrigin(b.Origin)
		if !ok || exact.Wildcard {
			continue
		}
		for _, other := range out {
			if other.Path != "" {
				continue
			}
			wild, ok := domain.ParseScopeOrigin(other.Origin)
			if !ok || !wild.Wildcard {
				continue
			}
			if wild.Scheme == exact.Scheme && wild.Port == exact.Port && domain.IsStrictSubdomain(exact.Host, wild.Host) {
				out[i].Path = ""
				break
			}
		}
	}
	return out
}

// scopePathBindingProblem reports why the collected bindings cannot be
// expressed by the scope's one global prefix list without widening it, or ""
// when they can.
//
// The representation is faithful only when every imported origin authorizes the
// SAME set of path prefixes, because the stored list applies to all of them at
// once. An origin the program left unrestricted authorizes every path, so it
// only matches a program in which no origin is path-scoped. Anything else is
// refused instead of being flattened into a scope that authorizes combinations
// of host, scheme/port and path the program never listed.
func scopePathBindingProblem(bindings []scopePathBinding) string {
	if len(bindings) == 0 {
		return ""
	}
	byOrigin := map[string][]string{}
	var order []string
	for _, b := range bindings {
		if _, seen := byOrigin[b.Origin]; !seen {
			order = append(order, b.Origin)
		}
		byOrigin[b.Origin] = append(byOrigin[b.Origin], b.Path)
	}
	sort.Strings(order)

	reduced := make(map[string][]string, len(order))
	for _, origin := range order {
		reduced[origin] = reduceScopePathPrefixes(byOrigin[origin])
	}
	want := reduced[order[0]]
	for _, origin := range order[1:] {
		if !slices.Equal(reduced[origin], want) {
			describe := func(prefixes []string) string {
				if len(prefixes) == 0 {
					return "the whole origin"
				}
				return strings.Join(prefixes, " ")
			}
			parts := make([]string, 0, len(order))
			for _, o := range order {
				parts = append(parts, o+" is scoped to "+describe(reduced[o]))
			}
			return "path prefixes in a project scope apply to every host in it, so this program's assets cannot be imported without authorizing paths it never listed (" +
				strings.Join(parts, "; ") +
				"). Import one path-scoped asset per project, or declare the project scope manually"
		}
	}
	return ""
}

// webScopeTargets converts platform scopes into the project scope's lists plus
// the seed targets the program actually authorizes.
//
// The two authorization shapes are deliberately kept apart (AGENTS.md §2.1):
//
//   - an EXACT asset ("https://www.example.com") authorizes that host and
//     nothing below it, so it goes into hosts and NOT into subdomainOnly. An
//     exact asset does not authorize a subdomain the program never listed;
//   - a WILDCARD asset ("*.example.com") authorizes subdomains of example.com
//     and NOT example.com itself, so its parent goes into subdomainOnly. The
//     apex is never added, and a row whose concrete asset is the apex (or a
//     host outside the wildcard) is reported in skipped instead of widened.
//
// A wildcard row's concrete asset, when it is a strict subdomain of that
// wildcard, is already authorized by the wildcard. It is kept as an exact host
// and a seed target so the operator gets something to run and the UI's
// include-host list is not empty — that entry only repeats authority the
// wildcard already granted.
//
// Path prefixes are validated before being carried through: an asset whose
// path cannot be a canonical scope prefix (encoded traversal, backslash,
// duplicate slash, path parameter, or percent escape) is skipped rather than
// stored, because dropping only its prefix would widen the host to its root.
// The other hosts in the same program are unaffected.
//
// Paths are also HOST-BOUND in the source but GLOBAL in a project scope, so the
// importer checks that every imported origin authorizes the same prefixes
// before it returns a plan (scopePathBindingProblem). A program that scopes
// different paths to different hosts/origins cannot be represented faithfully;
// it is refused with a reason (blocked non-empty, nothing imported) rather than
// flattened into a scope that authorizes the cross product.
//
// The scheme is never inferred. A row that states http(s) contributes exactly
// the origin it names; a row that does not (a bare host, or a wildcard with no
// scheme) is reported in skipped instead of being read as https, because
// guessing would authorize an origin the program never stated. A wildcard
// spelling is always decided as a wildcard, so an unusable one can never be
// downgraded to its asset_value host by falling through.
func webScopeTargets(scopes []bounty.Scope) (hosts, subdomainOnly, targets, prefixes, origins, skipped []string, blocked string) {
	hostSeen := map[string]bool{}
	subSeen := map[string]bool{}
	targetSeen := map[string]bool{}
	prefixSeen := map[string]bool{}
	originSeen := map[string]bool{}
	// bindings records, per imported origin, the path the source scoped it to.
	var bindings []scopePathBinding
	addHost := func(host string) {
		if host == "" || hostSeen[host] {
			return
		}
		hostSeen[host] = true
		hosts = append(hosts, host)
	}
	addSubdomainOnly := func(host string) {
		if host == "" || subSeen[host] {
			return
		}
		subSeen[host] = true
		subdomainOnly = append(subdomainOnly, host)
	}
	addPrefix := func(path string) bool {
		if path == "" || path == "/" {
			return true
		}
		if !importedPathIsSafe(path) {
			return false
		}
		if prefixSeen[path] {
			return true
		}
		prefixSeen[path] = true
		prefixes = append(prefixes, path)
		return true
	}
	addTarget := func(raw string) {
		if raw == "" || targetSeen[raw] {
			return
		}
		targetSeen[raw] = true
		targets = append(targets, raw)
	}
	addOrigin := func(origin string) {
		if origin == "" || originSeen[origin] {
			return
		}
		originSeen[origin] = true
		origins = append(origins, origin)
	}

	for _, sc := range scopes {
		if sc.ScopeType != "web-application" {
			skipped = append(skipped, sc.ScopeType+":"+sc.Scope)
			continue
		}
		// A wildcard spelling is decided FIRST, even when it cannot be used:
		// falling through to concreteAsset would read "*.example.com" through
		// asset_value and silently downgrade the program's wildcard
		// authorization to a single exact host.
		if wildcardSpelling(sc.Scope) {
			if !importedAssetURLPathSafe(sc.Scope) {
				skipped = append(skipped, "asset path is not a canonical scope path: "+sc.Scope)
				continue
			}
			scheme, parent, port, path, ok := wildcardAsset(sc.Scope)
			if !ok {
				// Fail closed: the row names a wildcard but no http(s) scheme,
				// and guessing https would authorize an origin the program
				// never stated.
				skipped = append(skipped, "wildcard asset states no http(s) scheme (an omitted scheme is never guessed): "+sc.Scope)
				continue
			}
			asset, assetOK, assetErr := concreteAsset(sc)
			if assetErr != "" {
				skipped = append(skipped, assetErr)
				continue
			}
			if !importedPathIsSafe(path) || (assetOK && !importedPathIsSafe(asset.Path)) {
				skipped = append(skipped, "asset path is not a canonical scope path: "+sc.Scope)
				continue
			}
			if !addPrefix(path) {
				skipped = append(skipped, "asset path is not a canonical scope path: "+sc.Scope)
				continue
			}
			addSubdomainOnly(parent)
			// The wildcard row names both the subdomain pattern and (when the
			// platform supplies one) the scheme/port it was declared under.
			wildcardOrigin := domain.ScopeOrigin{Scheme: scheme, Host: parent, Port: port, Wildcard: true}.String()
			addOrigin(wildcardOrigin)
			bindings = append(bindings, scopePathBinding{Origin: wildcardOrigin, Path: path})
			if !assetOK {
				skipped = append(skipped, "wildcard asset (subdomains authorized, no seed host): "+sc.Scope)
				continue
			}
			if !domain.IsStrictSubdomain(asset.Host, parent) {
				skipped = append(skipped, "wildcard asset names no subdomain of "+parent+": "+sc.Scope)
				continue
			}
			if !addPrefix(asset.Path) {
				skipped = append(skipped, "asset path is not a canonical scope path: "+sc.Scope)
				continue
			}
			addHost(asset.Host)
			addTarget(asset.targetURL())
			addOrigin(asset.origin())
			bindings = append(bindings, scopePathBinding{Origin: asset.origin(), Path: asset.Path})
			continue
		}
		asset, ok, assetErr := concreteAsset(sc)
		if assetErr != "" {
			skipped = append(skipped, assetErr)
			continue
		}
		if !ok {
			switch {
			case strings.HasPrefix(strings.TrimSpace(sc.Scope), "."):
				// ".example.com" reads as "host and subdomains" on some
				// platforms and "subdomains only" on others. Refuse to guess
				// rather than authorize one reading the program did not mean.
				skipped = append(skipped, "leading-dot asset spelling not interpreted: "+sc.Scope)
			case assetHasNoScheme(sc):
				// The row names a host but no scheme, so the origin it
				// authorizes cannot be read from the source. Import never
				// guesses https (see docs/bounty.md); the operator adds the
				// origin themselves.
				skipped = append(skipped, "asset states no http(s) scheme, so its origin cannot be read from the source: "+sc.Scope)
			default:
				skipped = append(skipped, "no host in scope:"+sc.Scope)
			}
			continue
		}
		if !importedPathIsSafe(asset.Path) || !addPrefix(asset.Path) {
			skipped = append(skipped, "asset path is not a canonical scope path: "+sc.Scope)
			continue
		}
		addHost(asset.Host)
		addTarget(asset.targetURL())
		// An exact asset authorizes exactly the origin it names. A program
		// that lists https://app.example.com did not authorize http, nor
		// another port, even though Indago used to accept both.
		addOrigin(asset.origin())
		bindings = append(bindings, scopePathBinding{Origin: asset.origin(), Path: asset.Path})
	}
	bindings = normalizeScopePathBindings(bindings)
	if problem := scopePathBindingProblem(bindings); problem != "" {
		// Fail closed: a plan that cannot bind each path to its own origin is
		// refused as a whole. Returning none of the lists means a caller that
		// ignores `blocked` still cannot store a widened scope.
		return nil, nil, nil, nil, nil, skipped, problem
	}
	// The stored prefix list is derived from the bindings, not from the raw
	// addPrefix accumulation: a restriction normalized away above must not
	// narrow the scope, and the plain-prefix reduction is what makes the one
	// global list exact for every origin.
	bindingPaths := make([]string, 0, len(bindings))
	for _, b := range bindings {
		bindingPaths = append(bindingPaths, b.Path)
	}
	prefixes = reduceScopePathPrefixes(bindingPaths)
	sort.Strings(hosts)
	sort.Strings(subdomainOnly)
	sort.Strings(targets)
	sort.Strings(prefixes)
	sort.Strings(origins)
	return hosts, subdomainOnly, targets, prefixes, origins, skipped, ""
}

// wildcardSpelling reports whether a row's scope field is written as a
// wildcard asset: "*.example.com", "*.example.com:8443", or the same with a
// scheme and path. It is checked before concreteAsset so an unusable wildcard
// (one that names no scheme) is skipped instead of being silently downgraded to
// the single host in asset_value.
func wildcardSpelling(raw string) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	return strings.HasPrefix(raw, "*.") || strings.Contains(raw, "://*.")
}

// assetHasNoScheme reports whether the row describes a host but states no
// http(s) scheme, so its origin cannot be read from the source. Guessing https
// for such a row would authorize an origin the program never named, which is
// exactly the widening the importer must not do (docs/bounty.md).
func assetHasNoScheme(sc bounty.Scope) bool {
	for _, cand := range []string{sc.AssetValue, sc.Scope} {
		cand = strings.TrimSpace(cand)
		if cand == "" || strings.Contains(cand, "://") {
			continue
		}
		if wildcardSpelling(cand) || looksLikeHost(cand) {
			return true
		}
	}
	return false
}

// wildcardAsset reads the wildcard spelling of a row's scope field:
// "https://*.example.com", "https://*.example.com/path",
// "https://*.example.com:8443/path" or "https://*.example.com:8443". ok is
// false for anything else — including a wildcard written WITHOUT a scheme:
// the source did not state http or https, so no origin can be derived from it
// (fail closed; the operator declares the origin themselves).
func wildcardAsset(raw string) (scheme, host string, port int, path string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", 0, "", false
	}
	if !strings.Contains(raw, "://") {
		return "", "", 0, "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return "", "", 0, "", false
	}
	path, pathErr := domain.SafeScopePath(u)
	if pathErr != nil {
		return "", "", 0, "", false
	}
	if !strings.HasPrefix(u.Hostname(), "*.") {
		return "", "", 0, "", false
	}
	parent := strings.TrimPrefix(strings.ToLower(u.Hostname()), "*.")
	if parent == "" || strings.Contains(parent, "*") {
		return "", "", 0, "", false
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", 0, "", false
	}
	port = defaultPortForScheme(scheme)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "", 0, "", false
		}
		port = n
	}
	if path == "/" {
		path = ""
	}
	return scheme, parent, port, path, true
}

// concreteAsset picks the row's concrete host. The API schema puts the asset in
// asset_value, while the public page's transfer state puts the severity there
// and the asset in scope, so the first field that actually parses as a host
// wins. A wildcard spelling is never a concrete host: wildcardAsset handles it
// separately, and treating "*." as an exact name would authorize the wrong
// thing.
//
// The value must state http or https: an asset written as a bare host cannot
// say which origin the program authorized, and defaulting to https would widen
// the imported scope beyond the source (fail closed — the row is skipped with a
// reason and the operator declares the origin).
func concreteAsset(sc bounty.Scope) (bountyAsset, bool, string) {
	for _, cand := range []string{sc.AssetValue, sc.Scope} {
		cand = strings.TrimSpace(cand)
		if cand == "" || strings.HasPrefix(cand, "*.") || strings.HasPrefix(cand, ".") {
			continue
		}
		if !looksLikeHost(cand) {
			continue
		}
		raw := cand
		if !strings.Contains(raw, "://") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil {
			continue
		}
		// A wildcard spelling is never a concrete host: wildcardAsset handles
		// it, and adopting "*.example.com" as an exact include entry would
		// authorize nothing while looking like it authorized something.
		if strings.Contains(u.Hostname(), "*") {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			continue
		}
		path, pathErr := domain.SafeScopePath(u)
		if pathErr != nil {
			return bountyAsset{}, false, "asset path is not a canonical scope path: " + pathErr.Error()
		}
		port := defaultPortForScheme(scheme)
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				continue
			}
			port = n
		}
		if path == "/" {
			path = ""
		}
		return bountyAsset{Scheme: scheme, Host: strings.ToLower(u.Hostname()), Port: port, Path: path}, true, ""
	}
	return bountyAsset{}, false, ""
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

func atoiDefault(v string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
		return n
	}
	return def
}

type ywhDraftReq struct {
	ProgramSlug string `json:"program_slug,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	DraftID     string `json:"draft_id,omitempty"`
}

// yesWeHackSlugFromNotes extracts the YesWeHack program slug from the note
// written by handleImportBountyPrograms ("Imported from YesWeHack (<slug>)").
func yesWeHackSlugFromNotes(notes string) string {
	const prefix = "YesWeHack ("
	i := strings.Index(notes, prefix)
	if i < 0 {
		return ""
	}
	rest := notes[i+len(prefix):]
	j := strings.Index(rest, ")")
	if j <= 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// handleYesWeHackDraft creates or updates a YesWeHack draft report for a
// confirmed finding in the scan. It strictly writes to the draft endpoint and
// never submits a report.
func (s *Server) handleYesWeHackDraft(w http.ResponseWriter, r *http.Request) {
	if s.bountyClient == nil || s.bountyStore == nil {
		writeError(w, http.StatusServiceUnavailable, "bounty integration is not configured on this server")
		return
	}
	if !s.bountyStore.Configured() {
		writeError(w, http.StatusBadRequest, "YesWeHack credential is not configured (set it on the Bug bounty page)")
		return
	}
	scanID := domain.ID(r.PathValue("id"))
	sc, err := s.store.Scans().Get(r.Context(), scanID)
	if err != nil {
		s.writeLookupError(w, err)
		return
	}
	proj, err := s.store.Projects().Get(r.Context(), sc.ProjectID)
	if err != nil {
		s.writeInternalError(w, "load project", err)
		return
	}
	var req ywhDraftReq
	if err := readJSON(r, &req); err != nil {
		writeJSONBodyError(w, err)
		return
	}
	slug := strings.TrimSpace(req.ProgramSlug)
	if slug == "" {
		slug = yesWeHackSlugFromNotes(proj.Notes)
	}
	if slug == "" {
		writeError(w, http.StatusBadRequest, "program_slug is required (this project was not imported from YesWeHack)")
		return
	}

	all, err := s.store.Findings().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list findings", err)
		return
	}
	var targetFinding *domain.Finding
	if fid := strings.TrimSpace(req.FindingID); fid != "" {
		for _, f := range all {
			if string(f.ID) == fid {
				targetFinding = f
				break
			}
		}
		if targetFinding == nil {
			writeError(w, http.StatusNotFound, "finding not found in this scan")
			return
		}
		if targetFinding.Verdict != domain.VerdictConfirmed {
			writeError(w, http.StatusBadRequest, "only confirmed findings can be drafted to YesWeHack")
			return
		}
	} else {
		for _, f := range report.Prioritized(all) {
			if f.Verdict == domain.VerdictConfirmed {
				targetFinding = f
				break
			}
		}
		if targetFinding == nil {
			writeError(w, http.StatusBadRequest, "no confirmed findings in this scan to draft")
			return
		}
	}

	endpoints, err := s.store.Endpoints().ListByScan(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list endpoints", err)
		return
	}
	endpointURL := ""
	for _, ep := range endpoints {
		if ep.ID == targetFinding.EndpointID {
			endpointURL = ep.URL
			break
		}
	}
	lookup, err := s.loadEvidence(r.Context(), scanID)
	if err != nil {
		s.writeInternalError(w, "list evidence", err)
		return
	}
	built := report.BuildYesWeHackDraft(targetFinding, endpointURL, lookup.metadata(targetFinding), s.version)
	draft := bounty.DraftReport{
		Title:               built.Title,
		BugType:             built.BugType,
		Scope:               built.Scope,
		EndPoint:            built.EndPoint,
		VulnerablePart:      built.VulnerablePart,
		PartName:            built.PartName,
		Payload:             built.Payload,
		DescriptionMarkdown: built.DescriptionMarkdown,
		TechnicalEnv:        built.TechnicalEnv,
	}

	var res *bounty.DraftResult
	action := "created"
	status := http.StatusCreated
	if draftID := strings.TrimSpace(req.DraftID); draftID != "" {
		res, err = s.bountyClient.UpdateDraft(r.Context(), slug, draftID, draft)
		action = "updated"
		status = http.StatusOK
	} else {
		res, err = s.bountyClient.CreateDraft(r.Context(), slug, draft)
	}
	if err != nil {
		switch {
		case errors.Is(err, bounty.ErrNoToken):
			writeError(w, http.StatusBadRequest, "YesWeHack credential is not configured")
		case errors.Is(err, bounty.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "YesWeHack rejected the stored credential (401/403)")
		default:
			writeError(w, http.StatusBadGateway, "YesWeHack draft request failed: "+err.Error())
		}
		return
	}
	writeJSON(w, status, map[string]any{
		"program_slug": slug,
		"finding_id":   targetFinding.ID,
		"draft_id":     res.DraftID(),
		"action":       action,
		"submitted":    false,
		"url":          res.URL,
		"draft":        draft,
	})
}

package main

// Client commands: project, target, scope, scan.
//
// The CLI is a thin client over the running server's HTTP API (the same API the
// web UI uses), so both always show the same state and only the server process
// ever opens the SQLite database. State-changing requests carry the
// X-Indago-Client header the server requires.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/web"
)

// defaultServer returns the API base URL: $INDAGO_SERVER or the local default.
func defaultServer() string {
	if v := os.Getenv("INDAGO_SERVER"); v != "" {
		return v
	}
	return "http://127.0.0.1:8750"
}

// cli carries the server address and output stream for client commands.
type cli struct {
	server string
	out    io.Writer
	http   *http.Client
}

func newCLI(server string, out io.Writer) *cli {
	return &cli{
		server: strings.TrimRight(server, "/"),
		out:    out,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

// apiError is a non-2xx response from the server.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status) }

// call performs a JSON request. in may be nil; out may be nil.
func (c *cli) call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.server+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set(web.ClientHeader, "cli")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the indago server at %s (is `indago serve` running?): %w", c.server, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &apiError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// getRaw performs a GET and returns the raw response body — for endpoints
// that serve rendered content (report/evidence bytes) rather than JSON.
func (c *cli) getRaw(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.server+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the indago server at %s (is `indago serve` running?): %w", c.server, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg}
	}
	return data, nil
}

// --- flag helpers ---

// stringList is a repeatable string flag (-seed a -seed b).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parseInterspersed parses flags that may appear before or after positional
// arguments (Go's flag package stops at the first positional), returning the
// positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// newFlags builds a FlagSet whose errors are returned (not os.Exit) and which
// shares the -server flag.
func (c *cli) newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.server, "server", c.server, "indago server URL")
	return fs
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- dispatch ---

// runClient dispatches `project|target|scope|scan <sub> ...`.
func (c *cli) runClient(group string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: indago %s <subcommand> (see `indago help`)", group)
	}
	sub, rest := args[0], args[1:]
	switch group {
	case "project":
		return c.project(sub, rest)
	case "target":
		return c.target(sub, rest)
	case "scope":
		return c.scope(sub, rest)
	case "scan":
		return c.scan(sub, rest)
	case "finding":
		return c.finding(sub, rest)
	case "endpoint":
		return c.endpoint(sub, rest)
	case "auth":
		return c.auth(sub, rest)
	case "report":
		return c.report(sub, rest)
	}
	return fmt.Errorf("unknown command group %q", group)
}

func (c *cli) project(sub string, args []string) error {
	fs := c.newFlags("project " + sub)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	switch sub {
	case "create":
		if len(pos) != 1 {
			return errors.New("usage: indago project create <name>")
		}
		var p domain.Project
		if err := c.call("POST", "/api/projects", map[string]string{"name": pos[0]}, &p); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "created project %s (%s)\n", p.ID, p.Name)
		return nil
	case "list":
		var ps []domain.Project
		if err := c.call("GET", "/api/projects", nil, &ps); err != nil {
			return err
		}
		if len(ps) == 0 {
			fmt.Fprintln(c.out, "no projects")
		}
		for _, p := range ps {
			fmt.Fprintf(c.out, "%s  %s\n", p.ID, p.Name)
		}
		return nil
	}
	return fmt.Errorf("unknown project subcommand %q (create, list)", sub)
}

func (c *cli) target(sub string, args []string) error {
	fs := c.newFlags("target " + sub)
	project := fs.String("project", "", "project ID")
	name := fs.String("name", "", "target name")
	baseURL := fs.String("url", "", "target base URL")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *project == "" {
		return errors.New("-project is required")
	}
	switch sub {
	case "add":
		if *name == "" || *baseURL == "" {
			return errors.New("usage: indago target add -project ID -name NAME -url URL")
		}
		var t domain.Target
		if err := c.call("POST", "/api/projects/"+url.PathEscape(*project)+"/targets",
			map[string]string{"name": *name, "base_url": *baseURL}, &t); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "created target %s (%s → %s)\n", t.ID, t.Name, t.BaseURL)
		return nil
	case "list":
		var ts []domain.Target
		if err := c.call("GET", "/api/projects/"+url.PathEscape(*project)+"/targets", nil, &ts); err != nil {
			return err
		}
		if len(ts) == 0 {
			fmt.Fprintln(c.out, "no targets")
		}
		for _, t := range ts {
			fmt.Fprintf(c.out, "%s  %s  %s\n", t.ID, t.Name, t.BaseURL)
		}
		return nil
	}
	return fmt.Errorf("unknown target subcommand %q (add, list)", sub)
}

func (c *cli) scope(sub string, args []string) error {
	fs := c.newFlags("scope " + sub)
	project := fs.String("project", "", "project ID")
	include := fs.String("include", "", "comma-separated in-scope hosts")
	exclude := fs.String("exclude", "", "comma-separated excluded hosts")
	includePath := fs.String("include-path", "", "comma-separated in-scope path prefixes")
	excludePath := fs.String("exclude-path", "", "comma-separated excluded path prefixes")
	subdomains := fs.Bool("subdomains", false, "allow subdomains of included hosts")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *project == "" {
		return errors.New("-project is required")
	}
	path := "/api/projects/" + url.PathEscape(*project) + "/scope"
	switch sub {
	case "set":
		if *include == "" {
			return errors.New("usage: indago scope set -project ID -include host[,host...] [-exclude ...] [-include-path ...] [-exclude-path ...] [-subdomains]")
		}
		var sc domain.Scope
		if err := c.call("PUT", path, map[string]any{
			"include_hosts": splitCSV(*include), "exclude_hosts": splitCSV(*exclude),
			"include_path_prefixes": splitCSV(*includePath), "exclude_path_prefixes": splitCSV(*excludePath),
			"allow_subdomains": *subdomains,
		}, &sc); err != nil {
			return err
		}
		printScope(c.out, &sc)
		return nil
	case "show":
		var sc domain.Scope
		if err := c.call("GET", path, nil, &sc); err != nil {
			return err
		}
		printScope(c.out, &sc)
		return nil
	}
	return fmt.Errorf("unknown scope subcommand %q (set, show)", sub)
}

func printScope(w io.Writer, sc *domain.Scope) {
	fmt.Fprintf(w, "include hosts:        %s\n", strings.Join(sc.IncludeHosts, ", "))
	fmt.Fprintf(w, "exclude hosts:        %s\n", strings.Join(sc.ExcludeHosts, ", "))
	fmt.Fprintf(w, "include path prefix:  %s\n", strings.Join(sc.IncludePathPrefixes, ", "))
	fmt.Fprintf(w, "exclude path prefix:  %s\n", strings.Join(sc.ExcludePathPrefixes, ", "))
	fmt.Fprintf(w, "allow subdomains:     %v\n", sc.AllowSubdomains)
}

func (c *cli) scan(sub string, args []string) error {
	switch sub {
	case "create":
		return c.scanCreate(args)
	case "list":
		return c.scanList(args)
	case "status":
		return c.scanStatus(args)
	case "start", "pause", "resume", "cancel":
		return c.scanAction(sub, args)
	case "config":
		return c.scanConfig(args)
	}
	return fmt.Errorf("unknown scan subcommand %q (create, list, status, start, pause, resume, cancel, config)", sub)
}

func (c *cli) scanCreate(args []string) error {
	fs := c.newFlags("scan create")
	project := fs.String("project", "", "project ID")
	target := fs.String("target", "", "target ID")
	name := fs.String("name", "", "scan name")
	profile := fs.String("profile", "balanced", "conservative | balanced | fast")
	stop := fs.String("stop", "", "stop policy: continue_all | first_confirmed | after_n_confirmed | pause_and_ask")
	stopN := fs.Int("stop-n", 0, "confirmed-finding limit for -stop after_n_confirmed")
	authMode := fs.String("auth", "", "auth mode: anonymous (default) | existing | interactive | mfa | password")
	authState := fs.String("auth-state", "", "saved session material (Playwright storage-state JSON) for -auth existing")
	loginURL := fs.String("login-url", "", "login page to open; REQUIRED for -auth interactive|mfa|password")
	successURL := fs.String("success-url", "", "URL glob the browser must reach for the login to count as done; REQUIRED for -auth interactive|mfa|password")
	loginUserSel := fs.String("login-username-selector", "", "CSS selector override for the username/email field; -auth password only, empty = heuristic")
	loginPassSel := fs.String("login-password-selector", "", "CSS selector override for the password field; -auth password only, empty = heuristic (input[type=password])")
	loginSubmitSel := fs.String("login-submit-selector", "", "CSS selector override for the submit control; -auth password only, empty = heuristic")
	candProfile := fs.String("candidate-profile", "", "XSS candidate profile: minimal | standard | thorough (default: server default)")
	maxCand := fs.Int("max-candidates", 0, "cap on candidates tried per injection point (0 = the profile's own; hard ceiling 32)")
	enableEvasion := fs.Bool("enable-evasion", false, "opt in to WAF/filter-bypass candidate variants (case variation, alt separators, double URL-encoding) ON TOP OF the canonical set; OFF by default — only for an authorized engagement where a bypass is itself the reportable finding (see AGENTS.md §2.3)")
	var proxyPool stringList
	fs.Var(&proxyPool, "proxy", "proxy to route this scan's traffic through — raw HTTP and browser verification alike (repeatable, round-robin; http://host:port, https://host:port, or socks5://host:port, optionally with embedded user:pass@ creds); operator-supplied infrastructure only, off by default (see AGENTS.md §2.3)")
	randomizeTLS := fs.Bool("randomize-tls-fingerprint", false, "randomize the raw HTTP engine's TLS ClientHello (JA3) via uTLS instead of Go's own default — OFF by default (see AGENTS.md §2.3); MUTUALLY EXCLUSIVE with -proxy (Go's transport never consults a custom TLS dialer for a proxied connection); has no effect on browser verification, which already uses a real browser's own TLS stack")
	quick := fs.Bool("quick", false, "quick scan: test the seeds only, do not follow links (crawl depth 0)")
	depth := fs.Int("depth", 0, "crawl depth for a full scan (0 = server default; ignored with -quick)")
	maxPages := fs.Int("max-pages", 0, "cap on pages fetched by the crawler (0 = server default)")
	maxEndpoints := fs.Int("max-endpoints", 0, "cap on endpoints discovered (0 = server default)")
	var seeds stringList
	fs.Var(&seeds, "seed", "discovery seed URL (repeatable; default: the target base URL)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *project == "" || *target == "" {
		return errors.New("usage: indago scan create -project ID -target ID [-name N] [-profile P] [-quick|-depth N] [-max-pages N] [-max-endpoints N] [-candidate-profile P] [-max-candidates N] [-seed URL]... [-stop MODE [-stop-n N]] [-auth existing -auth-state FILE]")
	}
	req := map[string]any{
		"project_id": *project, "target_id": *target, "name": *name,
		"profile": *profile, "seed_urls": []string(seeds),
		"quick_scan": *quick, "max_depth": *depth, "max_pages": *maxPages, "max_endpoints": *maxEndpoints,
		"enable_evasion": *enableEvasion,
	}
	if len(proxyPool) > 0 {
		req["proxy_pool"] = []string(proxyPool)
	}
	if *randomizeTLS {
		req["randomize_tls_fingerprint"] = true
	}
	if *candProfile != "" {
		req["candidate_profile"] = *candProfile
	}
	if *maxCand != 0 {
		req["max_candidates"] = *maxCand
	}
	if *authState != "" && *authMode == "" {
		*authMode = string(domain.AuthExisting) // the only mode that takes a state file
	}
	if *authMode != "" {
		req["auth_mode"] = *authMode
	}
	if *authState != "" {
		// The server opens the file, so send an absolute path: a relative one
		// would be resolved against the server's working directory, not ours.
		abs, err := filepath.Abs(*authState)
		if err != nil {
			return fmt.Errorf("-auth-state: %w", err)
		}
		req["auth_state_path"] = abs
	}
	if *loginURL != "" {
		req["login_url"] = *loginURL
	}
	if *successURL != "" {
		req["success_url"] = *successURL
	}
	if *loginUserSel != "" {
		req["login_username_selector"] = *loginUserSel
	}
	if *loginPassSel != "" {
		req["login_password_selector"] = *loginPassSel
	}
	if *loginSubmitSel != "" {
		req["login_submit_selector"] = *loginSubmitSel
	}
	if *stop != "" {
		req["stop"] = map[string]any{"mode": *stop, "confirmed_limit": *stopN}
	}
	var sc domain.Scan
	if err := c.call("POST", "/api/scans", req, &sc); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "created scan %s (profile %s, %d seed(s))\nstart it with: indago scan start %s\n",
		sc.ID, sc.Profile, len(sc.SeedURLs), sc.ID)
	return nil
}

func (c *cli) scanList(args []string) error {
	fs := c.newFlags("scan list")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	var scans []domain.Scan
	if err := c.call("GET", "/api/scans", nil, &scans); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, scans)
	}
	if len(scans) == 0 {
		fmt.Fprintln(c.out, "no scans")
		return nil
	}
	for _, s := range scans {
		fmt.Fprintf(c.out, "%s  %-13s discovery=%-9s %s\n", s.ID, s.State, s.Discovery, s.Name)
	}
	return nil
}

func (c *cli) scanStatus(args []string) error {
	fs := c.newFlags("scan status")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: indago scan status <scan-id> [-json]")
	}
	id, err := c.resolveScanID(pos[0])
	if err != nil {
		return err
	}
	var st scan.Status
	if err := c.call("GET", "/api/scans/"+url.PathEscape(id)+"/status", nil, &st); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, st)
	}
	printStatus(c.out, &st)
	return nil
}

func (c *cli) scanAction(action string, args []string) error {
	fs := c.newFlags("scan " + action)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: indago scan %s <scan-id>", action)
	}
	id, err := c.resolveScanID(pos[0])
	if err != nil {
		return err
	}
	var st scan.Status
	if err := c.call("POST", "/api/scans/"+url.PathEscape(id)+"/"+action, nil, &st); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s: scan %s is now %s (discovery: %s)\n", action, st.Scan.ID, st.Scan.State, st.Discovery.State)
	return nil
}

// scanConfig changes a running scan's concurrency/rate at runtime. Crawl extent
// (quick/depth/limits) is fixed at creation and preserved by the server.
func (c *cli) scanConfig(args []string) error {
	fs := c.newFlags("scan config")
	disc := fs.Int("discovery", -1, "discovery concurrency")
	httpC := fs.Int("http", -1, "HTTP concurrency")
	browserC := fs.Int("browser", -1, "browser concurrency")
	rps := fs.Float64("rate", -1, "requests per second (0 = unlimited)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: indago scan config <scan-id> [-discovery N] [-http N] [-browser N] [-rate N]")
	}
	id, err := c.resolveScanID(pos[0])
	if err != nil {
		return err
	}
	// Start from the scan's current config so unspecified flags are unchanged.
	var cur scan.Status
	if err := c.call("GET", "/api/scans/"+url.PathEscape(id)+"/status", nil, &cur); err != nil {
		return err
	}
	cfg := cur.Scan.Config
	if *disc >= 0 {
		cfg.DiscoveryConcurrency = *disc
	}
	if *httpC >= 0 {
		cfg.HTTPConcurrency = *httpC
	}
	if *browserC >= 0 {
		cfg.BrowserConcurrency = *browserC
	}
	if *rps >= 0 {
		cfg.RequestsPerSecond = *rps
	}
	req := map[string]any{
		"discovery_concurrency": cfg.DiscoveryConcurrency,
		"http_concurrency":      cfg.HTTPConcurrency,
		"browser_concurrency":   cfg.BrowserConcurrency,
		"requests_per_second":   cfg.RequestsPerSecond,
	}
	var st scan.Status
	if err := c.call("POST", "/api/scans/"+url.PathEscape(id)+"/config", req, &st); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "reconfigured scan %s: discovery=%d http=%d browser=%d rate=%g\n",
		st.Scan.ID, st.Scan.Config.DiscoveryConcurrency, st.Scan.Config.HTTPConcurrency,
		st.Scan.Config.BrowserConcurrency, st.Scan.Config.RequestsPerSecond)
	return nil
}

// resolveScanID accepts a full scan ID or a unique prefix of one.
func (c *cli) resolveScanID(ref string) (string, error) {
	var scans []domain.Scan
	if err := c.call("GET", "/api/scans", nil, &scans); err != nil {
		return "", err
	}
	ids := make([]domain.ID, len(scans))
	for i, s := range scans {
		ids[i] = s.ID
	}
	return resolveIDPrefix("scan", ids, ref)
}

// resolveFindingID accepts a full finding ID or a unique prefix of one, scoped
// to a single scan's findings.
func (c *cli) resolveFindingID(scanID, ref string) (string, error) {
	var findings []domain.Finding
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/findings", nil, &findings); err != nil {
		return "", err
	}
	ids := make([]domain.ID, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return resolveIDPrefix("finding", ids, ref)
}

// resolveIDPrefix finds the one id in ids that equals ref or has it as a
// unique prefix.
func resolveIDPrefix(kind string, ids []domain.ID, ref string) (string, error) {
	var matches []string
	for _, id := range ids {
		if string(id) == ref {
			return ref, nil
		}
		if strings.HasPrefix(string(id), ref) {
			matches = append(matches, string(id))
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no %s matches %q", kind, ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%q is ambiguous (%d %ss match); use more characters", ref, len(matches), kind)
	}
}

func printStatus(w io.Writer, st *scan.Status) {
	s := st.Scan
	fmt.Fprintf(w, "Scan       %s  %q\n", s.ID, s.Name)
	// Only a non-terminal scan without a live execution is worth flagging: it is
	// waiting for an operator to resume it (e.g. restored after a restart).
	note := ""
	switch {
	case st.Running:
		note = "  (active)"
	case !s.State.IsTerminal() && s.State != domain.ScanCreated:
		note = "  (no live execution; resume to continue)"
	}
	fmt.Fprintf(w, "State      %s%s\n", s.State, note)
	fmt.Fprintf(w, "Discovery  %s\n", st.Discovery.State)
	fmt.Fprintf(w, "           endpoints %d   parameters %d   injection points %d\n",
		st.Discovery.Endpoints, st.Discovery.Parameters, st.Discovery.InjectionPoints)
	if len(st.Discovery.EndpointsBySource) > 0 {
		keys := make([]string, 0, len(st.Discovery.EndpointsBySource))
		for k := range st.Discovery.EndpointsBySource {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, st.Discovery.EndpointsBySource[domain.DiscoverySource(k)]))
		}
		fmt.Fprintf(w, "           by source: %s\n", strings.Join(parts, "  "))
	}
	j := st.Jobs
	fmt.Fprintf(w, "Jobs       queued %d   running %d   succeeded %d   failed %d   canceled %d   dead %d\n",
		j.Queued, j.Running+j.Leased, j.Succeeded, j.Failed, j.Canceled, j.Dead)
	t := st.Tests
	fmt.Fprintf(w, "Tests      success %d   error %d   timeout %d   cancelled %d   skipped %d   running %d\n",
		t.Success, t.Error, t.Timeout, t.Cancelled, t.Skipped, t.Running)
	f := st.Findings
	fmt.Fprintf(w, "Findings   confirmed %d   inconclusive %d   rejected %d   pending %d\n",
		f.Confirmed, f.Inconclusive, f.Rejected, f.Pending)
	if t.RateLimited > 0 || t.ServerError > 0 {
		fmt.Fprintf(w, "Responses  429 (rate-limited) %d   5xx (server error) %d\n", t.RateLimited, t.ServerError)
	}
	cfg := s.Config
	rate := "unlimited"
	if cfg.RequestsPerSecond > 0 {
		rate = fmt.Sprintf("%g req/s", cfg.RequestsPerSecond)
	}
	fmt.Fprintf(w, "Config     discovery %d   http %d   browser %d   rate %s\n",
		cfg.DiscoveryConcurrency, cfg.HTTPConcurrency, cfg.BrowserConcurrency, rate)
	if st.Workers != nil {
		fmt.Fprintf(w, "Workers    discovery %d   http %d   browser %d   (live)\n",
			st.Workers.Discovery, st.Workers.HTTP, st.Workers.Browser)
	}
	if sess := st.Session; sess != nil {
		line := fmt.Sprintf("Session    mode %s   state %s", sess.Mode, sess.State)
		if sess.HasState {
			line += "   (session material on file)"
		}
		if sess.ExpiresAt != nil {
			line += "   expires " + sess.ExpiresAt.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintln(w, line)
		if sess.LastError != "" {
			fmt.Fprintf(w, "           auth error: %s\n", sess.LastError)
		}
	}
	if s.Error != "" {
		fmt.Fprintf(w, "Error      %s\n", s.Error)
	}
}

// --- auth ---

// auth dispatches `indago auth login -login-url URL [-success-url GLOB]`,
// a thin client over the standalone POST /api/auth/login endpoint — for
// capturing a session ONCE to reuse across several `scan create -auth
// existing -auth-state FILE` runs, or to test login mechanics before
// wiring `-auth interactive` directly into `scan create`. Requires the
// server to have been started with `-browser` (opens a real, visible
// browser the operator logs into).
func (c *cli) auth(sub string, args []string) error {
	switch sub {
	case "login":
		return c.authLogin(args)
	}
	return fmt.Errorf("unknown auth subcommand %q (login)", sub)
}

func (c *cli) authLogin(args []string) error {
	fs := c.newFlags("auth login")
	loginURL := fs.String("login-url", "", "login page to open in a real, visible browser")
	successURL := fs.String("success-url", "", "URL glob the browser must reach before the login counts as done (optional, but a login with none saves state IMMEDIATELY with no wait at all)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *loginURL == "" {
		return errors.New("usage: indago auth login -login-url URL [-success-url GLOB]")
	}
	var out struct {
		StatePath string `json:"state_path"`
		FinalURL  string `json:"final_url"`
	}
	if err := c.call("POST", "/api/auth/login", map[string]string{"login_url": *loginURL, "success_url": *successURL}, &out); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "saved session: %s\n", out.StatePath)
	fmt.Fprintf(c.out, "final URL: %s\n", out.FinalURL)
	fmt.Fprintf(c.out, "use it with: scan create ... -auth existing -auth-state %s\n", out.StatePath)
	return nil
}

// --- endpoints ---

// endpoint dispatches `indago endpoint list -scan ID`. There is deliberately
// no "show" — an operator debugging why an authenticated scan went
// Inconclusive wants the whole discovered surface at a glance (esp. anything
// that looks like a session-terminating link or a dynamic-token parameter),
// not one endpoint at a time.
func (c *cli) endpoint(sub string, args []string) error {
	switch sub {
	case "list":
		return c.endpointList(args)
	}
	return fmt.Errorf("unknown endpoint subcommand %q (list)", sub)
}

// endpointListItem mirrors web.endpointListItem's JSON shape (Endpoint +
// its Parameters), decoded here the same read-only way findingCandidate
// mirrors the finding JSON shape above — never by importing internal/web.
type endpointListItem struct {
	domain.Endpoint
	Parameters []domain.Parameter `json:"parameters"`
}

func (c *cli) endpointList(args []string) error {
	fs := c.newFlags("endpoint list")
	scanRef := fs.String("scan", "", "scan ID or prefix")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago endpoint list -scan <scan-id|prefix> [-json]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	var items []endpointListItem
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/endpoints", nil, &items); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, items)
	}
	if len(items) == 0 {
		fmt.Fprintln(c.out, "no endpoints discovered yet")
		return nil
	}
	for _, ep := range items {
		fmt.Fprintf(c.out, "%s  %-6s %-10s %s\n", ep.ID, ep.Method, ep.Source, ep.URL)
		for _, p := range ep.Parameters {
			fmt.Fprintf(c.out, "    %-10s %-8s %s\n", p.Location, p.Name, p.Example)
		}
	}
	return nil
}

// --- findings ---

func (c *cli) finding(sub string, args []string) error {
	switch sub {
	case "list":
		return c.findingList(args)
	case "show":
		return c.findingShow(args)
	}
	return fmt.Errorf("unknown finding subcommand %q (list, show)", sub)
}

func (c *cli) findingList(args []string) error {
	fs := c.newFlags("finding list")
	scanRef := fs.String("scan", "", "scan ID or prefix")
	asJSON := fs.Bool("json", false, "print JSON")
	verdict := fs.String("verdict", "", "verdicts to list: confirmed | pending | inconclusive | rejected | comma-separated list | all (default: confirmed; all with -json)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago finding list -scan <scan-id|prefix> [-verdict confirmed|all|...] [-json]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	// The human-readable default is confirmed-only; -json defaults to every
	// finding, so a script consuming the JSON never silently loses the
	// pending/rejected rows it used to get (it has no place for a hint).
	if *verdict == "" {
		*verdict = "confirmed"
		if *asJSON {
			*verdict = "all"
		}
	}
	var findings []domain.Finding
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/findings?verdict="+url.QueryEscape(*verdict), nil, &findings); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, findings)
	}
	// Unless everything was asked for, say how many findings the filter hides:
	// the default view lists confirmed vulnerabilities only, and silence would
	// make rejected/pending diagnostics look like they do not exist.
	hidden := 0
	if *verdict != "all" {
		var all []domain.Finding
		if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/findings", nil, &all); err != nil {
			return err
		}
		hidden = len(all) - len(findings)
	}
	if len(findings) == 0 {
		fmt.Fprintf(c.out, "no %s findings\n", strings.TrimSpace(*verdict))
		if hidden > 0 {
			fmt.Fprintf(c.out, "%d other finding(s) hidden; list them with -verdict all\n", hidden)
		}
		return nil
	}
	for _, f := range findings {
		fmt.Fprintf(c.out, "%s  %-12s %-8s %-14s %s\n", f.ID, f.Verdict, f.Severity, f.VulnClass, f.Title)
	}
	if hidden > 0 {
		fmt.Fprintf(c.out, "(%d other finding(s) hidden; list them with -verdict all)\n", hidden)
	}
	return nil
}

// findingCandidate and findingDetail mirror the web API's JSON shape for a
// finding's parsed Detail (see web.findingCandidate/web.findingDetail) —
// decoded here only through this small, local, read-only shape, the same way
// internal/report decodes it, never by importing internal/scan or
// internal/detection.
type findingCandidate struct {
	Category       string `json:"category"`
	Context        string `json:"context"`
	Value          string `json:"value"`
	Technique      string `json:"technique"`
	Transformation string `json:"transformation"`
	Rationale      string `json:"rationale"`
	Priority       int    `json:"priority"`
}

type findingDetailOut struct {
	domain.Finding
	ParsedDetail struct {
		Method        string             `json:"method"`
		ParameterName string             `json:"parameter_name"`
		Occurrences   int                `json:"occurrences"`
		Candidates    []findingCandidate `json:"candidates"`
	} `json:"parsed_detail"`
	Verified *struct {
		CandidateValue string `json:"candidate_value"`
		URL            string `json:"url"`
		Notes          string `json:"notes"`
	} `json:"verified_candidate"`
	Attempts []struct {
		CandidateValue string `json:"candidate_value"`
		URL            string `json:"url"`
		Verdict        string `json:"verdict"`
	} `json:"attempts"`
	Endpoint          *domain.Endpoint   `json:"endpoint"`
	Parameter         *domain.Parameter  `json:"parameter"`
	Evidence          []*domain.Evidence `json:"evidence"`
	ReviewReasonLabel string             `json:"review_reason_label"`
}

func (c *cli) findingShow(args []string) error {
	fs := c.newFlags("finding show")
	scanRef := fs.String("scan", "", "scan ID or prefix")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if *scanRef == "" || len(pos) != 1 {
		return errors.New("usage: indago finding show -scan <scan-id|prefix> <finding-id|prefix> [-json]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	findingID, err := c.resolveFindingID(scanID, pos[0])
	if err != nil {
		return err
	}
	var fd findingDetailOut
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/findings/"+url.PathEscape(findingID), nil, &fd); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, fd)
	}
	printFindingDetail(c.out, c.server, &fd)
	return nil
}

func printFindingDetail(w io.Writer, server string, fd *findingDetailOut) {
	fmt.Fprintf(w, "Finding    %s\n", fd.ID)
	fmt.Fprintf(w, "Title      %s\n", fd.Title)
	fmt.Fprintf(w, "Verdict    %s   Severity %s   Confidence %s   Class %s\n", fd.Verdict, fd.Severity, fd.Confidence, fd.VulnClass)
	if fd.Endpoint != nil {
		fmt.Fprintf(w, "Endpoint   %s %s\n", fd.Endpoint.Method, fd.Endpoint.URL)
	}
	if fd.Parameter != nil {
		fmt.Fprintf(w, "Parameter  %s (%s)\n", fd.Parameter.Name, fd.Parameter.Location)
	} else if fd.ParsedDetail.ParameterName != "" {
		fmt.Fprintf(w, "Parameter  %s\n", fd.ParsedDetail.ParameterName)
	}
	if fd.Verified != nil {
		fmt.Fprintf(w, "Verified   %s\n", fd.Verified.CandidateValue)
		if fd.Verified.Notes != "" {
			fmt.Fprintf(w, "           %s\n", fd.Verified.Notes)
		}
	}
	if len(fd.Attempts) > 0 {
		fmt.Fprintf(w, "Attempts   %d (kept as diagnostics):\n", len(fd.Attempts))
		for _, a := range fd.Attempts {
			fmt.Fprintf(w, "  - %-12s %s\n", a.Verdict, a.CandidateValue)
			if a.URL != "" {
				fmt.Fprintf(w, "    %s\n", a.URL)
			}
		}
	}
	if fd.ReviewReasonLabel != "" {
		fmt.Fprintf(w, "Review     needs manual review: %s\n", fd.ReviewReasonLabel)
		if strings.Contains(fd.ReviewReasonLabel, "user action") {
			fmt.Fprintln(w, "           Open the attempt URL(s) above yourself and perform the action (click/hover/navigate) to actually exercise it — Indago deliberately never simulates this (AGENTS.md \u00a73).")
		}
	}
	if len(fd.ParsedDetail.Candidates) > 0 {
		fmt.Fprintf(w, "Candidates (%d, %d occurrence(s)):\n", len(fd.ParsedDetail.Candidates), fd.ParsedDetail.Occurrences)
		for _, cand := range fd.ParsedDetail.Candidates {
			tech := ""
			if cand.Technique != "" {
				tech = " [bypass: " + cand.Technique + "]"
			}
			fmt.Fprintf(w, "  - [%s/%s]%s %s — %s\n", cand.Category, cand.Context, tech, cand.Value, cand.Rationale)
		}
	}
	fmt.Fprintf(w, "Provenance %s, discovered via %s", fd.Provenance.Engine, fd.Provenance.DiscoverySource)
	if fd.Provenance.AIAssisted {
		fmt.Fprint(w, " (AI-assisted; advisory only)")
	}
	fmt.Fprintln(w)
	if len(fd.Evidence) > 0 {
		fmt.Fprintf(w, "Evidence (%d):\n", len(fd.Evidence))
		for _, ev := range fd.Evidence {
			fmt.Fprintf(w, "  - %s  %-10s %s  %d bytes  sha256:%s\n    open: %s/api/evidence/%s/content\n",
				ev.ID, ev.Kind, ev.MediaType, ev.Size, ev.SHA256, server, ev.ID)
		}
	}
}

// --- reports ---

func (c *cli) report(sub string, args []string) error {
	switch sub {
	case "create":
		return c.reportCreate(args)
	case "list":
		return c.reportList(args)
	case "show":
		return c.reportShow(args)
	}
	return fmt.Errorf("unknown report subcommand %q (create, list, show)", sub)
}

func (c *cli) reportCreate(args []string) error {
	fs := c.newFlags("report create")
	scanRef := fs.String("scan", "", "scan ID or prefix")
	format := fs.String("format", "json", "json | markdown | html")
	out := fs.String("out", "", "also write the rendered report to this file")
	mode := fs.String("mode", "", "all | confirmed | selected (default: selected when -finding is given, else all)")
	aiSummary := fs.Bool("ai-summary", false, "ask the AI Gateway (if configured with -ai-provider on `indago serve`) for an advisory executive summary, prepended to the report and clearly labeled; no effect if AI is disabled")
	var findingIDs stringList
	fs.Var(&findingIDs, "finding", "finding ID to include with -mode selected (repeatable)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago report create -scan <scan-id|prefix> -format json|markdown|html [-mode all|confirmed|selected] [-finding ID]... [-ai-summary] [-out FILE]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	var rpt domain.Report
	if err := c.call("POST", "/api/scans/"+url.PathEscape(scanID)+"/reports",
		map[string]any{"format": *format, "mode": *mode, "finding_ids": []string(findingIDs), "ai_summary": *aiSummary}, &rpt); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "created report %s (%s, %d finding(s); selection %s, %d of %d in scan; %s)\n",
		rpt.ID, rpt.Format, rpt.Summary.TotalFindings, rpt.Summary.Selection,
		rpt.Summary.TotalFindings, rpt.Summary.ScanFindings, verdictBreakdown(rpt.Summary.ByVerdict))
	if *out != "" {
		return c.downloadReport(string(rpt.ID), *out)
	}
	return nil
}

// verdictBreakdown renders verdict counts in a fixed order, e.g.
// "confirmed 2, rejected 1" (zero counts omitted; "no findings" when empty).
func verdictBreakdown(by map[domain.Verdict]int) string {
	var parts []string
	for _, v := range []domain.Verdict{domain.VerdictConfirmed, domain.VerdictInconclusive, domain.VerdictRejected, domain.VerdictPending} {
		if n := by[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", v, n))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

func (c *cli) reportList(args []string) error {
	fs := c.newFlags("report list")
	scanRef := fs.String("scan", "", "scan ID or prefix")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago report list -scan <scan-id|prefix> [-json]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	var reports []domain.Report
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/reports", nil, &reports); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, reports)
	}
	if len(reports) == 0 {
		fmt.Fprintln(c.out, "no reports")
		return nil
	}
	for _, r := range reports {
		fmt.Fprintf(c.out, "%s  %-9s findings=%-3d %s\n", r.ID, r.Format, r.Summary.TotalFindings, r.CreatedAt.Format(time.RFC3339))
	}
	return nil
}

func (c *cli) reportShow(args []string) error {
	fs := c.newFlags("report show")
	out := fs.String("out", "", "write content to this file instead of stdout")
	download := fs.Bool("download", false, "ask the server for a download Content-Disposition")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: indago report show <report-id> [-out FILE] [-download]")
	}
	path := "/api/reports/" + url.PathEscape(pos[0]) + "/content"
	if *download {
		path += "?download"
	}
	data, err := c.getRaw(path)
	if err != nil {
		return err
	}
	if *out != "" {
		return writeReportFile(c.out, *out, data)
	}
	_, err = c.out.Write(data)
	return err
}

func (c *cli) downloadReport(id, out string) error {
	data, err := c.getRaw("/api/reports/" + url.PathEscape(id) + "/content")
	if err != nil {
		return err
	}
	return writeReportFile(c.out, out, data)
}

func writeReportFile(w io.Writer, path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote report to %s\n", path)
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

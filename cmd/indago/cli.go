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
	}
	return fmt.Errorf("unknown scan subcommand %q (create, list, status, start, pause, resume, cancel)", sub)
}

func (c *cli) scanCreate(args []string) error {
	fs := c.newFlags("scan create")
	project := fs.String("project", "", "project ID")
	target := fs.String("target", "", "target ID")
	name := fs.String("name", "", "scan name")
	profile := fs.String("profile", "balanced", "conservative | balanced | fast")
	stop := fs.String("stop", "", "stop policy: continue_all | first_confirmed | after_n_confirmed | pause_and_ask")
	stopN := fs.Int("stop-n", 0, "confirmed-finding limit for -stop after_n_confirmed")
	authMode := fs.String("auth", "", "auth mode: anonymous (default) | existing")
	authState := fs.String("auth-state", "", "saved session material (Playwright storage-state JSON) for -auth existing")
	var seeds stringList
	fs.Var(&seeds, "seed", "discovery seed URL (repeatable; default: the target base URL)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *project == "" || *target == "" {
		return errors.New("usage: indago scan create -project ID -target ID [-name N] [-profile P] [-seed URL]... [-stop MODE [-stop-n N]] [-auth existing -auth-state FILE]")
	}
	req := map[string]any{
		"project_id": *project, "target_id": *target, "name": *name,
		"profile": *profile, "seed_urls": []string(seeds),
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
	if s.Error != "" {
		fmt.Fprintf(w, "Error      %s\n", s.Error)
	}
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
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago finding list -scan <scan-id|prefix> [-json]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	var findings []domain.Finding
	if err := c.call("GET", "/api/scans/"+url.PathEscape(scanID)+"/findings", nil, &findings); err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, findings)
	}
	if len(findings) == 0 {
		fmt.Fprintln(c.out, "no findings")
		return nil
	}
	for _, f := range findings {
		fmt.Fprintf(c.out, "%s  %-12s %-8s %-14s %s\n", f.ID, f.Verdict, f.Severity, f.VulnClass, f.Title)
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
	Endpoint  *domain.Endpoint   `json:"endpoint"`
	Parameter *domain.Parameter  `json:"parameter"`
	Evidence  []*domain.Evidence `json:"evidence"`
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
	if len(fd.ParsedDetail.Candidates) > 0 {
		fmt.Fprintf(w, "Candidates (%d, %d occurrence(s)):\n", len(fd.ParsedDetail.Candidates), fd.ParsedDetail.Occurrences)
		for _, cand := range fd.ParsedDetail.Candidates {
			fmt.Fprintf(w, "  - [%s/%s] %s — %s\n", cand.Category, cand.Context, cand.Value, cand.Rationale)
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
	var findingIDs stringList
	fs.Var(&findingIDs, "finding", "finding ID to include (repeatable; default: every finding in the scan)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *scanRef == "" {
		return errors.New("usage: indago report create -scan <scan-id|prefix> -format json|markdown|html [-finding ID]... [-out FILE]")
	}
	scanID, err := c.resolveScanID(*scanRef)
	if err != nil {
		return err
	}
	var rpt domain.Report
	if err := c.call("POST", "/api/scans/"+url.PathEscape(scanID)+"/reports",
		map[string]any{"format": *format, "finding_ids": []string(findingIDs)}, &rpt); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "created report %s (%s, %d finding(s))\n", rpt.ID, rpt.Format, rpt.Summary.TotalFindings)
	if *out != "" {
		return c.downloadReport(string(rpt.ID), *out)
	}
	return nil
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

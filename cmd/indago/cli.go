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
	var seeds stringList
	fs.Var(&seeds, "seed", "discovery seed URL (repeatable; default: the target base URL)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *project == "" || *target == "" {
		return errors.New("usage: indago scan create -project ID -target ID [-name N] [-profile P] [-seed URL]... [-stop MODE [-stop-n N]]")
	}
	req := map[string]any{
		"project_id": *project, "target_id": *target, "name": *name,
		"profile": *profile, "seed_urls": []string(seeds),
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
	var matches []string
	for _, s := range scans {
		if string(s.ID) == ref {
			return ref, nil
		}
		if strings.HasPrefix(string(s.ID), ref) {
			matches = append(matches, string(s.ID))
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no scan matches %q", ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%q is ambiguous (%d scans match); use more characters", ref, len(matches))
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

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Command indago is the CLI entrypoint for the Indago security-hunting platform.
//
// Subcommands:
//
//	indago version            print version information
//	indago db init            create the data dir and initialize the database
//	indago serve              run the web UI + API server
//	indago project|target|scope|scan ...   drive a running server (see `indago help`)
//
// `serve` brings up the full backend (store, queue, scan controller, discovery,
// web). Scans perform scope-enforced discovery; job handlers are still the
// Phase 0 no-ops, so no vulnerability testing happens.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/config"
	"github.com/indago/indago/internal/evidence"
	"github.com/indago/indago/internal/httpengine"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/sqlite"
	"github.com/indago/indago/internal/web"
)

// Set via -ldflags at build time (see Makefile).
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "version", "-v", "--version":
		cmdVersion()
	case "db":
		err = cmdDB(args)
	case "serve":
		err = cmdServe(args)
	case "project", "target", "scope", "scan", "finding", "report":
		err = newCLI(defaultServer(), os.Stdout).runClient(cmd, args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "indago: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "indago: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `indago — local-first web application security hunting platform

Usage:
  indago <command> [flags]

Server:
  version        Print version information
  db init        Create the data directory and initialize the database
  serve          Run the web UI + API server (flags: -data, -addr, -v)

Client (talk to a running server; -server URL or $INDAGO_SERVER, default http://127.0.0.1:8750):
  project create <name> | project list
  target add -project ID -name NAME -url URL | target list -project ID
  scope set -project ID -include host[,host] [-exclude ..] [-include-path ..] [-exclude-path ..] [-subdomains]
  scope show -project ID
  scan create -project ID -target ID [-name N] [-profile P] [-seed URL]... [-stop MODE [-stop-n N]]
              [-auth existing -auth-state FILE]
  scan list [-json]
  scan status <scan-id|prefix> [-json]
  scan start|pause|resume|cancel <scan-id|prefix>
  finding list -scan <scan-id|prefix> [-json]
  finding show -scan <scan-id|prefix> <finding-id|prefix> [-json]
  report create -scan <scan-id|prefix> -format json|markdown|html [-finding ID]... [-out FILE]
  report list -scan <scan-id|prefix> [-json]
  report show <report-id|prefix> [-out FILE] [-download]

Scope is mandatory: nothing is requested outside it. Authorized use only.
`)
}

func cmdVersion() {
	fmt.Printf("indago %s (commit %s, built %s)\n", version, commit, buildDate)
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(l)
	return l
}

func cmdDB(args []string) error {
	// Expect: db <subcommand> [flags]. Flags follow the subcommand, so strip the
	// subcommand before parsing (Go's flag package stops at the first positional).
	if len(args) < 1 || args[0] != "init" {
		return fmt.Errorf("usage: indago db init [-data dir]")
	}
	fs := flag.NewFlagSet("db init", flag.ExitOnError)
	dataDir := fs.String("data", config.DefaultDataDir, "data directory")
	_ = fs.Parse(args[1:])

	cfg := config.Default()
	cfg.DataDir = *dataDir
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		return err
	}
	fmt.Printf("initialized database at %s\n", cfg.DBPath())
	fmt.Printf("evidence directory at %s\n", cfg.EvidenceDir())
	fmt.Printf("reports directory at %s\n", cfg.ReportsDir())
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", config.DefaultDataDir, "data directory")
	addr := fs.String("addr", "", "listen address (overrides config)")
	debug := fs.Bool("v", false, "verbose (debug) logging")
	allowUnsafe := fs.Bool("allow-state-changing", false,
		"also execute POST/PUT/PATCH/DELETE endpoints (default: only GET/HEAD/OPTIONS; others are skipped)")
	useBrowser := fs.Bool("browser", false, "enable browser network-observation discovery AND browser verification of reflected XSS candidates (needs Chromium; requests are scope-gated)")
	chromium := fs.String("chromium", "", "Chromium executable for -browser (default: $INDAGO_CHROMIUM_PATH or the Playwright cache)")
	allowRemote := fs.Bool("allow-remote", false,
		"allow binding a non-loopback address; required because the API has no authentication (see docs/deployment.md)")
	_ = fs.Parse(args)

	log := newLogger(*debug)

	cfg, err := config.Load(cfgPath(*dataDir))
	if err != nil {
		return err
	}
	cfg.DataDir = *dataDir
	if *addr != "" {
		cfg.Server.Addr = *addr
	}
	if err := checkRemoteBindAllowed(cfg.Server.Addr, *allowRemote); err != nil {
		return err
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	// Persist config so first run writes a template the operator can edit.
	if err := cfg.Save(cfg.ConfigPath()); err != nil {
		log.Warn("could not persist config", "err", err)
	}

	db, err := sqlite.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		return err
	}

	q := queue.NewSQLite(db.SQL())

	// Discovery's HTTP engine. FollowRedirects MUST be false: the scan controller
	// wraps this engine in a scope check that follows redirects itself, so every
	// hop is verified against scope. (Browser-network discovery is opt-in via
	// -browser; its requests are scope-gated inside the browser.)
	httpCfg := httpengine.DefaultConfig()
	httpCfg.FollowRedirects = false
	httpCfg.Timeout = 20 * time.Second
	eng, err := httpengine.New(httpCfg)
	if err != nil {
		return err
	}
	defer eng.Close()

	evStore, err := evidence.NewFS(cfg.EvidenceDir())
	if err != nil {
		return err
	}

	opts := scan.Options{
		HTTP:     eng,
		Evidence: evStore,
		Executor: scan.ExecutorConfig{AllowStateChanging: *allowUnsafe},
	}
	if *allowUnsafe {
		log.Warn("state-changing methods (POST/PUT/PATCH/DELETE) will be executed against in-scope targets")
	}
	if *useBrowser {
		bm, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: *chromium}, log)
		if err != nil {
			return fmt.Errorf("start browser (-browser): %w", err)
		}
		defer bm.Close()
		opts.Browser = bm
	}
	ctrl := scan.NewController(db, q, log, version, opts)

	// Restart recovery, in order: requeue jobs left active by the previous run,
	// then restore interrupted scans as PAUSED. Nothing is resumed automatically —
	// a restart never sends traffic until the operator resumes the scan.
	if n, err := ctrl.Recover(context.Background()); err != nil {
		log.Warn("job recovery failed", "err", err)
	} else if n > 0 {
		log.Info("recovered orphaned jobs", "count", n)
	}
	if n, err := ctrl.RecoverScans(context.Background()); err != nil {
		log.Warn("scan recovery failed", "err", err)
	} else if n > 0 {
		log.Info("restored interrupted scans as paused; resume them with `indago scan resume <id>`", "count", n)
	}
	if !isLoopbackAddr(cfg.Server.Addr) {
		log.Warn("listening on a non-loopback address (-allow-remote): the API has no authentication and can start scans, read evidence, and generate reports; restrict access at the network level (firewall/VPN)", "addr", cfg.Server.Addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := web.NewServer(db, ctrl, version, log, evStore, cfg.ReportsDir())
	log.Info("indago starting", "version", version, "data", cfg.DataDir)
	err = srv.ListenAndServe(ctx, cfg.Server.Addr)
	ctrl.Shutdown()
	return err
}

// checkRemoteBindAllowed refuses a non-loopback bind unless the operator
// explicitly opted in. The API has no authentication (it's a local control
// plane — see internal/web/guard.go): anyone who can reach it can start
// scans, read findings/evidence (which may include captured session
// cookies), and generate reports. A log warning alone is easy to miss running
// as a daemon, so this is an outright refusal, not just advice.
func checkRemoteBindAllowed(addr string, allowRemote bool) error {
	if isLoopbackAddr(addr) || allowRemote {
		return nil
	}
	return fmt.Errorf("refusing to bind non-loopback address %q without -allow-remote: "+
		"the API has no authentication and can start scans, read evidence, and generate reports; "+
		"see docs/deployment.md before exposing it beyond localhost", addr)
}

// isLoopbackAddr reports whether addr binds only the loopback interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cfgPath(dataDir string) string {
	c := config.Default()
	c.DataDir = dataDir
	return c.ConfigPath()
}

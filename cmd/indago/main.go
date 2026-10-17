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
// web) and the operational dashboard. Scans run the full scope-enforced
// Reflected XSS pipeline — discovery, reflection, context analysis, candidate
// execution, and (with -browser) real-browser verification — and the web UI and
// CLI drive it through the same HTTP API.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/indago/indago/internal/ai"
	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/config"
	"github.com/indago/indago/internal/domain"
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

// apiTokenEnv names the environment variable holding the control API's bearer
// token. It is deliberately never a command-line flag (see cmdServe).
const apiTokenEnv = "INDAGO_API_TOKEN"

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
	case "evidence":
		err = cmdEvidence(args)
	case "project", "target", "scope", "scan", "finding", "endpoint", "auth", "report":
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
  serve          Run the web UI + API server (flags: -data, -addr, -v, -tls-cert/-tls-key for HTTPS; env INDAGO_API_TOKEN enables the API bearer token)

Client (talk to a running server; -server URL or $INDAGO_SERVER_URL, default http://127.0.0.1:8750; $INDAGO_CA_CERT = PEM CA file for a private/self-signed https server; $INDAGO_API_TOKEN if the server requires a token):
  project create <name> | project list
  target add -project ID -name NAME -url URL | target list -project ID
  scope set -project ID -include host[,host] [-exclude ..] [-include-path ..] [-exclude-path ..] [-subdomains]
  scope show -project ID
  scan create -project ID -target ID [-name N] [-profile P] [-candidate-profile minimal|standard|thorough] [-max-candidates N] [-seed URL]... [-stop MODE [-stop-n N]]
              [-quick | -depth N] [-max-pages N] [-max-endpoints N] [-proxy URL]... [-randomize-tls-fingerprint]
              [-auth anonymous|existing|interactive|mfa|password] [-auth-state FILE] [-login-url URL] [-success-url GLOB]
              [-login-username-selector SEL] [-login-password-selector SEL] [-login-submit-selector SEL]
  scan list [-json]
  scan status <scan-id|prefix> [-json]
  scan start|pause|resume|cancel <scan-id|prefix>
  scan config <scan-id|prefix> [-discovery N] [-http N] [-browser N] [-rate N]   (runtime tuning)
  finding list -scan <scan-id|prefix> [-verdict confirmed|pending|inconclusive|rejected|all] [-json]   (default: confirmed; all with -json)
  finding show -scan <scan-id|prefix> <finding-id|prefix> [-json]
  finding poc -scan <scan-id|prefix> -out <file.html> <finding-id|prefix>   (standalone PoC artifact; Confirmed findings only)
  endpoint list -scan <scan-id|prefix> [-json]   (discovered endpoints + their parameters, for debugging why a scan is Inconclusive)
  auth login -login-url URL [-success-url GLOB]   (standalone interactive-login capture; requires indago serve -browser)
  report create -scan <scan-id|prefix> -format json|markdown|html [-mode all|confirmed|selected] [-finding ID]... [-out FILE]
  report list -scan <scan-id|prefix> [-json]
  report show <report-id|prefix> [-out FILE] [-download]

Local maintenance (reads -data directly; no server needed):
  evidence prune -older-than DURATION [-data DIR] [-scan ID] [-include-sessions] [-include-reports] [-apply]
              dry run by default; deletes evidence of terminal scans older than the cutoff (docs/deployment.md, Retention)

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
		"allow binding a non-loopback address; requires INDAGO_API_TOKEN and -tls-cert/-tls-key (see docs/deployment.md)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate file: serve HTTPS (a path, not the certificate value)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for -tls-cert (a path; the key is never printed or logged)")
	allowPlaintextRemote := fs.Bool("allow-plaintext-remote", false,
		"permit a non-loopback bind WITHOUT TLS: the bearer token then travels unencrypted, and a warning is logged")
	apiRate := fs.Float64("api-rate", config.DefaultAPIRate,
		"per-client-IP sustained requests/second on /api/ and /metrics; 0 disables (overrides config.json server.api_rate)")
	apiBurst := fs.Int("api-burst", config.DefaultAPIBurst,
		"per-client-IP burst size on /api/ and /metrics (overrides config.json server.api_burst)")
	aiProvider := fs.String("ai-provider", "", "enable the advisory AI Gateway with this provider (openai|anthropic|openrouter|ollama|vllm); empty keeps AI fully disabled")
	aiModel := fs.String("ai-model", "", "model name for -ai-provider (required if -ai-provider is set)")
	aiBaseURL := fs.String("ai-base-url", "", "override the provider's default base URL (required for a non-default ollama/vllm deployment)")
	_ = fs.Parse(args)
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	log := newLogger(*debug)

	// The API bearer token is read once, here, from the environment: never a
	// flag (shell history, `ps`), never written to config.json, never logged.
	apiToken := os.Getenv(apiTokenEnv)

	cfg, err := config.Load(cfgPath(*dataDir))
	if err != nil {
		return err
	}
	cfg.DataDir = *dataDir
	if *addr != "" {
		cfg.Server.Addr = *addr
	}
	// The rate-limit values as the config file had them: flags override them
	// for this run only and are not written back by the save-on-start below.
	fileRate, fileBurst := cfg.Server.APIRate, cfg.Server.APIBurst
	if cfg.Server, err = overlayRateLimitFlags(cfg.Server, setFlags, *apiRate, *apiBurst); err != nil {
		return err
	}
	if apiToken != "" {
		if err := web.ValidateAPIToken(apiToken); err != nil {
			return fmt.Errorf("%s: %w", apiTokenEnv, err)
		}
	}
	if err := validateTLSFlags(*tlsCert, *tlsKey); err != nil {
		return err
	}
	var tlsCfg *tls.Config
	if *tlsCert != "" {
		if tlsCfg, err = newServeTLSConfig(*tlsCert, *tlsKey); err != nil {
			return err
		}
	}
	warning, err := checkRemoteBindAllowed(cfg.Server.Addr, *allowRemote, apiToken, tlsCfg != nil, *allowPlaintextRemote)
	if err != nil {
		return err
	}
	if err := cfg.EnsureDirs(); err != nil {
		return err
	}
	// Persist config so first run writes a template the operator can edit.
	saved := cfg
	saved.Server.APIRate, saved.Server.APIBurst = fileRate, fileBurst
	if err := saved.Save(cfg.ConfigPath()); err != nil {
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
		HTTP:        eng,
		HTTPConfig:  httpCfg,
		Evidence:    evStore,
		Executor:    scan.ExecutorConfig{AllowStateChanging: *allowUnsafe},
		SessionsDir: cfg.SessionsDir(),
	}
	if *allowUnsafe {
		log.Warn("state-changing methods (POST/PUT/PATCH/DELETE) will be executed against in-scope targets")
	}
	var loginFn web.LoginFunc
	if *useBrowser {
		bm, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: *chromium}, log)
		if err != nil {
			return fmt.Errorf("start browser (-browser): %w", err)
		}
		defer bm.Close()
		opts.Browser = bm
		// Interactive login reuses the same manager; it opens its OWN visible
		// browser (independent of the pool's headless setting) and saves the
		// captured session under the data dir. The web layer only ever returns
		// the saved file's path, never its contents.
		sessionsDir := cfg.SessionsDir()
		loginFn = func(ctx context.Context, p web.LoginParams) (string, string, error) {
			statePath := filepath.Join(sessionsDir, "login-"+string(domain.NewID())+".json")
			res, err := bm.InteractiveLogin(ctx, browser.LoginOptions{
				LoginURL:         p.LoginURL,
				SuccessURLGlob:   p.SuccessURL,
				StorageStatePath: statePath,
			})
			if err != nil {
				return "", "", err
			}
			return res.StorageStatePath, res.FinalURL, nil
		}
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
	if warning != "" {
		log.Warn(warning, "addr", cfg.Server.Addr)
	}
	if tlsCfg != nil {
		// Paths only: the certificate and key contents are never logged.
		log.Info("serving HTTPS", "cert", *tlsCert, "key", *tlsKey)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := web.NewServer(db, ctrl, version, log, evStore, cfg.ReportsDir())
	srv.SetLoginFunc(loginFn) // nil unless -browser: endpoint then reports unavailable
	if err := srv.SetRateLimit(cfg.Server.APIRate, cfg.Server.APIBurst); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	if cfg.Server.APIRate > 0 {
		log.Info("api rate limit enabled", "rate_per_s", cfg.Server.APIRate, "burst", cfg.Server.APIBurst)
	} else {
		log.Warn("api rate limit DISABLED (-api-rate 0 or api_rate 0)")
	}
	if err := srv.SetAPIToken(apiToken); err != nil {
		return fmt.Errorf("%s: %w", apiTokenEnv, err)
	}
	if apiToken != "" {
		log.Info("control API requires a bearer token", "env", apiTokenEnv)
	}
	gw, err := ai.New(ai.Settings{
		Enabled:  *aiProvider != "",
		Provider: *aiProvider,
		Model:    *aiModel,
		BaseURL:  *aiBaseURL,
		// Read fresh here, once, at startup — same pattern as
		// INDAGO_AUTH_USER/PASS for AuthMode password: a secret never
		// arrives via a CLI flag (shell history, `ps`) or a request body.
		APIKey: os.Getenv("INDAGO_AI_API_KEY"),
	})
	if err != nil {
		return fmt.Errorf("configure AI gateway (-ai-provider): %w", err)
	}
	srv.SetAIGateway(gw)
	if gw.Enabled() {
		log.Info("AI gateway enabled (advisory only)", "provider", *aiProvider, "model", *aiModel)
	}
	log.Info("indago starting", "version", version, "data", cfg.DataDir)
	err = srv.ListenAndServe(ctx, cfg.Server.Addr, tlsCfg)
	ctrl.Shutdown()
	return err
}

// checkRemoteBindAllowed refuses a non-loopback bind unless the operator opts
// in with -allow-remote AND configures INDAGO_API_TOKEN AND serves TLS
// (-tls-cert/-tls-key). The control API can start scans, read findings and
// evidence (which may include captured session cookies), and generate reports;
// a remote bind without the bearer token, or with the token in clear text,
// would expose all of that. The only way around the TLS requirement is
// -allow-plaintext-remote, which is allowed but returns a warning for the
// caller to log. Every refusal is an error, not a log line, which is easy to
// miss running as a daemon. The token value never appears in the returned
// error or warning.
func checkRemoteBindAllowed(addr string, allowRemote bool, token string, tlsOn, allowPlaintext bool) (warning string, err error) {
	if isLoopbackAddr(addr) {
		return "", nil
	}
	if !allowRemote {
		return "", fmt.Errorf("refusing to bind non-loopback address %q without -allow-remote; "+
			"a remote bind also requires %s (the control API can start scans, read evidence, and generate reports) "+
			"and TLS (-tls-cert and -tls-key); see docs/deployment.md before exposing it beyond localhost", addr, apiTokenEnv)
	}
	if token == "" {
		return "", fmt.Errorf("refusing to bind non-loopback address %q with -allow-remote and no API token: "+
			"set %s to a random token of at least %d characters (for example: openssl rand -hex 32); "+
			"see docs/deployment.md", addr, apiTokenEnv, web.MinAPITokenLen)
	}
	if tlsOn {
		return "", nil
	}
	if !allowPlaintext {
		return "", fmt.Errorf("refusing to bind non-loopback address %q without TLS: the API token would travel "+
			"unencrypted. Pass -tls-cert and -tls-key to serve HTTPS (see docs/deployment.md). To accept plaintext "+
			"anyway, pass -allow-plaintext-remote", addr)
	}
	return "listening on a non-loopback address WITHOUT TLS (-allow-plaintext-remote): the API bearer token and " +
		"all API responses travel unencrypted; prefer -tls-cert/-tls-key or a TLS-terminating proxy", nil
}

// validateTLSFlags requires -tls-cert and -tls-key to be given together.
func validateTLSFlags(certFile, keyFile string) error {
	switch {
	case certFile == "" && keyFile == "":
		return nil
	case keyFile == "":
		return errors.New("-tls-cert requires -tls-key (both are needed to serve HTTPS)")
	case certFile == "":
		return errors.New("-tls-key requires -tls-cert (both are needed to serve HTTPS)")
	}
	return nil
}

// newServeTLSConfig loads and checks the certificate/key pair at startup, so a
// wrong path or a mismatched key fails here, not on the first connection. The
// error names the files; it never includes key material.
func newServeTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate %s with key %s: %w", certFile, keyFile, err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
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

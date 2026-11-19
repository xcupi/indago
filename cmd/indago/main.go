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
	"github.com/indago/indago/internal/bounty"
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
	"github.com/indago/indago/internal/llm"
	"github.com/indago/indago/internal/oast"
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

// apiTokenEnv names the environment variable holding the control API's token.
// The same value can be supplied per invocation with -api-token (see
// api_token_flags.go); the flag wins when both are present.
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
	case "project", "target", "scope", "scan", "finding", "endpoint", "auth", "report", "config":
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
  serve          Run the web UI + API server (flags: -data, -addr, -v, -tls-cert/-tls-key for HTTPS; -api-token or $INDAGO_API_TOKEN enables API token authentication)

Client (talk to a running server; -server URL or $INDAGO_SERVER_URL, default http://127.0.0.1:8750; $INDAGO_CA_CERT = PEM CA file for a private/self-signed https server; -api-token or $INDAGO_API_TOKEN if the server requires a token):
  project create <name> | project list
  target add -project ID -name NAME -url URL | target list -project ID
  scope set -project ID -include host[,host] [-exclude ..] [-include-path ..] [-exclude-path ..] [-subdomains]
  scope show -project ID
  scan create -project ID -target ID [-name N] [-profile P] [-candidate-profile minimal|standard|thorough] [-max-candidates N] [-seed URL]... [-stop MODE [-stop-n N]]
              [-quick | -depth N] [-max-pages N] [-max-endpoints N] [-proxy URL]... [-randomize-tls-fingerprint]
              [-allow-insecure-tls]   (lab/staging only: accept a self-signed/hostname-mismatched HTTPS certificate; default strict)
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
  report create -scan <scan-id|prefix> -format json|markdown|html|sarif [-mode all|confirmed|selected] [-finding ID]... [-out FILE]
  report list -scan <scan-id|prefix> [-json]
  report show <report-id|prefix> [-out FILE] [-download]

Local configuration (reads/writes -data directly; no server needed):
  config llm set -provider deepseek|openai|custom -api-key KEY [-model M] [-base-url URL] [-data DIR]
                 (the key is stored 0600 under DIR/llm/; prefer $INDAGO_LLM_API_KEY over -api-key)
  config llm show|clear|test [-data DIR]
                 (test makes ONE small request to the configured provider; nothing else does)

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
	browserNoSandbox := fs.Bool("browser-no-sandbox", false,
		"launch -browser Chromium WITHOUT its process sandbox (--no-sandbox). The sandbox is ON by default; use only when the host cannot provide it (e.g. an unprivileged container). Lowers isolation from hostile pages")
	allowRemote := fs.Bool("allow-remote", false,
		"allow binding a non-loopback address; requires an API token (-api-token or INDAGO_API_TOKEN) and -tls-cert/-tls-key (see docs/deployment.md)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate file: serve HTTPS (a path, not the certificate value)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for -tls-cert (a path; the key is never printed or logged)")
	allowPlaintextRemote := fs.Bool("allow-plaintext-remote", false,
		"permit a non-loopback bind WITHOUT TLS: the bearer token then travels unencrypted, and a warning is logged")
	// The token is also read from INDAGO_API_TOKEN; this flag overrides it. A
	// flag value is visible in shell history and `ps`, so the environment
	// variable stays the recommended form for a long-lived service.
	var apiTokenFlag apiTokenFlagState
	apiTokenFlag.register(fs, apiTokenServeUsage())
	apiRate := fs.Float64("api-rate", config.DefaultAPIRate,
		"per-client-IP sustained requests/second on /api/ and /metrics; 0 disables (overrides config.json server.api_rate)")
	apiBurst := fs.Int("api-burst", config.DefaultAPIBurst,
		"per-client-IP burst size on /api/ and /metrics (overrides config.json server.api_burst)")
	aiProvider := fs.String("ai-provider", "", "enable the advisory AI Gateway with this provider (openai|anthropic|openrouter|ollama|vllm); empty keeps AI fully disabled")
	aiModel := fs.String("ai-model", "", "model name for -ai-provider (required if -ai-provider is set)")
	aiBaseURL := fs.String("ai-base-url", "", "override the provider's default base URL (required for a non-default ollama/vllm deployment)")
	oastAddr := fs.String("oast-addr", "",
		"start the built-in OAST collaborator on this address (host:port, e.g. 127.0.0.1:0 for an ephemeral port): one local listener that confirms out-of-band callbacks for SSRF/XXE/command injection automatically. Empty (default) starts nothing")
	oastPublicURL := fs.String("oast-public-url", "",
		"URL a TARGET can reach for -oast-addr (a tunnel or reverse proxy, e.g. https://abc.example-tunnel.net). Without it the callback base URL is the loopback listener, which only a target on this host can reach and which SSRF refuses as a canary")
	oastAllowExternalBind := fs.Bool("oast-allow-external-bind", false,
		"allow -oast-addr to bind a non-loopback address; the callback listener is then reachable beyond this host (readily flooded — see docs/oast.md)")
	allowPrivateOAST := fs.Bool("allow-private-oast", false,
		"let the SSRF engine use an OAST collaborator on a literal private (RFC 1918/ULA) address, e.g. a lab listener at 192.168.103.1:8751 for a target at 192.168.103.20. OFF by default: a canary there asks the target to request the operator's own LAN. Loopback, link-local/instance-metadata, unspecified, multicast and CGNAT collaborators stay refused regardless")
	_ = fs.Parse(args)
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	log := newLogger(*debug)

	browserCfg, err := browserConfigFromFlags(*useBrowser, *browserNoSandbox, *chromium)
	if err != nil {
		return err
	}
	oastCfg, wantOAST, err := oastConfigFromFlags(*oastAddr, *oastPublicURL, *oastAllowExternalBind)
	if err != nil {
		return err
	}

	// The API token is resolved once, here: -api-token wins over
	// $INDAGO_API_TOKEN. It is never written to config.json, never logged, and
	// never echoed in an error.
	apiToken, apiTokenSource, err := resolveAPIToken(apiTokenFlag, os.Getenv(apiTokenEnv))
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgPath(*dataDir))
	if err != nil {
		return err
	}
	cfg.DataDir = *dataDir
	// Capture the template before applying any transient serve overlays.
	stored := cfg
	if *addr != "" {
		cfg.Server.Addr = *addr
	}
	if cfg.Server, err = overlayRateLimitFlags(cfg.Server, setFlags, *apiRate, *apiBurst); err != nil {
		return err
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
	// Only initialize a missing template. Never rewrite an operator's config
	// (including formatting and fields unknown to this binary) at startup.
	if _, err := os.Stat(cfg.ConfigPath()); os.IsNotExist(err) {
		if err := stored.Save(cfg.ConfigPath()); err != nil {
			log.Warn("could not persist config", "err", err)
		}
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
		HTTP:             eng,
		HTTPConfig:       httpCfg,
		Evidence:         evStore,
		Executor:         scan.ExecutorConfig{AllowStateChanging: *allowUnsafe, AllowPrivateOAST: *allowPrivateOAST},
		SessionsDir:      cfg.SessionsDir(),
		Preflight:        true,
		AutoPauseOnBlock: true,
	}
	if *allowUnsafe {
		log.Warn("state-changing methods (POST/PUT/PATCH/DELETE) will be executed against in-scope targets")
	}
	if *allowPrivateOAST {
		log.Warn("SSRF may use an OAST collaborator on a private (RFC 1918/ULA) address; loopback, link-local/instance-metadata, unspecified, multicast and CGNAT collaborators stay refused")
	}
	// Built-in OAST collaborator. One listener + one loopback poll API for the
	// whole process: the scan controller hands their URLs to every engine that
	// confirms a vulnerability by callback (SSRF, XXE, command injection), so an
	// operator needs no third-party webhook account — and nothing is started at
	// all when -oast-addr is empty (the default).
	var oastMgr *oast.Manager // nil unless -oast-addr: /api/capabilities reports it
	if wantOAST {
		oastCfg.Logger = log
		mgr, oerr := oast.New(context.Background(), oastCfg)
		if oerr != nil {
			return fmt.Errorf("start OAST collaborator (-oast-addr): %w", oerr)
		}
		oastMgr = mgr
		defer func() { _ = oastMgr.Close() }()
		// Start the poll API now, not on the first scan: a listener that cannot
		// report its own hits is worse than none, and this is where the
		// operator can still see the failure.
		pollURL, perr := oastMgr.PollURL()
		if perr != nil {
			return fmt.Errorf("start OAST poll API: %w", perr)
		}
		opts.OAST = oastMgr
		log.Info("OAST collaborator listening",
			"callback", oastMgr.BaseURL(), "listen", oastMgr.ListenAddr(), "poll", pollURL)
		if oastCfg.PublicBaseURL == "" {
			log.Info("OAST: no -oast-public-url, so only a target on this host can reach the collaborator; " +
				"a remote target cannot call back to a loopback URL, and SSRF keeps its response-differential confirmation")
		}
	}
	var loginFn web.LoginFunc
	// bm is nil unless -browser. It is closed explicitly in the shutdown
	// sequence below; the deferred Close is the safety net for early returns
	// (Manager.Close is idempotent).
	var bm *browser.Manager
	if *useBrowser {
		mgr, err := browser.NewManager(browserCfg, log)
		if err != nil {
			return fmt.Errorf("start browser (-browser): %w", err)
		}
		bm = mgr
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
				AllowRequest:     p.AllowRequest,
				SuccessURLGlob:   p.SuccessURL,
				StorageStatePath: statePath,
				UserAgent:        p.UserAgent,
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
	// LLM provider settings are local-only: the store writes under the same
	// data directory (0600 files in a 0700 directory) and the web handlers
	// never return the key. Configuration-only: nothing here calls a provider.
	srv.SetLLMStore(llm.NewStore(filepath.Join(cfg.DataDir, "llm")))
	// Bug-bounty platform tokens live under the same data directory, 0600.
	srv.SetBountyStore(bounty.NewStore(filepath.Join(cfg.DataDir, "bounty")))
	// Claude OAuth (PKCE) is Indago-owned, like the ChatGPT session.
	srv.SetClaudeOAuthStore(filepath.Join(cfg.DataDir, "claude"))
	srv.SetLoginFunc(loginFn) // nil unless -browser: endpoint then reports unavailable
	// PDF export prints the HTML report through the same Chromium the browser
	// engine uses; absent an executable the endpoint reports unavailability
	// and every other report format keeps working.
	if p := web.ChromiumForPDF(*chromium); p != "" {
		srv.SetPDFRenderer(web.NewChromiumPDFRenderer(p, *browserNoSandbox))
	}
	// ChatGPT OAuth: Indago keeps its own session under the data directory so
	// an operator can log in once here instead of borrowing another tool's.
	srv.SetChatGPTCredDir(filepath.Join(cfg.DataDir, "chatgpt"))
	// Callback-confirmed engines (SSRF/XXE/command injection) only get their
	// collaborator when -oast-addr started one, and their silence must not read
	// as a clean result when it did not. BaseURL is the public URL when the
	// operator published one, otherwise the loopback listener.
	oastEnabled := oastMgr != nil
	var oastURL string
	if oastEnabled {
		oastURL = oastMgr.BaseURL()
	}
	srv.SetCapabilities(web.Capabilities{
		BrowserEnabled:       *useBrowser,
		BrowserSandbox:       *useBrowser && !*browserNoSandbox,
		StateChangingAllowed: *allowUnsafe,
		OASTEnabled:          oastEnabled,
		OASTCallbackURL:      oastURL,
		AllowPrivateOAST:     *allowPrivateOAST,
	})
	if err := srv.SetRateLimit(cfg.Server.APIRate, cfg.Server.APIBurst); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	if cfg.Server.APIRate > 0 {
		log.Info("api rate limit enabled", "rate_per_s", cfg.Server.APIRate, "burst", cfg.Server.APIBurst)
	} else {
		log.Warn("api rate limit DISABLED (-api-rate 0 or api_rate 0)")
	}
	if err := srv.SetAPIToken(apiToken); err != nil {
		return fmt.Errorf("%s: %w", apiTokenSource, err)
	}
	if apiToken != "" {
		log.Info("control API requires a bearer token", "source", apiTokenSource)
		if apiTokenSource == apiTokenFlagName {
			log.Warn("the API token was passed with " + apiTokenFlagName + ", which is visible in shell history and `ps`; prefer " + apiTokenEnv)
		}
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
	serveErr := srv.ListenAndServe(ctx, cfg.Server.Addr, tlsCfg)

	// Shutdown, in dependency order. ListenAndServe returns only after the HTTP
	// server stopped accepting connections and drained in-flight requests
	// (bounded at 5s inside serve). Workers stop next so no handler can touch
	// the browser or the store afterwards; Controller.Shutdown bounds each
	// scan's worker/browser pool at 30s. Then the browser manager (30s bound),
	// then the store last so its Close can checkpoint the WAL with nothing
	// writing. A wedged step is logged by the component that timed out; the
	// process still exits rather than hanging forever.
	if ctx.Err() != nil {
		log.Info("shutdown signal received; HTTP server drained")
	}
	start := time.Now()
	ctrl.Shutdown()
	log.Info("scan controller stopped", "dur", time.Since(start).Round(time.Millisecond))

	if bm != nil {
		start = time.Now()
		if cerr := bm.Close(); cerr != nil {
			log.Warn("browser manager close failed", "err", cerr)
		} else {
			log.Info("browser manager closed", "dur", time.Since(start).Round(time.Millisecond))
		}
	}

	start = time.Now()
	if cerr := db.Close(); cerr != nil {
		log.Warn("store closed with an incomplete WAL checkpoint; the -wal file holds the remaining pages", "err", cerr)
	} else {
		log.Info("store closed; WAL checkpointed", "dur", time.Since(start).Round(time.Millisecond))
	}
	return serveErr
}

// checkRemoteBindAllowed refuses a non-loopback bind unless the operator opts
// in with -allow-remote AND configures an API token (-api-token or
// INDAGO_API_TOKEN) AND serves TLS (-tls-cert/-tls-key). The control API can
// start scans, read findings and evidence (which may include captured session
// cookies), and generate reports; a remote bind without the token, or with the
// token in clear text, would expose all of that. The only way around the TLS
// requirement is -allow-plaintext-remote, which is allowed but returns a
// warning for the caller to log. Every refusal is an error, not a log line,
// which is easy to miss running as a daemon. The token value never appears in
// the returned error or warning.
func checkRemoteBindAllowed(addr string, allowRemote bool, token string, tlsOn, allowPlaintext bool) (warning string, err error) {
	if isLoopbackAddr(addr) {
		return "", nil
	}
	if !allowRemote {
		return "", fmt.Errorf("refusing to bind non-loopback address %q without -allow-remote; "+
			"a remote bind also requires an API token (-api-token or %s; the control API can start scans, read evidence, and generate reports) "+
			"and TLS (-tls-cert and -tls-key); see docs/deployment.md before exposing it beyond localhost", addr, apiTokenEnv)
	}
	if token == "" {
		return "", fmt.Errorf("refusing to bind non-loopback address %q with -allow-remote and no API token: "+
			"pass -api-token or set %s to a random token of at least %d characters (for example: openssl rand -hex 32); "+
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

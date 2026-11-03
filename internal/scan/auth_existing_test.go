package scan_test

// AuthExisting end to end through the Controller, without a browser: create-
// time validation, Start-time re-validation, HTTP-level session reuse
// (including after a restart), and the monitor pausing for re-authentication
// when the session material disappears mid-scan.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

// writeState writes a Playwright storage-state file holding one cookie for
// 127.0.0.1 and returns its absolute path.
func writeState(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "state.json")
	body := `{"cookies":[{"name":"sid","value":"s3cret","domain":"127.0.0.1","path":"/"}],"origins":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// authedSite counts every request, and those presenting the saved session
// cookie. /slow blocks until gate is closed, so a scan can be interrupted
// provably mid-run.
func authedSite(t *testing.T, total, authed *atomic.Int64, gate <-chan struct{}) *site {
	return newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			total.Add(1)
			if c, err := r.Cookie("sid"); err == nil && c.Value == "s3cret" {
				authed.Add(1)
			}
			switch r.URL.Path {
			case "/":
				writeHTML(w, `<a href="/slow">s</a>`)
			case "/slow":
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
				writeHTML(w, "ok")
			default:
				http.NotFound(w, r)
			}
		})
	})
}

func createAuthScan(ctx context.Context, c *scan.Controller, proj, tgt domain.ID, mode domain.AuthMode, statePath string) (*domain.Scan, error) {
	return c.CreateScan(ctx, scan.CreateScanParams{
		ProjectID: proj, TargetID: tgt, Name: "auth", Profile: domain.ProfileCustom,
		Config: workersCfg(2), AuthMode: mode, AuthStatePath: statePath,
	})
}

func TestCreateScanValidatesAuthConfiguration(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	dir := t.TempDir()
	good := writeState(t, dir)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	expired := filepath.Join(dir, "expired.json")
	if err := os.WriteFile(expired, []byte(stateWithCookie(1)), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		mode domain.AuthMode
		path string
	}{
		"existing without path":     {domain.AuthExisting, ""},
		"existing relative path":    {domain.AuthExisting, "state.json"},
		"existing missing file":     {domain.AuthExisting, filepath.Join(dir, "missing.json")},
		"existing malformed file":   {domain.AuthExisting, bad},
		"existing all-expired file": {domain.AuthExisting, expired},
		"anonymous with path":       {domain.AuthAnonymous, good},
		"unimplemented password":    {domain.AuthPassword, ""},
		"unimplemented interactive": {domain.AuthInteractive, ""},
		"unimplemented mfa":         {domain.AuthMFA, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := createAuthScan(ctx, ctrl, proj, tgt, tc.mode, tc.path); !errors.Is(err, scan.ErrAuth) {
				t.Fatalf("CreateScan = %v, want ErrAuth", err)
			}
		})
	}

	// Material whose cookies are all expired fails creation with a message
	// that says so, instead of starting a scan on dead credentials that would
	// quietly test the target unauthenticated.
	if _, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("CreateScan with all-expired material = %v, want an ErrAuth that says the cookies are expired", err)
	}

	sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, good)
	if err != nil {
		t.Fatalf("valid existing-session scan rejected: %v", err)
	}
	sess, err := st.Sessions().GetByScan(ctx, sc.ID)
	if err != nil || sess.Mode != domain.AuthExisting || sess.StatePath != good {
		t.Fatalf("session not persisted as configured: %+v (%v)", sess, err)
	}
}

func TestStartFailsWithErrAuthWhenStateRemovedAfterCreate(t *testing.T) {
	ctx := context.Background()
	s := standardSite(t)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	path := writeState(t, t.TempDir())
	sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(ctx, sc.ID); !errors.Is(err, scan.ErrAuth) {
		t.Fatalf("Start = %v, want ErrAuth", err)
	}
	got, _ := st.Scans().Get(ctx, sc.ID)
	if got.State != domain.ScanCreated {
		t.Fatalf("scan state = %s after a failed Start, want created (retryable)", got.State)
	}
	if s.hitCount("/") != 0 {
		t.Fatal("target contacted although the session could not be established")
	}
}

// The saved session cookie reaches the target on every HTTP-level request,
// including after a restart (Resume rebuilds the engine from the persisted
// session; it does not fall back to anonymous).
func TestExistingSessionReusedAcrossRestart(t *testing.T) {
	ctx := context.Background()
	var total, authed atomic.Int64
	gate := make(chan struct{})
	s := authedSite(t, &total, &authed, gate)
	dbPath := filepath.Join(t.TempDir(), "indago.db")
	state := writeState(t, t.TempDir())

	db, q := openSQLite(t, dbPath)
	proj, tgt := seedProject(t, db, s.URL, hostScope())
	ctrl1 := newCtrl(t, db, q, scan.Options{})
	sc, err := createAuthScan(ctx, ctrl1, proj, tgt, domain.AuthExisting, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl1.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	// Interrupt while discovery is provably parked on /slow.
	waitFor(t, 10*time.Second, func() bool { return s.hitCount("/slow") > 0 })
	ctrl1.Shutdown()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	beforeRestart := total.Load()
	close(gate)

	db2, q2 := openSQLite(t, dbPath)
	defer db2.Close()
	ctrl2 := newCtrl(t, db2, q2, scan.Options{})
	if _, err := ctrl2.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl2.RecoverScans(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ctrl2.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl2, sc.ID, 10*time.Second, isCompleted)

	if total.Load() <= beforeRestart {
		t.Fatal("setup: no requests after the restart")
	}
	if total.Load() != authed.Load() {
		t.Fatalf("%d of %d requests did not carry the imported session cookie", total.Load()-authed.Load(), total.Load())
	}
}

// Removing the session material mid-scan pauses the scan into AwaitingAuth —
// it must not quietly continue testing unauthenticated. Restoring it and
// resuming re-establishes the session.
func TestExistingSessionLossPausesForReauth(t *testing.T) {
	ctx := context.Background()
	gate := make(chan struct{})
	s := newSite(t, func(mux *http.ServeMux, _ func() string) {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			writeHTML(w, `<a href="/slow">s</a>`)
		})
		mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
			select { // keeps discovery (and so the scan) running until released
			case <-gate:
			case <-r.Context().Done():
			}
			writeHTML(w, "ok")
		})
	})
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	state := writeState(t, t.TempDir())
	sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanRunning })

	saved, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 3*time.Second, func(s *scan.Status) bool { return s.Scan.State == domain.ScanAwaitingAuth })
	sess, _ := st.Sessions().GetByScan(ctx, sc.ID)
	if sess.State != domain.SessionExpired {
		t.Fatalf("session state = %s, want expired", sess.State)
	}

	// Resume without the material fails clearly and leaves the scan waiting.
	if err := ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrAuth) {
		t.Fatalf("Resume without session material = %v, want ErrAuth", err)
	}
	if got, _ := st.Scans().Get(ctx, sc.ID); got.State != domain.ScanAwaitingAuth {
		t.Fatalf("scan state = %s after failed re-auth, want awaiting_auth", got.State)
	}

	if err := os.WriteFile(state, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	close(gate)
	waitStatus(t, ctrl, sc.ID, 10*time.Second, isCompleted)
}

// stateWithCookie renders a one-cookie Playwright storage state for the dummy
// session cookie authedSite checks for. expires is unix seconds; -1 means a
// session cookie.
func stateWithCookie(expires int64) string {
	return `{"cookies":[{"name":"sid","value":"s3cret","domain":"127.0.0.1","path":"/","expires":` +
		strconv.FormatInt(expires, 10) + `}],"origins":[]}`
}

// A saved session whose cookies have all expired is dead credentials: the
// monitor must move the scan to AwaitingAuth, stop sending target requests,
// refuse a Resume that still carries the expired material, and continue only
// once fresh material is in place.
func TestExistingExpiredCookiesPauseForReauth(t *testing.T) {
	ctx := context.Background()
	var total, authed atomic.Int64
	gate := make(chan struct{})
	s := authedSite(t, &total, &authed, gate)
	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, s.URL, hostScope())
	ctrl := newCtrl(t, st, q, scan.Options{})
	state := filepath.Join(t.TempDir(), "state.json")
	live := stateWithCookie(4102444800) // 2100
	expired := stateWithCookie(1)       // 1970
	if err := os.WriteFile(state, []byte(live), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Start(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	// The session's own expiry is now derived from the cookie, so the
	// controller's time check and the API can see it.
	sess, err := st.Sessions().GetByScan(ctx, sc.ID)
	if err != nil || sess.ExpiresAt == nil || sess.ExpiresAt.Unix() != 4102444800 {
		t.Fatalf("session expiry not derived from the saved cookie: %+v (%v)", sess, err)
	}
	// Discovery is provably parked on the gated /slow request: the scan is
	// running with work left to do.
	waitFor(t, 10*time.Second, func() bool { return s.hitCount("/slow") > 0 })

	// The operator's saved material is replaced by an all-expired state.
	if err := os.WriteFile(state, []byte(expired), 0o600); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, ctrl, sc.ID, 5*time.Second, func(st *scan.Status) bool {
		return st.Scan.State == domain.ScanAwaitingAuth
	})
	sess, _ = st.Sessions().GetByScan(ctx, sc.ID)
	if sess.State != domain.SessionExpired {
		t.Fatalf("session state = %s, want expired", sess.State)
	}

	// No further target requests while awaiting re-authentication: let any
	// in-flight request settle, then require a quiet window.
	time.Sleep(200 * time.Millisecond)
	settled := total.Load()
	time.Sleep(300 * time.Millisecond)
	if got := total.Load(); got != settled {
		t.Fatalf("%d target request(s) were sent while awaiting re-authentication", got-settled)
	}

	// Resuming with the same expired material fails clearly and leaves the
	// scan waiting — it must not quietly continue unauthenticated.
	if err := ctrl.Resume(ctx, sc.ID); !errors.Is(err, scan.ErrAuth) {
		t.Fatalf("Resume with expired material = %v, want ErrAuth", err)
	}
	if got, _ := st.Scans().Get(ctx, sc.ID); got.State != domain.ScanAwaitingAuth {
		t.Fatalf("scan state = %s after failed re-auth, want awaiting_auth", got.State)
	}

	// Fresh material lets Resume continue and the scan complete.
	if err := os.WriteFile(state, []byte(live), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Resume(ctx, sc.ID); err != nil {
		t.Fatalf("resume with fresh material: %v", err)
	}
	close(gate)
	waitStatus(t, ctrl, sc.ID, 10*time.Second, isCompleted)
	if total.Load() != authed.Load() {
		t.Fatalf("%d of %d requests were sent without the session", total.Load()-authed.Load(), total.Load())
	}
}

// Negative controls: material that is not knowably expired — a persistent
// cookie still in the future, a session cookie, or an origins-only state —
// must never pause the scan. AwaitingAuth never self-recovers, so a scan that
// reaches Completed proves the monitor never paused it.
func TestExistingLiveMaterialNeverPauses(t *testing.T) {
	cases := map[string]struct {
		body   string
		exp    int64
		authed bool
	}{
		"persistent future cookie": {stateWithCookie(4102444800), 4102444800, true},
		"session cookie":           {stateWithCookie(-1), 0, true},
		"origins only":             {`{"cookies":[],"origins":[]}`, 0, false},
		// All cookies stale, but origin storage may hold the real SPA token:
		// the monitor must not false-pause this scan.
		"expired cookies with origin localStorage": {
			`{"cookies":[{"name":"sid","value":"s3cret","domain":"127.0.0.1","path":"/","expires":1}],` +
				`"origins":[{"origin":"https://example.test","localStorage":[{"name":"dummy","value":"dummy"}]}]}`,
			0, false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			var total, authed atomic.Int64
			gate := make(chan struct{})
			close(gate) // nothing blocks: the scan can run to completion
			s := authedSite(t, &total, &authed, gate)
			st, q := memory.New(), queue.NewMemory()
			proj, tgt := seedProject(t, st, s.URL, hostScope())
			ctrl := newCtrl(t, st, q, scan.Options{})
			state := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(state, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			sc, err := createAuthScan(ctx, ctrl, proj, tgt, domain.AuthExisting, state)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if err := ctrl.Start(ctx, sc.ID); err != nil {
				t.Fatalf("start: %v", err)
			}
			waitStatus(t, ctrl, sc.ID, 10*time.Second, isCompleted)

			sess, err := st.Sessions().GetByScan(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.exp == 0 {
				if sess.ExpiresAt != nil {
					t.Fatalf("session ExpiresAt = %v, want nil", sess.ExpiresAt)
				}
			} else if sess.ExpiresAt == nil || sess.ExpiresAt.Unix() != tc.exp {
				t.Fatalf("session ExpiresAt = %v, want %d", sess.ExpiresAt, tc.exp)
			}
			if tc.authed && total.Load() != authed.Load() {
				t.Fatalf("%d of %d requests did not carry the saved cookie", total.Load()-authed.Load(), total.Load())
			}
		})
	}
}

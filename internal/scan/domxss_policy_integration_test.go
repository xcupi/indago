//go:build browser_integration

package scan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/ratelimit"
)

func TestDOMPolicyEveryNavigationSharesScanPacing(t *testing.T) {
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	var arrivals atomic.Int64
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		fmt.Fprint(w, "<!doctype html><p>safe</p>")
	}))
	defer lab.Close()
	env := newScanEnv(t)
	c := &Controller{store: env.st, opts: Options{Browser: mgr}, log: execLog()}
	lim := ratelimit.New(1)
	ex := c.defaultHandlers(nil, sourceSelectionScope(t, lab.URL), nil, lim)[domain.JobDOMXSS].(*domXSSExecutor)
	bc, err := mgr.NewContext(context.Background(), browser.ContextOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	ep := env.endpoint(lab.URL, domain.MethodGET)
	for _, source := range detection.DOMXSSSources {
		t.Run(string(source), func(t *testing.T) {
			lim.SetRate(1)
			if err := lim.Wait(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			before := arrivals.Load()
			_, _, _, _, _, err := ex.navigateSource(ctx, bc, source, ep, "key", "POLICY_MARKER", "inert")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("navigation bypassed shared pacing: %v", err)
			}
			if arrivals.Load() != before {
				t.Fatal("target request sent without a scan permit")
			}
		})
	}
	t.Run("storage observation", func(t *testing.T) {
		lim.SetRate(1)
		if err := lim.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := ex.discoverStorageKeys(ctx, bc, detection.DOMSourceLocalStorage, lab.URL)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("storage discovery bypassed shared pacing: %v", err)
		}
	})
}

func TestDOMPolicyProxySessionReferrerAndScope(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Chromium's own connectivity check is not target traffic. Never tunnel it.
		if r.Method == http.MethodConnect {
			http.Error(w, "lab proxy does not tunnel", http.StatusBadGateway)
			return
		}
		mu.Lock()
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/allowed" && r.Header.Get("Cookie") != "dummy=policy" {
			http.Error(w, "missing dummy session", 403)
			return
		}
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>document.getElementById('sink').innerHTML=decodeURIComponent(document.referrer); fetch('/denied');</script>`)
	}))
	defer proxy.Close()
	mgr := newSourceSelectionBrowser(t)
	defer mgr.Close()
	env := newScanEnv(t)
	state := filepath.Join(t.TempDir(), "dummy-state.json")
	if err := os.WriteFile(state, []byte(`{"cookies":[{"name":"dummy","value":"policy","domain":"dom-policy.invalid","path":"/allowed","expires":-1,"httpOnly":true,"secure":false,"sameSite":"Lax"}],"origins":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Sessions().Create(context.Background(), &domain.Session{ID: domain.NewID(), ScanID: env.scanID, StatePath: state}); err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{IncludeHosts: []string{"dom-policy.invalid"}, IncludePathPrefixes: []string{"/allowed"}}
	c := &Controller{store: env.st, opts: Options{Browser: mgr, Evidence: env.ev}, log: execLog()}
	ex := c.defaultHandlers(nil, scope, []string{proxy.URL}, ratelimit.New(0))[domain.JobDOMXSS]
	ep := env.endpoint("http://dom-policy.invalid/allowed", domain.MethodGET)
	if err := ex.Handle(context.Background(), sourceSelectionJob(t, env.scanID, ep, string(detection.DOMSourceReferrer))); err != nil {
		t.Fatal(err)
	}
	fs := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	if len(fs) != 1 || fs[0].Verdict != domain.VerdictConfirmed || len(fs[0].EvidenceIDs) == 0 || !strings.Contains(fs[0].Summary, "is not defined") {
		t.Fatalf("proxy/session/referrer confirmation with evidence missing: %+v", fs)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) < 2 {
		t.Fatalf("proxy was not used for both phases: %v", requests)
	}
	for _, path := range requests {
		if path != "/allowed" {
			t.Fatalf("out-of-scope network request reached proxy: %q", path)
		}
	}
}

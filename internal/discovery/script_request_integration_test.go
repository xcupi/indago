package discovery_test

// Real-browser check for the static script-request harvest: a page whose XML
// call only fires on a button click is never observed by network capture, yet
// its endpoint and body must still be registered. Runs by default and skips
// (quickly) when no Chromium is available or when -short is set.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

type countingHandler struct {
	hits atomic.Int32
	body string
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.hits.Add(1)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	_, _ = w.Write([]byte(c.body))
}

func discoveryChromiumOrSkip(t *testing.T) *browser.Manager {
	t.Helper()
	if testing.Short() {
		t.Skip("real-browser test skipped in -short mode")
	}
	exe := os.Getenv("INDAGO_CHROMIUM_PATH")
	if exe == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			matches, _ := filepath.Glob(filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"))
			sort.Strings(matches)
			if len(matches) > 0 {
				exe = matches[len(matches)-1]
			}
		}
	}
	if exe == "" {
		t.Skip("no Chromium found (set INDAGO_CHROMIUM_PATH or `playwright install chromium`)")
	}
	m, err := browser.NewManager(browser.Config{Headless: true, ExecutablePath: exe, PoolSize: 1}, nil)
	if err != nil {
		t.Skipf("browser engine unavailable: %v", err)
	}
	return m
}

func TestBrowserDiscoveryRegistersClickOnlyXMLRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/xxe-1.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(`<html><body>
<p>Reset your secret to <input type="button" onclick="ResetSecret();" value="Any bugs?"></p>
<script type="text/javascript">
function ResetSecret()
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("POST","xxe-2.php",true);
    xmlHttp.setRequestHeader("Content-type","text/xml; charset=UTF-8");
    xmlHttp.send("<reset><login>bee</login><secret>Any bugs?</secret></reset>");
}
</script>
</body></html>`))
	})
	sink := &countingHandler{body: "reset"}
	mux.Handle("/xxe-2.php", sink)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	br := discoveryChromiumOrSkip(t)
	defer br.Close()

	cfg := discovery.DefaultConfig()
	registry := discovery.NewRegistry()
	registry.Register(discovery.NewNetworkSource(br, cfg))
	st, q := memory.New(), queue.NewMemory()
	manager := discovery.NewManager(st, q, registry, cfg, quiet())
	scanID := domain.NewID()
	if _, err := manager.Run(context.Background(), discovery.RunParams{ScanID: scanID, Scope: scopeFor(srv), SeedURLs: []string{srv.URL + "/xxe-1.php"}}); err != nil {
		t.Fatalf("run discovery: %v", err)
	}

	var xmlEndpoint *domain.Endpoint
	endpoints, err := st.Endpoints().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range endpoints {
		if ep.URL == srv.URL+"/xxe-2.php" {
			xmlEndpoint = ep
			break
		}
	}
	if xmlEndpoint == nil {
		t.Fatalf("click-only XHR endpoint not registered: %+v", endpoints)
	}
	if xmlEndpoint.Method != domain.MethodPOST || xmlEndpoint.ContentType != "text/xml; charset=UTF-8" || xmlEndpoint.RequestBody == "" {
		t.Fatalf("registered endpoint lost its declared shape: %+v", xmlEndpoint)
	}
	// The harvest is static: the browser never clicked the button, so the
	// target itself must not have been requested during discovery.
	if hits := sink.hits.Load(); hits != 0 {
		t.Fatalf("discovery requested the declared endpoint %d times; it must only register it", hits)
	}
}

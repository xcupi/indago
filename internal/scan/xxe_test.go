package scan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
)

func TestXXEConfirmsExternalEntityCallback(t *testing.T) {
	var callbackMu sync.Mutex
	var callbackPath string
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/poll" {
			callbackMu.Lock()
			path := callbackPath
			callbackMu.Unlock()
			if path == "" {
				fmt.Fprint(w, "[]")
				return
			}
			fmt.Fprintf(w, `{"callback":%q}`, path)
			return
		}
		callbackMu.Lock()
		callbackPath = r.URL.Path
		callbackMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer callback.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<20)
		n, _ := r.Body.Read(body)
		request := string(body[:n])
		if m := regexp.MustCompile(`SYSTEM "([^"]+)"`).FindStringSubmatch(request); m != nil {
			_, _ = http.Get(m[1])
		}
		fmt.Fprint(w, "<result>ok</result>")
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/stock",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml",
		RequestBody: `<stockCheck><productId>1</productId></stockCheck>`, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)
	ex.withCallback(callback.URL, callback.URL+"/poll")
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobXXE,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnXXE || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed XXE", findings)
	}
}

func TestXXESkipsNonXMLBodyWithoutPayload(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/json",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/json",
		RequestBody: `{"id":1}`, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)
	ex.withCallback("http://127.0.0.1:1", "http://127.0.0.1:1/poll")
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobXXE,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("JSON endpoint received %d XXE requests, want 0", got)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].VulnClass != domain.VulnXXE || cases[0].Status != domain.TestCaseSkipped {
		t.Fatalf("cases = %+v, want one skipped XXE case", cases)
	}
}

func TestInjectXXEAddsEntityToXMLBody(t *testing.T) {
	got, ok := injectXXE(`<root><value>1</value></root>`, "http://example.test/marker")
	if !ok || !strings.Contains(got, "<!DOCTYPE root") || !strings.Contains(got, "&xxe;") {
		t.Fatalf("injectXXE = %q, ok=%v", got, ok)
	}
}

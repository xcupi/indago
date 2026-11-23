package scan_test

// QA bug 2, end to end: a scan with no wordlist recon (the conservative default)
// must still discover /graphql and actually run the GraphQL engine. A GraphQL
// API is a single POST URL that nothing links to, so if discovery does not probe
// the conventional path the engine never receives a target and silently never
// runs — which is what QA measured against DVGA with -profile conservative.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/scan"
	"github.com/indago/indago/internal/store/memory"
)

func TestConservativeScanRunsGraphQLEngineOnWellKnownPath(t *testing.T) {
	if testing.Short() {
		t.Skip("full-scan integration test skipped in -short mode")
	}

	var mu sync.Mutex
	graphQLRequests := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// DVGA's shape: one page that links nowhere useful, and a GraphQL API at
	// /graphql. Nothing in the HTML points at it.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, `<html><body><h1>Damn Vulnerable GraphQL Application</h1><p>menu</p></body></html>`)
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		graphQLRequests++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		document := r.URL.Query().Get("query")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			document = string(body)
		}
		if strings.Contains(document, "__schema") {
			// Introspection is enabled: only the schema's type names are read.
			_, _ = io.WriteString(w, `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Post"}]}}}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
	})

	st, q := memory.New(), queue.NewMemory()
	proj, tgt := seedProject(t, st, srv.URL, hostScope())
	cfg := &domain.ScanConfig{
		DiscoveryConcurrency: 2, HTTPConcurrency: 4, BrowserConcurrency: 0,
		// No ReconLevel: the conservative default, no wordlist requests at all.
		MaxDepth: 1,
		// Isolate the assertion: only the GraphQL engine matters here.
		SkipDOMXSS: true, SkipAccessControl: true, SkipIDOR: true,
		SkipInfoDisclosure: true, SkipSSRF: true, SkipCORS: true, SkipOpenRedirect: true,
	}
	ctrl := newCtrl(t, st, q, scan.Options{})
	sc := createScan(t, ctrl, proj, tgt, cfg, domain.StopPolicy{})
	if err := ctrl.Start(context.Background(), sc.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitStatus(t, ctrl, sc.ID, 90*time.Second, isCompleted)

	ctx := context.Background()
	eps, err := st.Endpoints().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	discovered := false
	for _, e := range eps {
		if e != nil && strings.HasSuffix(e.URL, "/graphql") {
			discovered = true
			break
		}
	}
	if !discovered {
		var got []string
		for _, e := range eps {
			got = append(got, string(e.Method)+" "+e.URL)
		}
		t.Fatalf("/graphql was not discovered on a scan with no wordlist recon; endpoints: %v", got)
	}

	cases, err := st.TestCases().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("list test cases: %v", err)
	}
	ran, skipNote := false, ""
	for _, tc := range cases {
		if tc == nil || tc.VulnClass != domain.VulnGraphQL {
			continue
		}
		switch tc.Status {
		case domain.TestCaseCompleted:
			ran = true
		case domain.TestCaseSkipped:
			skipNote = tc.Note
		}
	}
	if !ran {
		t.Fatalf("the GraphQL engine never ran (skipped note: %q)", skipNote)
	}

	findings, err := st.Findings().ListByScan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	observed := false
	for _, f := range findings {
		if f != nil && f.VulnClass == domain.VulnGraphQL && f.Verdict == domain.VerdictInconclusive {
			observed = true
			break
		}
	}
	if !observed {
		var got []string
		for _, f := range findings {
			got = append(got, string(f.VulnClass)+"/"+string(f.Verdict))
		}
		t.Fatalf("no GraphQL feature observation from the discovered endpoint; findings: %v", got)
	}

	mu.Lock()
	n := graphQLRequests
	mu.Unlock()
	if n == 0 {
		t.Fatal("no request ever reached the fake GraphQL API")
	}
}

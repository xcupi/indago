package scan

// Executor tests for cases 38/39: the classification runs against real servers,
// and a surface that discloses nothing must produce no finding.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func runDisclosureJob(t *testing.T, target string) (*scanEnv, []*domain.Finding, *domain.TestCase) {
	t.Helper()
	env := newScanEnv(t)
	ep := acEndpoint(t, env, target, domain.SourceContentDiscovery, domain.MethodGET)
	ex := newDisclosureExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), &sync.Mutex{})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobDisclosure,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: target}, MaxAttempts: 1}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (%v), want 1", len(cases), err)
	}
	return env, env.findings(), cases[0]
}

func TestDisclosureConfirmsDebugPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.4.33</h1>
<table><tr><td>Configuration File (php.ini) Path</td><td>/etc/php/7.4/cli</td></tr>
<tr><td>SECRET_KEY</td><td>abc123</td></tr></table>
<h1>PHP Credits</h1></body></html>`)
	}))
	defer srv.Close()

	_, findings, tc := runDisclosureJob(t, srv.URL+"/cgi-bin/phpinfo.php")
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}
	f := findings[0]
	if f.VulnClass != domain.VulnInfoDisclosure || f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("finding = %s/%s, want information_disclosure/confirmed", f.VulnClass, f.Verdict)
	}
	if f.Severity != domain.SeverityHigh {
		t.Fatalf("severity = %s, want high for a dump that carries a secret key", f.Severity)
	}
	if len(f.EvidenceIDs) == 0 || len(tc.EvidenceIDs) == 0 {
		t.Fatal("the finding and its test case must reference the stored request/response")
	}
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("test case status = %s", tc.Status)
	}
}

func TestDisclosureConfirmsBackupSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backup/ProductTemplate.java.bak" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "package com.example;\n\nimport java.sql.*;\n\npublic class ProductTemplate {\n  private static final String DB_PASSWORD = \"s3cr3t\";\n}\n")
	}))
	defer srv.Close()

	_, findings, _ := runDisclosureJob(t, srv.URL+"/backup/ProductTemplate.java.bak")
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnInfoDisclosure {
		t.Fatalf("findings = %+v, want one information_disclosure finding", findings)
	}
}

func TestDisclosurePageThatDisclosesNothingIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Debug</h1><p>Nothing to see here.</p></body></html>`)
	}))
	defer srv.Close()

	_, findings, tc := runDisclosureJob(t, srv.URL+"/debug")
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
	if tc.Status != domain.TestCaseCompleted || tc.Outcome != domain.OutcomeSuccess {
		t.Fatalf("case = %s/%s, want a completed success with no finding", tc.Status, tc.Outcome)
	}
}

func TestDisclosureNotFoundIsNotAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<?php echo "not found"; ?>`)
	}))
	defer srv.Close()

	_, findings, _ := runDisclosureJob(t, srv.URL+"/x.php.bak")
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a 404", findings)
	}
}

// The crawler ignores commented-out markup; the disclosure pass must not.
func TestDisclosureFollowsCommentedDebugLink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>store front<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> --></body></html>`)
	})
	mux.HandleFunc("/cgi-bin/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4</h1>
<p>Configuration File (php.ini) Path /etc/php.ini</p><h1>PHP Credits</h1>
<p>SECRET_KEY s3cr3t</p></body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, findings, _ := runDisclosureJob(t, srv.URL+"/")
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnInfoDisclosure {
		t.Fatalf("findings = %+v, want one for the commented debug link", findings)
	}
}

// An open directory listing names the backup artefact; the pass must read it.
func TestDisclosureFollowsDirectoryListing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Index of /backup</title></head><body><table>
<tr><td><a href='/backup/ProductTemplate.java.bak'>ProductTemplate.java.bak</a></td></tr></table></body></html>`)
	})
	mux.HandleFunc("/backup/ProductTemplate.java.bak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "package com.example;\nimport java.sql.*;\npublic class ProductTemplate { static final String DB_PASSWORD = \"s3cr3t\"; }\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, findings, _ := runDisclosureJob(t, srv.URL+"/backup")
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnInfoDisclosure {
		t.Fatalf("findings = %+v, want one for the listed backup artefact", findings)
	}
}

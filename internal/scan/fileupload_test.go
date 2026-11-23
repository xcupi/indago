package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/queue"
	"github.com/indago/indago/internal/store/memory"
)

func fileUploadJob(env *scanEnv, ep *domain.Endpoint) *domain.TestJob {
	env.t.Helper()
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobFileUpload,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2,
	}
}

func runFileUpload(t *testing.T, env *scanEnv, ep *domain.Endpoint, cfg ExecutorConfig) *domain.TestCase {
	t.Helper()
	ex := newFileUploadExecutor(env.st, scopedClient(t, openScope()), env.ev, cfg, execLog(), nil)
	if err := ex.Handle(context.Background(), fileUploadJob(env, ep)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("test cases = %d, want 1", len(cases))
	}
	return cases[0]
}

func fileUploadDetailOf(t *testing.T, tc *domain.TestCase) fileUploadDetail {
	t.Helper()
	var d fileUploadDetail
	if err := json.Unmarshal(tc.Detail, &d); err != nil {
		t.Fatalf("unmarshal detail: %v (%s)", err, string(tc.Detail))
	}
	return d
}

func TestFileUploadGatedWithoutAllowStateChanging(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/api/upload", domain.MethodPOST)
	tc := runFileUpload(t, env, ep, ExecutorConfig{AllowStateChanging: false})

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("target hits = %d, want 0 when AllowStateChanging is false", got)
	}
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %q, want skipped", tc.Status)
	}
	if !strings.Contains(tc.Note, "AllowStateChanging") {
		t.Fatalf("skip note = %q, want AllowStateChanging", tc.Note)
	}
	if d := fileUploadDetailOf(t, tc); !d.Skipped {
		t.Fatalf("detail = %+v, want Skipped=true", d)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestFileUploadVulnerableEndpointConfirmedAndRedacted(t *testing.T) {
	const secret = "supersecret-upload-session-token"
	var sawControl, sawSVG, sawPHPJPG bool
	var gotCookie string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		var filename, partCT string
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, "multipart read error", http.StatusBadRequest)
				return
			}
			if part.FileName() != "" {
				filename = part.FileName()
				partCT = part.Header.Get("Content-Type")
			}
			_ = part.Close()
		}

		switch {
		case strings.HasSuffix(filename, ".txt") && partCT == "text/plain":
			sawControl = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"ok":true,"path":"/uploads/%s"}`, filename)
		case strings.HasSuffix(filename, ".svg") && partCT == "image/svg+xml":
			sawSVG = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"ok":true,"path":"/uploads/%s"}`, filename)
		case strings.HasSuffix(filename, ".html"):
			http.Error(w, "html not allowed", http.StatusUnsupportedMediaType)
		case strings.HasSuffix(filename, ".php.jpg") && partCT == "image/jpeg":
			sawPHPJPG = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"ok":true,"file":"%s"}`, filename)
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	statePath := writeCSRFStorageState(t, srv.URL, "sid", secret, "Lax")
	now := time.Now()
	if err := env.st.Sessions().Create(context.Background(), &domain.Session{
		ID: domain.NewID(), ScanID: env.scanID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: statePath, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	ep := env.endpoint(srv.URL+"/api/avatar", domain.MethodPOST)
	env.param(ep, "avatar", domain.LocationForm, "")

	tc := runFileUpload(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	if !sawControl || !sawSVG || !sawPHPJPG {
		t.Fatalf("probes seen: control=%v svg=%v php.jpg=%v, want all true", sawControl, sawSVG, sawPHPJPG)
	}
	if !strings.Contains(gotCookie, secret) {
		t.Fatalf("Cookie = %q, want session cookie to be sent", gotCookie)
	}

	d := fileUploadDetailOf(t, tc)
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q, want confirmed (reason: %s)", d.Verdict, d.Reason)
	}
	if d.ControlStatus != http.StatusCreated {
		t.Fatalf("ControlStatus = %d, want 201", d.ControlStatus)
	}
	if len(d.AcceptedProbes) != 2 {
		t.Fatalf("AcceptedProbes = %v, want [.svg .php.jpg]", d.AcceptedProbes)
	}
	if len(d.RejectedProbes) != 1 || d.RejectedProbes[0] != ".html" {
		t.Fatalf("RejectedProbes = %v, want [.html]", d.RejectedProbes)
	}

	findings := scanFindings(t, env)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].VulnClass != domain.VulnFileUpload {
		t.Fatalf("VulnClass = %q, want %q", findings[0].VulnClass, domain.VulnFileUpload)
	}
	if findings[0].Verdict != domain.VerdictInconclusive {
		t.Fatalf("finding Verdict = %q, want inconclusive", findings[0].Verdict)
	}

	if len(tc.EvidenceIDs) == 0 {
		t.Fatal("expected request/response evidence to be persisted")
	}
	for _, evID := range tc.EvidenceIDs {
		evMeta, err := env.st.Evidence().Get(context.Background(), evID)
		if err != nil {
			t.Fatal(err)
		}
		rc, err := env.ev.Open(evMeta.BlobPath)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), secret) {
			t.Fatalf("evidence blob %s leaked raw cookie value:\n%s", evID, string(blob))
		}
	}
}

func TestFileUploadProtectedEndpointRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		var filename string
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, "bad part", http.StatusBadRequest)
				return
			}
			if part.FileName() != "" {
				filename = part.FileName()
			}
			_ = part.Close()
		}
		switch {
		case strings.HasSuffix(filename, ".txt"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasSuffix(filename, ".svg"), strings.HasSuffix(filename, ".html"):
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		case strings.HasSuffix(filename, ".php.jpg"):
			http.Error(w, "double extension not allowed", http.StatusBadRequest)
		default:
			http.Error(w, "rejected", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/upload", domain.MethodPOST)
	tc := runFileUpload(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	d := fileUploadDetailOf(t, tc)
	if d.Verdict != domain.VerdictRejected {
		t.Fatalf("verdict = %q, want rejected", d.Verdict)
	}
	if len(d.AcceptedProbes) != 0 {
		t.Fatalf("AcceptedProbes = %v, want empty", d.AcceptedProbes)
	}
	if len(d.RejectedProbes) != 3 {
		t.Fatalf("RejectedProbes = %v, want 3", d.RejectedProbes)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestFileUploadThrottledInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	env := newScanEnv(t)
	ep := env.endpoint(srv.URL+"/upload", domain.MethodPOST)
	tc := runFileUpload(t, env, ep, ExecutorConfig{AllowStateChanging: true})

	d := fileUploadDetailOf(t, tc)
	if !d.Throttled {
		t.Fatalf("detail = %+v, want Throttled=true", d)
	}
	if d.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict = %q, want inconclusive", d.Verdict)
	}
	if got := scanFindings(t, env); len(got) != 0 {
		t.Fatalf("findings = %d, want 0", len(got))
	}
}

func TestEnqueueFileUploadProbes(t *testing.T) {
	for _, tc := range []struct {
		name           string
		skipFileUpload bool
		want           int
	}{
		{name: "enabled caps at maxFileUploadEndpoints", skipFileUpload: false, want: maxFileUploadEndpoints},
		{name: "respects SkipFileUpload", skipFileUpload: true, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, q := memory.New(), queue.NewMemory()
			now := time.Now()
			sc := &domain.Scan{
				ID: domain.NewID(), ProjectID: domain.NewID(), State: domain.ScanCreated,
				Config: domain.ScanConfig{SkipFileUpload: tc.skipFileUpload}, CreatedAt: now, UpdatedAt: now,
			}
			if err := st.Scans().Create(ctx, sc); err != nil {
				t.Fatal(err)
			}

			// Non-state-changing or non-upload endpoints must be skipped.
			for _, ep := range []*domain.Endpoint{
				{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/upload", Method: domain.MethodGET, Source: domain.SourceCrawler, CreatedAt: now},
				{ID: domain.NewID(), ScanID: sc.ID, URL: "https://app.example.test/api/profile", Method: domain.MethodPOST, ContentType: "application/json", Source: domain.SourceCrawler, CreatedAt: now},
			} {
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}

			// Create 20 upload-shaped endpoints (multipart ContentType, upload path, or upload param)
			// to verify the 15-endpoint cap.
			for i := 0; i < 20; i++ {
				ep := &domain.Endpoint{
					ID: domain.NewID(), ScanID: sc.ID,
					URL:    fmt.Sprintf("https://app.example.test/api/items/%d/upload", i),
					Method: domain.MethodPOST, Source: domain.SourceCrawler, CreatedAt: now,
				}
				if i == 0 {
					ep.URL = "https://app.example.test/api/items/0/submit"
					ep.ContentType = "multipart/form-data; boundary=abc"
				}
				if err := st.Endpoints().Create(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}

			ctrl := NewController(st, q, execLog(), filepath.Join(t.TempDir(), "test"), Options{})
			t.Cleanup(ctrl.Shutdown)
			ctrl.enqueueFileUploadProbes(ctx, sc.ID)

			jobs, err := q.Jobs(ctx, sc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != tc.want {
				t.Fatalf("jobs = %d, want %d", len(jobs), tc.want)
			}
			for _, job := range jobs {
				if job.Type != domain.JobFileUpload || job.Priority != fileUploadPriority {
					t.Fatalf("unexpected job type/priority: %+v", job)
				}
			}
		})
	}
}

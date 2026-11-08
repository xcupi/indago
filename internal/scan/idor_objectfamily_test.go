package scan

// Case 34: a page's own scripts name both the endpoint that CREATES an object
// and the field that carries it; the scan submits its own marker, reads the
// object the server names, and probes the neighbouring ids.
//
// The fixture mirrors the lab exactly: /chat posts a transcript, the server
// answers 302 -> /download-transcript/2.txt (the caller's own object), and
// /download-transcript/1.txt is somebody else's transcript with a password.
// The negative fixture has a sibling that is a different document but discloses
// nothing — that must stay Inconclusive.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/idor"
)

func objectFamilyServer(t *testing.T, siblingBody string) http.HandlerFunc {
	var mu sync.Mutex
	own := ""
	n := 1
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/chat":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script src="/resources/js/viewTranscript.js"></script><script>viewTranscript('/download-transcript')</script></body></html>`)
		case r.URL.Path == "/resources/js/viewTranscript.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `function viewTranscript(p){ var xhr=new XMLHttpRequest(); xhr.open("POST", p); var data=new FormData(); data.append("transcript", "x"); xhr.send(data); }`)
		case r.URL.Path == "/download-transcript" && r.Method == http.MethodPost:
			_ = r.ParseForm()
			mu.Lock()
			n++
			own = r.PostForm.Get("transcript")
			id := n
			mu.Unlock()
			w.Header().Set("Location", fmt.Sprintf("/download-transcript/%d.txt", id))
			w.WriteHeader(http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/download-transcript/"):
			name := strings.TrimPrefix(r.URL.Path, "/download-transcript/")
			mu.Lock()
			mine := own
			mu.Unlock()
			if name == "2.txt" {
				fmt.Fprint(w, "CONNECTED: -- Now chatting with Hal Pline --\nYou: "+mine+"\n")
				return
			}
			if name == "1.txt" && siblingBody != "" {
				fmt.Fprint(w, siblingBody)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `"No transcript"`)
		default:
			http.NotFound(w, r)
		}
	}
}

func runObjectFamilyJob(t *testing.T, target string) (*scanEnv, idorDetail, []*domain.Finding) {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(target, domain.MethodGET)
	ex := newIDORExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil, nil, idor.EnumerationOptions{})
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobIDOR,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: target}, MaxAttempts: 1,
		Payload: idorModePayload(idorModeObjectFamily)}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("test cases = %d (%v), want 1", len(cases), err)
	}
	return env, idorDecision(t, cases[0]), env.findings()
}

func TestObjectFamilyConfirmsCredentialSibling(t *testing.T) {
	srv := httptest.NewServer(objectFamilyServer(t, "CONNECTED: -- Now chatting with Hal Pline --\nYou: Ok so my password is 8au5aj8yoahk0x1ewp9y. Is that right?\n"))
	defer srv.Close()

	_, d, findings := runObjectFamilyJob(t, srv.URL+"/chat")
	if d.Verdict != domain.VerdictConfirmed {
		t.Fatalf("verdict = %q (%s), want confirmed", d.Verdict, d.Reason)
	}
	if !d.ObjectFamily || d.ObjectField != "transcript" {
		t.Fatalf("detail = %+v, want object_family with field transcript", d)
	}
	if !strings.HasSuffix(d.OwnObject, "/download-transcript/2.txt") {
		t.Fatalf("own object = %q, want the redirect target the server named", d.OwnObject)
	}
	if !strings.Contains(d.Reason, "disclosing a password") {
		t.Fatalf("reason should name the credential: %q", d.Reason)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnIDOR || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed idor finding", findings)
	}
	if len(findings[0].EvidenceIDs) == 0 {
		t.Fatal("the confirmed finding must reference evidence")
	}
}

func TestObjectFamilyWithoutCredentialStaysInconclusive(t *testing.T) {
	srv := httptest.NewServer(objectFamilyServer(t, "CONNECTED: -- Now chatting with Hal Pline --\nYou: hello there\n"))
	defer srv.Close()

	_, d, findings := runObjectFamilyJob(t, srv.URL+"/chat")
	if d.Verdict == domain.VerdictConfirmed {
		t.Fatalf("a sibling with no credential must never be confirmed: %s", d.Reason)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestObjectFamilyWithoutScriptEndpointSkips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>no scripts here</body></html>`)
	}))
	defer srv.Close()

	_, d, findings := runObjectFamilyJob(t, srv.URL+"/chat")
	if !d.Skipped {
		t.Fatalf("detail = %+v, want a skip when the page names no endpoint", d)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

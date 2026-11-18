package scan

// Fingerprint-gated SSTI applicability.
//
// The SSTI engine asks internal/fingerprint whether template probing is worth a
// request for THIS injection point and, when it is, which payload shape to try
// first. These tests cover both directions of that gate: a response the server
// cannot render as a template is skipped without a single payload, and a
// template-capable stack is probed with its own syntax ahead of every other
// shape.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/indago/indago/internal/domain"
)

// sstiProbeLog records the q value of every request the fixture received that
// was not the baseline, in arrival order.
type sstiProbeLog struct {
	mu       sync.Mutex
	payloads []string
}

func (l *sstiProbeLog) add(q string) {
	if q == "" || q == "hello" {
		return // the baseline, not a probe
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.payloads = append(l.payloads, q)
}

func (l *sstiProbeLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.payloads))
	copy(out, l.payloads)
	return out
}

// runSSTIFingerprintJob drives the SSTI engine once against endpointURL (a full URL with
// ?q=hello) and returns the recorded detail plus the single test case.
func runSSTIFingerprintJob(t *testing.T, endpointURL string) (*sstiDetail, *domain.TestCase) {
	t.Helper()
	env := newScanEnv(t)
	ep := env.endpoint(endpointURL, domain.MethodGET)
	focus := env.param(ep, "q", domain.LocationQuery, "hello")
	ip := env.injection(ep, focus)
	ex := newSSTIExecutor(env.st, scopedClient(t, openScope()), env.ev, ExecutorConfig{}, execLog(), nil)
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobSSTI,
		Target: domain.JobTarget{EndpointID: ep.ID, InjectionPointID: ip.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 2}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 {
		t.Fatalf("cases = %d, want exactly 1", len(cases))
	}
	d := &sstiDetail{}
	if len(cases[0].Detail) > 0 {
		if err := json.Unmarshal(cases[0].Detail, d); err != nil {
			t.Fatalf("detail: %v", err)
		}
	}
	return d, cases[0]
}

// TestSSTIFingerprintSkipsStaticAssetEndpoint: an image is not a rendered
// template. The PHP marker is present on purpose — the local marker table would
// have enabled probing, so this fixture proves the shared gate wins.
func TestSSTIFingerprintSkipsStaticAssetEndpoint(t *testing.T) {
	probes := &sstiProbeLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.add(r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Powered-By", "PHP/8.2")
		_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
	}))
	defer srv.Close()

	d, tc := runSSTIFingerprintJob(t, srv.URL+"/assets/logo.png?q=hello")
	if got := probes.all(); len(got) != 0 {
		t.Fatalf("static asset received %d template payloads, want 0: %v", len(got), got)
	}
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped (note %q)", tc.Status, tc.Note)
	}
	if !strings.Contains(tc.Note, "static asset") {
		t.Fatalf("skip note = %q, want the fingerprint's static-asset reason", tc.Note)
	}
	if len(d.TemplateEngines) != 0 {
		t.Fatalf("template engines = %v, want none for a skipped point", d.TemplateEngines)
	}
}

// TestSSTIFingerprintSkipsJSONWithoutTemplateEvidence: a serialized JSON reply is
// data, not a rendered document. The PHP marker is again present, so only the
// fingerprint gate can produce the skip.
func TestSSTIFingerprintSkipsJSONWithoutTemplateEvidence(t *testing.T) {
	probes := &sstiProbeLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.add(r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Powered-By", "PHP/8.2")
		fmt.Fprint(w, `{"ok":true,"greeting":"hello"}`)
	}))
	defer srv.Close()

	_, tc := runSSTIFingerprintJob(t, srv.URL+"/api/page?q=hello")
	if got := probes.all(); len(got) != 0 {
		t.Fatalf("JSON endpoint received %d template payloads, want 0: %v", len(got), got)
	}
	if tc.Status != domain.TestCaseSkipped {
		t.Fatalf("status = %s, want skipped (note %q)", tc.Status, tc.Note)
	}
	if !strings.Contains(tc.Note, "serialized JSON") {
		t.Fatalf("skip note = %q, want the fingerprint's JSON reason", tc.Note)
	}
}

// TestSSTIFingerprintProbesJSONWhenEngineNamed is the fail-open half: JSON is not
// a blanket skip, only JSON with no engine evidence is. An error payload that
// names the engine keeps the point probeable.
func TestSSTIFingerprintProbesJSONWhenEngineNamed(t *testing.T) {
	probes := &sstiProbeLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.add(r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":"jinja2.exceptions.UndefinedError: 'name' is undefined"}`)
	}))
	defer srv.Close()

	d, tc := runSSTIFingerprintJob(t, srv.URL+"/api/error?q=hello")
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("status = %s, want completed (note %q)", tc.Status, tc.Note)
	}
	sent := probes.all()
	if len(sent) == 0 {
		t.Fatal("an engine-naming error payload must stay probeable")
	}
	if len(d.TemplateEngines) == 0 || d.TemplateEngines[0] != "jinja2" {
		t.Fatalf("template engines = %v, want jinja2 first", d.TemplateEngines)
	}
	// Every probe carries the job's per-run marker after its shape (see
	// sstiProbe), so the exact payload is the recommended shape plus d.Marker.
	if want := "{{7*7}}" + d.Marker; sent[0] != want {
		t.Fatalf("first payload = %q, want the Jinja2 shape %q", sent[0], want)
	}
}

// TestSSTIFingerprintPrioritizesMatchingShape: the recommended engine decides
// which already-existing payload shape goes first — "{{…}}" for Jinja2/Flask,
// "${…}" for a Java servlet stack (Freemarker/SpEL/Thymeleaf), "<%= … %>" for
// Rails/ERB — and no candidate is dropped from the plan.
func TestSSTIFingerprintPrioritizesMatchingShape(t *testing.T) {
	cases := []struct {
		name       string
		headers    map[string]string
		body       string
		wantFirst  string
		wantEngine string
	}{
		{
			name:       "flask-jinja2",
			headers:    map[string]string{"Server": "Werkzeug/3.0.1 Python/3.11"},
			body:       "<html><body><p>hello</p></body></html>",
			wantFirst:  "{{7*7}}",
			wantEngine: "jinja2",
		},
		{
			name:       "java-servlet-freemarker",
			headers:    map[string]string{"Server": "Apache-Coyote/1.1"},
			body:       "<html><body><p>hello</p></body></html>",
			wantFirst:  "${7*7}",
			wantEngine: "freemarker",
		},
		{
			name:       "rails-erb",
			body:       `<html><head><meta name="csrf-token" content="t"></head><body>hello</body></html>`,
			wantFirst:  "<%= 7*7 %>",
			wantEngine: "erb",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probes := &sstiProbeLog{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				probes.add(r.URL.Query().Get("q"))
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				for k, v := range c.headers {
					w.Header().Set(k, v)
				}
				fmt.Fprint(w, c.body)
			}))
			defer srv.Close()

			d, tc := runSSTIFingerprintJob(t, srv.URL+"/page?q=hello")
			if tc.Status != domain.TestCaseCompleted {
				t.Fatalf("status = %s, want completed (note %q)", tc.Status, tc.Note)
			}
			sent := probes.all()
			if len(sent) < 2 {
				t.Fatalf("sent %d probes, want the plan to run: %v", len(sent), sent)
			}
			// The shape must come first; the per-run marker always follows it
			// (see sstiProbe), so the exact payload is shape + d.Marker.
			if want := c.wantFirst + d.Marker; sent[0] != want {
				t.Fatalf("first payload = %q, want %q (order %v)", sent[0], want, sent)
			}
			if len(d.TemplateEngines) == 0 || d.TemplateEngines[0] != c.wantEngine {
				t.Fatalf("template engines = %v, want %s first", d.TemplateEngines, c.wantEngine)
			}
			// The probes below never evaluate, so the whole main plan AND the
			// context plan must have been sent: prioritizing reorders, it does
			// not shrink the plan.
			families := sstiFamiliesForEngines(d.TemplateEngines)
			want := len(sstiFilteredVariants(sstiVariants(), families)) +
				len(sstiFilteredVariants(sstiContextVariants("hello"), families))
			if len(sent) != want {
				t.Fatalf("sent %d probes, want the full plan of %d: %v", len(sent), want, sent)
			}
		})
	}
}

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	var detail xxeDetail
	if err := json.Unmarshal(findings[0].Detail, &detail); err != nil {
		t.Fatalf("finding detail: %v", err)
	}
	if detail.Mode != xxeModeOutOfBand {
		t.Fatalf("mode = %q, want %q (an opaque endpoint must fall back to the collaborator)", detail.Mode, xxeModeOutOfBand)
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

// An endpoint whose stored content type merely CONTAINS "xml" is not proof of an
// XML parser: application/xml-dtd with an HTML fragment in the body passes the
// structural check above, so the fingerprint gate is what keeps the entity off
// the wire.
func TestXXEFingerprintRejectsNonXMLEntitySurface(t *testing.T) {
	var requests atomic.Int32
	var entityRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if strings.Contains(string(body), "<!DOCTYPE") {
			entityRequests.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/legacy",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml-dtd",
		RequestBody: `<p>hello</p>`, CreatedAt: time.Now()}
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
	if got := entityRequests.Load(); got != 0 {
		t.Fatalf("endpoint received %d entity payloads, want 0", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("endpoint received %d requests, want the baseline only", got)
	}
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].VulnClass != domain.VulnXXE || cases[0].Status != domain.TestCaseSkipped {
		t.Fatalf("cases = %+v, want one skipped XXE case", cases)
	}
	if !strings.Contains(cases[0].Note, "no XML surface") {
		t.Fatalf("skip note = %q, want the fingerprint's XML-surface reason", cases[0].Note)
	}
}

func TestInjectXXEAddsEntityToXMLBody(t *testing.T) {
	got, ok := injectXXE(`<root><value>1</value></root>`, "http://example.test/marker")
	if !ok || !strings.Contains(got, "<!DOCTYPE root") || !strings.Contains(got, "&xxe;") {
		t.Fatalf("injectXXE = %q, ok=%v", got, ok)
	}
}

// xxeTestEntityRe matches one INTERNAL entity declaration.
var xxeTestEntityRe = regexp.MustCompile(`<!ENTITY\s+([A-Za-z_][A-Za-z0-9_.:-]*)\s+"([^"]*)"\s*>`)

// xxeTestExpand stands in for a DTD-expanding parser: it resolves the document's
// own internal entity declarations, substitutes their references, and returns the
// document with the DOCTYPE removed — the shape an application that echoes parsed
// values sends back. External entities are not resolved, exactly like a hardened
// or offline parser.
func xxeTestExpand(body string) (string, bool) {
	if strings.Contains(body, "SYSTEM") || strings.Contains(body, "PUBLIC") {
		return "", false
	}
	start := strings.Index(body, "<!DOCTYPE")
	if start < 0 {
		return "", false
	}
	_, _, end := xxeInternalSubset(body, start)
	if end < 0 {
		return "", false
	}
	decls := xxeTestEntityRe.FindAllStringSubmatch(body, -1)
	if len(decls) == 0 {
		return "", false
	}
	out := body[:start] + body[end+1:]
	for _, m := range decls {
		out = strings.ReplaceAll(out, "&"+m[1]+";", m[2])
	}
	if strings.Contains(out, "&indago_") {
		return "", false // an unresolved reference is a parse error
	}
	return out, true
}

// newInBandXXETarget is the standard in-band fixture: an XML endpoint whose
// parser expands document-internal entities and echoes the parsed document.
func newInBandXXETarget(t *testing.T, body string) (*httptest.Server, *domain.Endpoint, *scanEnv) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		out, ok := xxeTestExpand(string(raw))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, out)
	}))
	t.Cleanup(target.Close)
	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/stock",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml",
		RequestBody: body, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return target, ep, env
}

func handleXXEJob(t *testing.T, ex *xxeExecutor, env *scanEnv, ep *domain.Endpoint) {
	t.Helper()
	job := &domain.TestJob{ID: domain.NewID(), ScanID: env.scanID, Type: domain.JobXXE,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Attempts: 1, MaxAttempts: 1}
	if err := ex.Handle(context.Background(), job); err != nil {
		t.Fatalf("handle: %v", err)
	}
}

func xxeCaseDetail(t *testing.T, env *scanEnv) (xxeDetail, *domain.TestCase) {
	t.Helper()
	cases, err := env.st.TestCases().ListByScan(context.Background(), env.scanID)
	if err != nil || len(cases) != 1 {
		t.Fatalf("expected exactly 1 test case, got %d (err %v)", len(cases), err)
	}
	var detail xxeDetail
	if err := json.Unmarshal(cases[0].Detail, &detail); err != nil {
		t.Fatalf("test case detail: %v", err)
	}
	return detail, cases[0]
}

// An XML endpoint that expands document-internal entities is confirmed WITHOUT
// any collaborator: the response carries the random marker value and not the
// declaration we sent.
func TestXXEConfirmsInBandInternalEntityWithoutCallback(t *testing.T) {
	_, ep, env := newInBandXXETarget(t, `<stockCheck><productId>1</productId></stockCheck>`)
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)

	handleXXEJob(t, ex, env, ep)

	findings, err := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].VulnClass != domain.VulnXXE || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed in-band XXE", findings)
	}
	var detail xxeDetail
	if err := json.Unmarshal(findings[0].Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Mode != xxeModeInBand {
		t.Fatalf("mode = %q, want %q", detail.Mode, xxeModeInBand)
	}
	if len(detail.InBand) != 2 {
		t.Fatalf("in-band attempts = %d, want 2 independent markers", len(detail.InBand))
	}
	names := map[string]bool{}
	for i, attempt := range detail.InBand {
		if !attempt.Expanded {
			t.Fatalf("attempt %d not expanded: %+v", i, attempt)
		}
		if names[attempt.Entity] {
			t.Fatalf("attempt %d reused entity name %q; two independent markers are required", i, attempt.Entity)
		}
		names[attempt.Entity] = true
		for _, forbidden := range []string{"SYSTEM", "PUBLIC", "file://", "http://", "https://"} {
			if strings.Contains(attempt.Payload, forbidden) {
				t.Fatalf("in-band payload must stay local, found %q in %q", forbidden, attempt.Payload)
			}
		}
	}
	if detail.InBand[0].Entity == "" || !strings.Contains(detail.Reason, "document-internal") {
		t.Fatalf("detail = %+v, want entity names and an in-band reason", detail)
	}
}

// A target that echoes the request body verbatim proves nothing: the marker
// value is only present inside the declaration we sent, so the in-band probe
// must reject it and must not send a second identical probe.
func TestXXEInBandRejectsRawPayloadEcho(t *testing.T) {
	var inBandRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "<!ENTITY") {
			inBandRequests.Add(1)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write(raw)
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/echo",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork, ContentType: "application/xml",
		RequestBody: `<stockCheck><productId>1</productId></stockCheck>`, CreatedAt: time.Now()}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)
	handleXXEJob(t, ex, env, ep)

	if got := inBandRequests.Load(); got != 1 {
		t.Fatalf("in-band probes = %d, want 1 (an echo must stop the loop)", got)
	}
	findings, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(findings) != 0 {
		t.Fatalf("raw payload echo must not be confirmed: %+v", findings)
	}
	detail, tc := xxeCaseDetail(t, env)
	if detail.Verdict != domain.VerdictRejected || !strings.Contains(detail.Reason, "echoed") {
		t.Fatalf("verdict = %s reason = %q, want rejected because of the echo", detail.Verdict, detail.Reason)
	}
	if tc.Status != domain.TestCaseCompleted {
		t.Fatalf("test case status = %s", tc.Status)
	}
}

// One expansion is real evidence but not independent evidence: a second marker
// must confirm too, otherwise the verdict stays inconclusive.
func TestXXEInBandSingleExpansionIsInconclusive(t *testing.T) {
	var expansions atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "<!ENTITY") && expansions.Add(1) == 1 {
			if out, ok := xxeTestExpand(string(raw)); ok {
				w.Header().Set("Content-Type", "application/xml")
				fmt.Fprint(w, out)
				return
			}
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
	handleXXEJob(t, ex, env, ep)

	findings, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(findings) != 0 {
		t.Fatalf("a single expansion must not be confirmed: %+v", findings)
	}
	detail, _ := xxeCaseDetail(t, env)
	if detail.Verdict != domain.VerdictInconclusive || !strings.Contains(detail.Reason, "second independent marker") {
		t.Fatalf("verdict = %s reason = %q, want inconclusive pending a second marker", detail.Verdict, detail.Reason)
	}
}

// When the in-band probe already confirms, the collaborator is never contacted:
// OAST stays available but is not exercised needlessly.
func TestXXEInBandConfirmationSkipsCollaborator(t *testing.T) {
	var callbacks atomic.Int32
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks.Add(1)
		fmt.Fprint(w, "[]")
	}))
	defer callback.Close()

	_, ep, env := newInBandXXETarget(t, `<stockCheck><productId>1</productId></stockCheck>`)
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)
	ex.withCallback(callback.URL, callback.URL+"/poll")
	handleXXEJob(t, ex, env, ep)

	if got := callbacks.Load(); got != 0 {
		t.Fatalf("collaborator received %d requests, want 0 after an in-band confirmation", got)
	}
	findings, _ := env.st.Findings().ListByScan(context.Background(), env.scanID)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("findings = %+v, want one confirmed finding", findings)
	}
	var detail xxeDetail
	_ = json.Unmarshal(findings[0].Detail, &detail)
	if detail.Mode != xxeModeInBand {
		t.Fatalf("mode = %q, want %q", detail.Mode, xxeModeInBand)
	}
}

func TestInjectXXEInternalDeclaresOnlyAnInternalEntity(t *testing.T) {
	probe := xxeEntityProbe{Name: "indago_test", Value: "indagovalue"}
	got, ok := injectXXEInternal(`<root><value>1</value></root>`, probe)
	if !ok {
		t.Fatal("injectXXEInternal reported no injectable document")
	}
	if want := `<!DOCTYPE root [<!ENTITY indago_test "indagovalue">]>`; !strings.Contains(got, want) {
		t.Fatalf("payload = %q, want it to contain %q", got, want)
	}
	if want := `<value>&indago_test;</value>`; !strings.Contains(got, want) {
		t.Fatalf("payload = %q, want the reference inside the text leaf %q", got, want)
	}
	for _, forbidden := range []string{"SYSTEM", "PUBLIC", "file://", "http://"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("payload must not reference %q: %q", forbidden, got)
		}
	}
}

func TestInjectXXEInternalFallsBackToRootContent(t *testing.T) {
	probe := xxeEntityProbe{Name: "indago_test", Value: "indagovalue"}
	// No text-only element exists, so the reference becomes the root's first
	// content node instead of replacing a leaf value.
	got, ok := injectXXEInternal(`<root><empty></empty><self/></root>`, probe)
	if !ok {
		t.Fatal("injectXXEInternal reported no injectable document")
	}
	if want := `<root>&indago_test;<empty>`; !strings.Contains(got, want) {
		t.Fatalf("payload = %q, want the reference as the root's first content", got)
	}
	// A leaf is preferred when one exists: that is the value an application is
	// most likely to echo back.
	leaf, ok := injectXXEInternal(`<root><nested><deep>x</deep></nested></root>`, probe)
	if !ok || !strings.Contains(leaf, `<deep>&indago_test;</deep>`) {
		t.Fatalf("payload = %q, want the reference inside the text leaf", leaf)
	}
	if _, ok := injectXXEInternal(`<root/>`, probe); ok {
		t.Fatal("a self-closing root has no content to inject into")
	}
}

func TestInjectXMLDTDReusesExistingDOCTYPE(t *testing.T) {
	body := `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY keep "kept">]><root><v>x</v></root>`
	got, ok := injectXMLDTD(body, `<!ENTITY added "y">`)
	if !ok {
		t.Fatal("injectXMLDTD reported no injectable document")
	}
	if n := strings.Count(got, "<!DOCTYPE"); n != 1 {
		t.Fatalf("payload has %d DOCTYPE declarations, want 1: %q", n, got)
	}
	if want := `<!ENTITY keep "kept"><!ENTITY added "y">]>`; !strings.Contains(got, want) {
		t.Fatalf("payload = %q, want the declaration inside the existing subset (%q)", got, want)
	}
	if strings.Contains(got, "<?xml version=\"1.0\"?>") == false {
		t.Fatalf("payload dropped the XML declaration: %q", got)
	}
}

func TestXXEEntityExpansionNeedsStrictNonReflection(t *testing.T) {
	probe := xxeEntityProbe{Name: "indago_abc", Value: "indagoabc"}
	cases := []struct {
		name     string
		resp     string
		baseline string
		want     bool
	}{
		{name: "expanded value only", resp: "<productId>indagoabc</productId>", want: true},
		{name: "declaration echoed", resp: `<!DOCTYPE root [<!ENTITY indago_abc "indagoabc">]>`, want: false},
		{name: "reference echoed", resp: "<productId>&indago_abc;</productId>", want: false},
		{name: "escaped declaration echoed", resp: "&lt;!ENTITY indago_abc \"indagoabc\"&gt;", want: false},
		{name: "value already in baseline", resp: "<p>indagoabc</p>", baseline: "indagoabc", want: false},
		{name: "no marker", resp: "<p>ok</p>", want: false},
		{name: "empty response", resp: "", want: false},
	}
	for _, tc := range cases {
		if got := xxeEntityExpanded(tc.resp, tc.baseline, probe); got != tc.want {
			t.Fatalf("%s: xxeEntityExpanded(%q, %q) = %v, want %v", tc.name, tc.resp, tc.baseline, got, tc.want)
		}
	}
}

func TestXXEExplicitXMLContentTypeWithoutObservedBody(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s := string(body)
		if !strings.Contains(s, "<indago>") {
			http.Error(w, "missing fallback xml", http.StatusBadRequest)
			return
		}
		// Simulate an XML parser that expands a declared internal entity.
		if idx := strings.Index(s, "<!ENTITY "); idx >= 0 {
			rest := s[idx+len("<!ENTITY "):]
			if sp := strings.IndexByte(rest, ' '); sp > 0 {
				q1 := strings.IndexByte(rest[sp:], '"')
				if q1 >= 0 {
					afterQ1 := rest[sp+q1+1:]
					if q2 := strings.IndexByte(afterQ1, '"'); q2 >= 0 {
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"output":%q}`, afterQ1[:q2])
						return
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"output":"probe"}`)
	}))
	defer target.Close()

	env := newScanEnv(t)
	ep := &domain.Endpoint{
		ID: domain.NewID(), ScanID: env.scanID, URL: target.URL + "/xxe/simple",
		Method: domain.MethodPOST, Source: domain.SourceBrowserNetwork,
		ContentType: "application/xml", RequestBody: "", CreatedAt: time.Now(),
	}
	if err := env.st.Endpoints().Create(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if !isXMLBodyEndpoint(ep) {
		t.Fatal("isXMLBodyEndpoint() = false, want true for explicit application/xml without body")
	}
	ex := newXXEExecutor(env.st, scopedClient(t, openScope()), env.ev,
		ExecutorConfig{AllowStateChanging: true, SkipWriteEndpoints: false}, execLog(), nil)
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

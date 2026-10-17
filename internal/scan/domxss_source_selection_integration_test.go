//go:build browser_integration

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/store"
)

func TestDOMXSSSourceSelectionTestsEveryQueryParameter(t *testing.T) {
	ctx := context.Background()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>
const value = new URLSearchParams(location.search).get('x');
document.getElementById('sink').innerHTML = value || '';
</script>`)
	}))
	defer lab.Close()

	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/query?first=unused&x=unused", domain.MethodGET)
	first := env.param(ep, "first", domain.LocationQuery, "unused")
	duplicateFirst := env.param(ep, "first", domain.LocationQuery, "also-unused")
	x := env.param(ep, "x", domain.LocationQuery, "unused")

	// Force the same stable discovery order the scanner receives: the first
	// query parameter is inert, while the page reads only the second.
	st := orderedQueryParameterStore{
		Store: env.st,
		params: orderedQueryParameterRepo{
			ParameterRepo: env.st.Parameters(),
			ordered:       []*domain.Parameter{first, duplicateFirst, x},
		},
	}
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	exec := newDOMXSSExecutor(st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	queryJob := sourceSelectionJob(t, env.scanID, ep, detectionSourceQuery)
	if err := exec.Handle(ctx, queryJob); err != nil {
		t.Fatalf("run query DOM-XSS job: %v", err)
	}

	findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	if len(findings) != 1 {
		t.Fatalf("query source findings = %d, want one finding for x (first is inert)", len(findings))
	}
	f := findings[0]
	detail := decodeFindingDetail(f.Detail)
	if f.Verdict != domain.VerdictConfirmed {
		t.Fatalf("query parameter x verdict = %s, want confirmed; title=%q summary=%q", f.Verdict, f.Title, f.Summary)
	}
	if !strings.Contains(f.Title, `parameter "x"`) || detail.ParameterName != "x" || len(detail.Candidates) != 1 || detail.Candidates[0].Parameter != "x" {
		t.Fatalf("query finding must identify parameter x in title/detail/candidate: title=%q detail=%+v", f.Title, detail)
	}
	if !strings.Contains(strings.Join(sourceSelectionAttemptNotes(detail), "\n"), "is not defined") {
		t.Fatalf("expected actual browser execution signal in verification notes: %+v", detail.Attempts)
	}
	queryCases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	candidateTests := 0
	for _, tc := range queryCases {
		if tc.JobID == queryJob.ID {
			candidateTests++
		}
	}
	if candidateTests != 3 {
		t.Fatalf("query candidate attempts = %d, want 3 (one inert name + x reachability and verification; duplicate name is skipped)", candidateTests)
	}

	// An endpoint URL may contain query text without any corresponding
	// discovered LocationQuery parameter. It must be explicitly skipped,
	// never treated as a clean negative.
	noParams := env.endpoint(lab.URL+"/query?first=unused&x=unused", domain.MethodGET)
	noParamExec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	noParamJob := sourceSelectionJob(t, env.scanID, noParams, detectionSourceQuery)
	if err := noParamExec.Handle(ctx, noParamJob); err != nil {
		t.Fatalf("run query source with no discovered parameters: %v", err)
	}
	cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	querySkip := false
	for _, tc := range cases {
		if tc.JobID == noParamJob.ID && tc.Status == domain.TestCaseSkipped && strings.Contains(tc.Note, "not tested") && strings.Contains(tc.Note, "no discovered query parameter") {
			querySkip = true
		}
	}
	if !querySkip {
		t.Fatalf("endpoint without discovered query parameters must be an explicit not-tested skip, cases=%+v", cases)
	}
}

func TestDOMXSSSourceSelectionDiscoversCustomStorageKeysAndConfirms(t *testing.T) {
	ctx := context.Background()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/local":
			fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>
const value = localStorage.getItem('profile_note');
document.getElementById('sink').innerHTML = value || '';
</script>`)
		case "/session":
			fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>
const value = sessionStorage.getItem('tab_note');
document.getElementById('sink').innerHTML = value || '';
</script>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer lab.Close()

	env := newScanEnv(t)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	scope := sourceSelectionScope(t, lab.URL)

	for _, tc := range []struct {
		path   string
		source string
		key    string
	}{
		{path: "/local", source: "localStorage", key: "profile_note"},
		{path: "/session", source: "sessionStorage", key: "tab_note"},
	} {
		ep := env.endpoint(lab.URL+tc.path, domain.MethodGET)
		exec := newDOMXSSExecutor(env.st, manager, env.ev, scope, execLog(), &sync.Mutex{})
		if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, tc.source)); err != nil {
			t.Fatalf("run %s DOM-XSS job: %v", tc.source, err)
		}
		findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
		if len(findings) != 1 {
			t.Fatalf("%s findings = %d, want one for discovered key %q", tc.source, len(findings), tc.key)
		}
		f := findings[0]
		detail := decodeFindingDetail(f.Detail)
		if f.Verdict != domain.VerdictConfirmed {
			t.Fatalf("%s key %q verdict = %s, want confirmed; summary=%q", tc.source, tc.key, f.Verdict, f.Summary)
		}
		if len(detail.Candidates) != 1 {
			t.Fatalf("storage finding should retain one candidate: %+v", detail)
		}
		if !strings.Contains(f.Summary, "attacker-relevant ability to write or poison") || !strings.Contains(detail.Candidates[0].Rationale, "manual exploitability review") {
			t.Fatalf("storage finding must preserve attacker-control caveat in rationale and verification summary: summary=%q candidate=%+v", f.Summary, detail.Candidates[0])
		}
		if !strings.Contains(f.Title, tc.source+` key "`+tc.key+`"`) || detail.ParameterName != tc.key || detail.Candidates[0].Parameter != tc.key || detail.Candidates[0].ContextSub != tc.source {
			t.Fatalf("%s finding must distinguish backend and key in title/detail/candidate: title=%q detail=%+v", tc.source, f.Title, detail)
		}
		if !strings.Contains(strings.Join(sourceSelectionAttemptNotes(detail), "\n"), "is not defined") {
			t.Fatalf("expected actual browser execution signal for %s key %q: %+v", tc.source, tc.key, detail.Attempts)
		}
	}
}

func TestDOMXSSSourceSelectionCapsStorageKeysAndRecordsSkippedCount(t *testing.T) {
	ctx := context.Background()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/many" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>
for (let i = 0; i < 34; i++) {
  const key = 'note_' + String(i).padStart(2, '0');
  if (localStorage.getItem(key) === null) localStorage.setItem(key, 'seed');
}
document.getElementById('sink').textContent = 'safe';
</script>`)
	}))
	defer lab.Close()

	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/many", domain.MethodGET)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	job := sourceSelectionJob(t, env.scanID, ep, "localStorage")
	exec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
	if err := exec.Handle(ctx, job); err != nil {
		t.Fatalf("run capped localStorage DOM-XSS job: %v", err)
	}

	cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
	if err != nil {
		t.Fatal(err)
	}
	discoveryNote := ""
	tested := make(map[string]bool)
	for _, tc := range cases {
		if tc.JobID != job.ID {
			continue
		}
		if strings.Contains(tc.Note, "key discovery observed") {
			discoveryNote = tc.Note
		}
		for i := 0; i < 34; i++ {
			key := fmt.Sprintf("note_%02d", i)
			if strings.Contains(tc.Note, fmt.Sprintf(`localStorage key %q`, key)) {
				tested[key] = true
			}
		}
	}
	if !strings.Contains(discoveryNote, "observed 34 distinct key(s)") || !strings.Contains(discoveryNote, "ceiling=32, testing 32") || !strings.Contains(discoveryNote, "skipped 2 additional key(s)") {
		t.Fatalf("storage key cap must be operator-visible in the discovery TestCase, note=%q", discoveryNote)
	}
	if len(tested) != domXSSStorageKeyLimit {
		t.Fatalf("tested storage keys = %d, want ceiling %d", len(tested), domXSSStorageKeyLimit)
	}
	for i := 0; i < domXSSStorageKeyLimit; i++ {
		if !tested[fmt.Sprintf("note_%02d", i)] {
			t.Fatalf("deterministic sorted key note_%02d was not tested: %v", i, tested)
		}
	}
	if tested["note_32"] || tested["note_33"] {
		t.Fatalf("keys beyond the 32-key ceiling were tested: %v", tested)
	}
	if findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID); len(findings) != 0 {
		t.Fatalf("safe textContent control unexpectedly produced storage findings: %+v", findings)
	}
}

func TestDOMXSSSourceSelectionEnumeratesStorageStateSeededKeys(t *testing.T) {
	ctx := context.Background()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><div id="sink"></div><script>
// Property access drives the sink, so enumeration must discover this key;
// the getItem call separately proves the observer preserves its native value.
const value = localStorage['seeded_note'];
let coercions = 0;
const dynamicKey = { toString() { coercions++; return 'seeded_note'; } };
window.__getItemResult = localStorage.getItem('seeded_note');
window.__dynamicGetItemResult = localStorage.getItem(dynamicKey);
window.__keyCoercions = coercions;
document.getElementById('sink').innerHTML = value || '';
</script>`)
	}))
	defer lab.Close()

	env := newScanEnv(t)
	statePath := t.TempDir() + "/storage-state.json"
	state, err := json.Marshal(map[string]any{
		"cookies": []any{},
		"origins": []any{map[string]any{
			"origin":       lab.URL,
			"localStorage": []any{map[string]any{"name": "seeded_note", "value": "seeded-value"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := env.st.Sessions().Create(ctx, &domain.Session{
		ID: domain.NewID(), ScanID: env.scanID, Mode: domain.AuthExisting,
		State: domain.SessionActive, StatePath: statePath,
	}); err != nil {
		t.Fatal(err)
	}

	ep := env.endpoint(lab.URL+"/seeded", domain.MethodGET)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	scope := sourceSelectionScope(t, lab.URL)
	observationCtx, err := manager.NewContext(ctx, browser.ContextOptions{AllowRequest: func(raw string) bool { return scope.Permits(raw).Allowed }, StorageStatePath: statePath})
	if err != nil {
		t.Fatalf("create isolated seeded context: %v", err)
	}
	observationPage, err := observationCtx.NewPage(ctx)
	if err != nil {
		t.Fatalf("create storage observation page: %v", err)
	}
	if err := observationPage.AddInitScript(ctx, domXSSStorageObserverScript()); err != nil {
		t.Fatalf("install storage observation hook: %v", err)
	}
	if _, err := observationPage.Navigate(ctx, ep.URL, browser.NavOptions{WaitUntil: browser.WaitLoad}); err != nil {
		t.Fatalf("navigate storage observation pass: %v", err)
	}
	observedValue, err := observationPage.Evaluate(ctx, "window.__getItemResult")
	if err != nil || observedValue != "seeded-value" {
		t.Fatalf("storage observer changed native getItem result: got %#v, err=%v", observedValue, err)
	}
	observedDynamicValue, err := observationPage.Evaluate(ctx, "window.__dynamicGetItemResult")
	if err != nil || observedDynamicValue != "seeded-value" {
		t.Fatalf("storage observer changed object-key getItem result: got %#v, err=%v", observedDynamicValue, err)
	}
	coercions, err := observationPage.Evaluate(ctx, "window.__keyCoercions")
	if err != nil || fmt.Sprint(coercions) != "1" {
		t.Fatalf("storage observer should not coerce object keys a second time: got %#v, err=%v", coercions, err)
	}
	if keys := parseDOMXSSStorageReads(observationPage.ConsoleMessages(), detection.DOMSourceLocalStorage); len(keys) != 1 || keys[0] != "seeded_note" {
		t.Fatalf("storage observer did not report the target's getItem key: %v", keys)
	}
	_ = observationPage.Close()
	_ = observationCtx.Close()

	exec := newDOMXSSExecutor(env.st, manager, env.ev, scope, execLog(), &sync.Mutex{})
	if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, "localStorage")); err != nil {
		t.Fatalf("run seeded localStorage DOM-XSS job: %v", err)
	}
	findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
	if len(findings) != 1 || findings[0].Verdict != domain.VerdictConfirmed {
		t.Fatalf("storage-state seeded key should be enumerated, written, and confirmed: %+v", findings)
	}
	detail := decodeFindingDetail(findings[0].Detail)
	if detail.ParameterName != "seeded_note" || len(detail.Candidates) != 1 || detail.Candidates[0].Parameter != "seeded_note" {
		t.Fatalf("seeded storage key was not identified in finding detail: %+v", detail)
	}
}

func TestDOMXSSSourceSelectionSkipsStorageWhenNoKeyIsObserved(t *testing.T) {
	ctx := context.Background()
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><div id="sink">safe</div><script>
// No localStorage/sessionStorage key is read or present.
</script>`)
	}))
	defer lab.Close()

	env := newScanEnv(t)
	ep := env.endpoint(lab.URL+"/safe", domain.MethodGET)
	manager := newSourceSelectionBrowser(t)
	defer manager.Close()
	for _, source := range []string{"localStorage", "sessionStorage"} {
		exec := newDOMXSSExecutor(env.st, manager, env.ev, sourceSelectionScope(t, lab.URL), execLog(), &sync.Mutex{})
		if err := exec.Handle(ctx, sourceSelectionJob(t, env.scanID, ep, source)); err != nil {
			t.Fatalf("run %s DOM-XSS job: %v", source, err)
		}
		findings := sourceSelectionFindings(t, env.st, env.scanID, ep.ID)
		if len(findings) != 0 {
			t.Fatalf("safe storage source %s produced %d findings: %+v", source, len(findings), findings)
		}
		cases, err := env.st.TestCases().ListByScan(ctx, env.scanID)
		if err != nil {
			t.Fatal(err)
		}
		foundSkip := false
		for _, tc := range cases {
			if strings.Contains(tc.Note, source) && strings.Contains(tc.Note, "not tested") && strings.Contains(tc.Note, "no storage key") && tc.Status == domain.TestCaseSkipped {
				foundSkip = true
			}
		}
		if !foundSkip {
			t.Fatalf("no-key %s probe must be an explicit skipped/not-tested diagnostic, cases=%+v", source, cases)
		}
	}
}

func newSourceSelectionBrowser(t *testing.T) *browser.Manager {
	t.Helper()
	exe := os.Getenv("INDAGO_CHROMIUM_PATH")
	if exe == "" {
		exe = "/usr/bin/google-chrome"
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("real Chromium required for browser_integration tests (%s): %v", exe, err)
	}
	manager, err := browser.NewManager(browser.Config{
		Headless: true, ExecutablePath: exe, PoolSize: 1,
		NavigationTimeout: 15 * time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("start real Chromium: %v", err)
	}
	return manager
}

func sourceSelectionScope(t *testing.T, rawURL string) domain.Scope {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return domain.Scope{IncludeHosts: []string{u.Hostname()}}
}

func sourceSelectionJob(t *testing.T, scanID domain.ID, ep *domain.Endpoint, source string) *domain.TestJob {
	t.Helper()
	payload, err := json.Marshal(domXSSJob{EndpointID: ep.ID, Source: detection.DOMXSSSource(source)})
	if err != nil {
		t.Fatal(err)
	}
	return &domain.TestJob{
		ID: domain.NewID(), ScanID: scanID, Type: domain.JobDOMXSS,
		Target: domain.JobTarget{EndpointID: ep.ID, URL: ep.URL}, Payload: payload,
		Attempts: 1, MaxAttempts: 1,
	}
}

func sourceSelectionFindings(t *testing.T, st store.Store, scanID, endpointID domain.ID) []*domain.Finding {
	t.Helper()
	findings, err := st.Findings().ListByScan(context.Background(), scanID)
	if err != nil {
		t.Fatal(err)
	}
	var out []*domain.Finding
	for _, f := range findings {
		if f.VulnClass == domain.VulnDOMXSS && f.EndpointID == endpointID {
			out = append(out, f)
		}
	}
	return out
}

func sourceSelectionAttemptNotes(detail findingDetail) []string {
	var out []string
	for _, attempt := range detail.Attempts {
		out = append(out, attempt.Notes)
	}
	return out
}

type orderedQueryParameterStore struct {
	store.Store
	params store.ParameterRepo
}

func (s orderedQueryParameterStore) Parameters() store.ParameterRepo { return s.params }

type orderedQueryParameterRepo struct {
	store.ParameterRepo
	ordered []*domain.Parameter
}

func (r orderedQueryParameterRepo) ListByEndpoint(context.Context, domain.ID) ([]*domain.Parameter, error) {
	return append([]*domain.Parameter(nil), r.ordered...), nil
}

const detectionSourceQuery = "location.search"

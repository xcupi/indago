package web_test

// Real-browser test for the LLM settings screen: the form starts in an
// explicit "not configured" state, the key field is a password input that is
// never repopulated, Save stores the configuration, and only the explicit
// Test / Fetch models buttons contact the provider.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUISettingsLLMConfigureAndTest(t *testing.T) {
	const uiKey = "sk-ui-test-0123456789abcdefZYXW"

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		switch r.URL.Path {
		case "/models":
			io.WriteString(w, `{"data":[{"id":"test-model"},{"id":"test-model-mini"}]}`)
		default:
			io.WriteString(w, `{"choices":[{"message":{"content":"OK"}}]}`)
		}
	}))
	defer upstream.Close()

	u := newUIHarness(t)
	u.eval(`navigate("#/settings")`)
	u.waitUI("settings rendered", `document.getElementById('view').dataset.view==='settings'`)
	u.waitUI("llm card loaded", `document.getElementById('llm_provider') && document.getElementById('llm_provider').options.length===3`)

	// Explicit not-configured state; nothing contacted the provider.
	if !strings.Contains(u.evalStr(`document.getElementById('view').textContent`), "Not configured") {
		t.Fatal("settings page does not show the not-configured state")
	}
	if got := u.evalStr(`document.getElementById('llm_api_key').type`); got != "password" {
		t.Fatalf("API key field type = %q, want password", got)
	}
	if got := u.evalStr(`document.getElementById('llm_api_key').value`); got != "" {
		t.Fatalf("API key field is populated before anything was saved: %q", got)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("opening the settings page contacted the provider %d time(s)", got)
	}

	// Fill and save.
	u.setVal("llm_provider", "custom")
	u.setVal("llm_model", "test-model")
	u.setVal("llm_base_url", upstream.URL)
	u.setVal("llm_api_key", uiKey)
	u.click("llm_save")
	u.waitUI("configuration saved", `document.querySelector('#view .detail') && document.querySelector('#view .detail').textContent.indexOf('configured')>=0`)
	u.waitUI("key field cleared", `document.getElementById('llm_api_key').value===''`)

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("saving the configuration contacted the provider %d time(s)", got)
	}
	if got := u.evalStr(`document.body.innerHTML`); strings.Contains(got, uiKey) {
		t.Fatal("the API key appears in the rendered page")
	}

	// The explicit Test button is the only thing that makes a chat request.
	u.click("llm_test")
	u.waitUI("test succeeded", `document.getElementById('view').textContent.indexOf('Connection OK')>=0`)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("Test made %d provider requests, want exactly 1", got)
	}

	// Fetch models is the other explicit action, and its result feeds the
	// free-text model field as suggestions.
	u.click("llm_models")
	u.waitUI("models fetched", `document.querySelectorAll('#llm_model_list option').length===2`)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("Fetch models made %d total provider requests, want 2", got)
	}

	// Navigating away and back must not repopulate the key field.
	u.eval(`navigate("#/dashboard")`)
	u.waitUI("dashboard rendered", `document.getElementById('view').dataset.view==='dashboard'`)
	u.eval(`navigate("#/settings")`)
	u.waitUI("settings re-rendered", `document.getElementById('view').dataset.view==='settings'`)
	u.waitUI("llm card reloaded", `document.querySelector('#view .detail') && document.getElementById('llm_api_key').value===''`)
	if !strings.Contains(u.evalStr(`document.querySelector('#view .detail').textContent`), "configured") {
		t.Fatal("the saved configuration is not shown after navigating back")
	}
	if got := u.evalStr(`document.body.innerHTML`); strings.Contains(got, uiKey) {
		t.Fatal("the API key appears in the rendered page after reload")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("re-opening the settings page made extra provider requests (total %d)", got)
	}
}

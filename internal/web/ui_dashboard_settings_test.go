package web_test

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/web"
)

func TestUIDashboardUsesCompactScanOverview(t *testing.T) {
	u := newUIHarness(t)
	now := time.Now()
	for _, scan := range []*domain.Scan{
		{ID: "created", Name: "New draft", State: domain.ScanCreated, CreatedAt: now},
		{ID: "reauth", Name: "Needs session", State: domain.ScanAwaitingAuth, CreatedAt: now.Add(-time.Second)},
		{ID: "canceling", Name: "Stopping", State: domain.ScanCanceling, CreatedAt: now.Add(-time.Minute)},
	} {
		if err := u.st.Scans().Create(u.ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := u.page.Navigate(u.ctx, u.url+"/#/dashboard", browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	u.waitUI("dashboard shows recent scans and lifecycle counts", `
		document.querySelector('main table')?.textContent.includes('Needs session') &&
		['awaiting_auth', 'created', 'canceling'].every((state) =>
			[...document.querySelectorAll('main span')].some((el) =>
				el.textContent === state && el.nextElementSibling?.textContent === '1'
			)
		)
	`)
	if u.evalBool(`performance.getEntriesByType('resource').some((e) => new URL(e.name).pathname === '/api/scans')`) {
		t.Fatal("dashboard requested the full scan list")
	}
}

func TestUISettingsCanRetryFailedLoads(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	u := newUIHarnessWithHandler(t, "", web.Capabilities{}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && unavailable.Load() && (r.URL.Path == "/api/llm/providers" || r.URL.Path == "/api/llm/config") {
				http.Error(w, "fixture unavailable", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	if _, err := u.page.Navigate(u.ctx, u.url+"/#/settings", browser.NavOptions{}); err != nil {
		t.Fatal(err)
	}
	u.waitUI("settings offer retry for both failed reads", `
		[...document.querySelectorAll('main [role="alert"]')].filter((alert) =>
			alert.textContent.includes('HTTP 503') && alert.querySelector('button')?.textContent === 'Retry'
		).length === 2
	`)
	if u.evalBool(`document.querySelector('main').textContent.includes('Usable providers (0/0)')`) {
		t.Fatal("settings displayed empty credentials during an outage")
	}
	unavailable.Store(false)
	u.mustClickText(`main [role="alert"] button`, "Retry")
	u.waitUI("settings recover without a navigation", `
		document.querySelector('main select[aria-label="Provider"]')?.querySelector('option[value="openrouter"]') &&
		!document.querySelector('main [role="alert"]')
	`)
}

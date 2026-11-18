package browser

// Tests for NavigateForm's same-origin warm-up. A form POST must be submitted
// from a document that is already on the form target's own origin: Chromium
// decides same-site/cross-site from the SUBMITTING document's origin, and a
// fresh page is about:blank (opaque), so the POST would be cross-site and every
// SameSite=Lax/Strict cookie — the scan's authenticated session among them —
// would be withheld. These tests use a fake driver, so they need no browser;
// the real-browser proof is in samesite_form_integration_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/indago/indago/internal/ratelimit"
)

// formFakePage is a pageHandle that can submit a form and report the URL of the
// document it currently holds, so NavigateForm's warm-up policy is testable
// without Chromium. Each Goto/GotoForm moves the fake's notion of the current
// URL, exactly as a real navigation would.
type formFakePage struct {
	*fakePage
	current string   // URL of the document currently loaded
	landOn  string   // final URL a warm-up Goto resolves to ("" = the requested URL)
	gotos   []string // URLs passed to Goto, in order
	forms   []formCall
}

type formCall struct {
	method string
	url    string
	fields map[string]string
}

func (p *formFakePage) CurrentURL() string { return p.current }

func (p *formFakePage) Goto(url, referer, waitUntil string, timeout time.Duration) (int, string, error) {
	p.gotos = append(p.gotos, url)
	final := p.landOn
	if final == "" {
		final = url
	}
	p.current = final
	return 200, final, nil
}

func (p *formFakePage) GotoForm(method, url string, fields map[string]string, waitUntil string, timeout time.Duration) (int, string, error) {
	p.forms = append(p.forms, formCall{method: method, url: url, fields: fields})
	p.current = url
	return 200, url, nil
}

func newFormTestPage(t *testing.T, current string) (*Page, *formFakePage) {
	t.Helper()
	d := &fakeDriver{}
	m := newFakeManager(t, Config{PoolSize: 1}, d)
	t.Cleanup(func() { _ = m.Close() })
	// NavigateForm is the state-changing (POST) path, so the context needs the
	// scan's explicit opt-in; these tests are about the origin warm-up.
	c, err := m.NewContext(context.Background(), ContextOptions{
		AllowRequest:       func(string) bool { return true },
		AllowStateChanging: true,
	})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	ph := &formFakePage{fakePage: &fakePage{}, current: current}
	p, err := newPage(c, ph)
	if err != nil {
		t.Fatalf("newPage: %v", err)
	}
	return p, ph
}

// A brand-new page is about:blank. NavigateForm must first put the document on
// the target's own origin — with the exact target URL, which the caller already
// had authorized — and only then submit the form.
func TestNavigateFormWarmsUpAnAboutBlankPageToTheTargetOrigin(t *testing.T) {
	p, ph := newFormTestPage(t, "about:blank")
	const target = "http://127.0.0.1:8080/app/submit"

	nav, err := p.NavigateForm(context.Background(), "POST", target, map[string]string{"q": "value & more"}, NavOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NavigateForm: %v", err)
	}
	if nav.Status != 200 {
		t.Fatalf("status = %d, want 200", nav.Status)
	}
	if len(ph.gotos) != 1 || ph.gotos[0] != target {
		t.Fatalf("warm-up navigations = %v, want exactly [%s]", ph.gotos, target)
	}
	if len(ph.forms) != 1 {
		t.Fatalf("form submissions = %d, want 1", len(ph.forms))
	}
	got := ph.forms[0]
	if got.method != "POST" || got.url != target {
		t.Fatalf("form submitted as %s %s, want POST %s", got.method, got.url, target)
	}
	if got.fields["q"] != "value & more" {
		t.Fatalf("form field q = %q, want the caller's exact value", got.fields["q"])
	}
}

// A page already on the target's origin (the DOM-XSS replay navigates there
// first) must not pay for a second navigation.
func TestNavigateFormSkipsWarmUpWhenPageIsAlreadyOnTheTargetOrigin(t *testing.T) {
	for _, tc := range []struct{ name, current string }{
		{"same path", "http://127.0.0.1:8080/app/list"},
		{"default http port written explicitly", "http://127.0.0.1:80/app/list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := "http://127.0.0.1:8080/app/submit"
			if tc.current == "http://127.0.0.1:80/app/list" {
				target = "http://127.0.0.1/app/submit"
			}
			p, ph := newFormTestPage(t, tc.current)
			if _, err := p.NavigateForm(context.Background(), "POST", target, map[string]string{"q": "x"}, NavOptions{Timeout: 5 * time.Second}); err != nil {
				t.Fatalf("NavigateForm: %v", err)
			}
			if len(ph.gotos) != 0 {
				t.Fatalf("warm-up navigations = %v, want none (page already same-origin)", ph.gotos)
			}
			if len(ph.forms) != 1 {
				t.Fatalf("form submissions = %d, want 1", len(ph.forms))
			}
		})
	}
}

// If the warm-up cannot land on the target's origin, the POST would be
// cross-site (session cookie withheld) — refuse it with a named error instead of
// producing an unauthenticated replay that looks like a rejected candidate.
func TestNavigateFormRefusesWhenWarmUpLeavesTheTargetOrigin(t *testing.T) {
	p, ph := newFormTestPage(t, "about:blank")
	ph.landOn = "https://elsewhere.example.test/login"

	_, err := p.NavigateForm(context.Background(), "POST", "http://127.0.0.1:8080/app/submit", map[string]string{"q": "x"}, NavOptions{Timeout: 5 * time.Second})
	if !errors.Is(err, ErrFormOriginUnavailable) {
		t.Fatalf("err = %v, want ErrFormOriginUnavailable", err)
	}
	if len(ph.forms) != 0 {
		t.Fatalf("form submissions = %d, want 0 (a cross-site POST must never be sent)", len(ph.forms))
	}
}

// A relative or non-HTTP action URL has no origin to warm up to: leave the
// submission to report the problem itself rather than inventing a navigation.
func TestNavigateFormSkipsWarmUpWithoutAnHTTPOrigin(t *testing.T) {
	p, ph := newFormTestPage(t, "about:blank")
	if _, err := p.NavigateForm(context.Background(), "POST", "/submit", map[string]string{"q": "x"}, NavOptions{Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("NavigateForm: %v", err)
	}
	if len(ph.gotos) != 0 {
		t.Fatalf("warm-up navigations = %v, want none for a relative action", ph.gotos)
	}
	if len(ph.forms) != 1 {
		t.Fatalf("form submissions = %d, want 1", len(ph.forms))
	}
}

// The warm-up is a real target-facing request, so it takes its own permit from
// the scan's shared limiter: two navigations, two permits.
func TestNavigateFormPacesTheWarmUpAndTheSubmissionSeparately(t *testing.T) {
	p, _ := newFormTestPage(t, "about:blank")
	ctx := context.Background()
	l := ratelimit.New(10) // 100ms interval; consume the first permit.
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := p.NavigateForm(ctx, "POST", "http://127.0.0.1:8080/app/submit", map[string]string{"q": "x"}, NavOptions{Limiter: l, Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("NavigateForm: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 180*time.Millisecond {
		t.Fatalf("warm-up + submission took %v after reserving one permit; want two paced requests (~200ms)", elapsed)
	}
}

func TestSameOriginMatchesChromium(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b", true},
		{"http://127.0.0.1/a", "http://127.0.0.1:80/b", true},
		{"https://app.example.test/a", "https://app.example.test:443/b", true},
		{"HTTP://App.Example.Test/a", "http://app.example.test/b", true},
		{"http://127.0.0.1:8080/a", "http://127.0.0.1:8081/b", false},
		{"http://app.example.test/a", "https://app.example.test/b", false},
		{"http://app.example.test/a", "http://other.example.test/b", false},
		{"http://app.example.test/a", "http://sub.app.example.test/b", false},
		{"http://[::1]:8080/a", "http://[::1]:8080/b", true},
		{"http://[::1]:8080/a", "http://[::1]:8081/b", false},
	} {
		a, aok := parseHTTPURL(tc.a)
		b, bok := parseHTTPURL(tc.b)
		if !aok || !bok {
			t.Fatalf("parse %q / %q failed", tc.a, tc.b)
		}
		if got := sameOrigin(a, b); got != tc.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

package browser

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recordingRenderBrowser is a Browser that records renders, so the decorator's
// pass-through and fail-closed behaviour can be asserted without a browser.
type recordingRenderBrowser struct {
	renders int
	closed  int
	err     error
}

func (b *recordingRenderBrowser) Render(context.Context, string, RenderOptions) (*RenderResult, error) {
	b.renders++
	if b.err != nil {
		return nil, b.err
	}
	return &RenderResult{Status: 200}, nil
}

func (b *recordingRenderBrowser) Close() error {
	b.closed++
	return nil
}

func TestWithProxyPoolPassesThroughWhenNoPool(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    Browser
		pool []string
	}{
		{"nil browser", nil, []string{"http://127.0.0.1:1"}},
		{"nil pool", &recordingRenderBrowser{}, nil},
		{"empty pool", &recordingRenderBrowser{}, []string{}},
		{"blank entries", &recordingRenderBrowser{}, []string{"", "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WithProxyPool(tc.b, tc.pool); got != tc.b {
				t.Fatalf("WithProxyPool returned a decorator (%T) where the direct path must stay unchanged", got)
			}
		})
	}
}

func TestProxyPoolRotationIsRoundRobin(t *testing.T) {
	pool := []string{"http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"}
	w, ok := WithProxyPool(&recordingRenderBrowser{}, pool).(*proxyPoolBrowser)
	if !ok {
		t.Fatalf("WithProxyPool did not return a proxyPoolBrowser")
	}
	for i, want := range []string{pool[0], pool[1], pool[2], pool[0], pool[1]} {
		if got := w.nextProxy(); got != want {
			t.Fatalf("nextProxy #%d = %q, want %q", i, got, want)
		}
	}
}

// A Browser that cannot carry a proxy must REFUSE the render, not fall back to
// a direct connection: silently going direct is the bug this decorator exists
// to prevent.
func TestWithProxyPoolFailsClosedForBrowserThatCannotProxy(t *testing.T) {
	inner := &recordingRenderBrowser{}
	b := WithProxyPool(inner, []string{"http://127.0.0.1:3128"})
	_, err := b.Render(context.Background(), "http://target.example/page", RenderOptions{})
	if !errors.Is(err, ErrProxyUnsupported) {
		t.Fatalf("Render = %v, want ErrProxyUnsupported", err)
	}
	if inner.renders != 0 {
		t.Fatalf("inner Browser rendered %d time(s); a scan with a proxy pool must never send a direct render", inner.renders)
	}
	if strings.Contains(err.Error(), "user:") {
		t.Fatalf("error leaked credentials: %v", err)
	}
}

func TestProxyDecoratorNeverClosesTheSharedBrowser(t *testing.T) {
	inner := &recordingRenderBrowser{}
	b := WithProxyPool(inner, []string{"http://127.0.0.1:3128"})
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inner.closed != 0 {
		t.Fatalf("decorator closed the shared Browser; another scan's browser work would die with it")
	}
}

func TestRedactProxyCredentials(t *testing.T) {
	plain := errors.New("context: proxy http://127.0.0.1:3128 refused")
	if got := redactProxyCredentials(plain, "http://127.0.0.1:3128"); got != plain {
		t.Fatalf("redaction changed an error with no credentials: %v", got)
	}

	cause := errors.New(`browser: new context: proxy http://user:s3cr3t@proxy.example:3128 refused`)
	got := redactProxyCredentials(cause, "http://user:s3cr3t@proxy.example:3128")
	if strings.Contains(got.Error(), "s3cr3t") {
		t.Fatalf("credentials survived redaction: %v", got)
	}
	if !strings.Contains(got.Error(), "***@proxy.example:3128") {
		t.Fatalf("redacted error = %q, want the host to remain readable", got)
	}
	if !errors.Is(got, cause) {
		t.Fatalf("redaction broke the error chain; callers classify this error")
	}

	// The error must not be rewritten when the secret is not echoed back.
	unrelated := errors.New("browser: launch failed")
	if got := redactProxyCredentials(unrelated, "http://user:s3cr3t@proxy.example:3128"); got != unrelated {
		t.Fatalf("redaction rewrote an unrelated error: %v", got)
	}
}

func TestRedactURLDropsCredentialsAndQuery(t *testing.T) {
	got := redactURL("http://user:pass@target.example/a?token=secret#frag")
	if strings.Contains(got, "pass") || strings.Contains(got, "secret") {
		t.Fatalf("redactURL leaked: %q", got)
	}
	if !strings.Contains(got, "target.example/a") {
		t.Fatalf("redactURL = %q, want the host and path", got)
	}
}

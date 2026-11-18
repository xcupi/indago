package browser_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/indago/indago/internal/browser"
)

// Every control uses the same owned destination as its scoped run. In
// particular a successful Evaluate or a popup event is not evidence of traffic.
func TestIntegrationScopeGateRejectsUnmanagedTargets(t *testing.T) {
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	for _, tc := range []struct {
		name, script string
		direct       bool
	}{
		{"ordinary-anchor", `const a=document.createElement('a');a.target='_blank';a.href='/api/redirect';document.body.append(a);a.click();`, false},
		{"late-anchor-target", `const a=document.createElement('a');a.href='/api/redirect';document.body.append(a);a.addEventListener('click',()=>{a.target='_blank'});a.click();`, false},
		{"closed-shadow-anchor", `const h=document.createElement('div');document.body.append(h);const s=h.attachShadow({mode:'closed'});const a=document.createElement('a');a.href='/api/redirect';a.target='_blank';s.append(a);a.click();`, false},
		{"late-form-target", `const f=document.createElement('form');f.action='/api/redirect';f.method='POST';const b=document.createElement('button');f.append(b);document.body.append(f);f.addEventListener('submit',()=>{f.target='_blank'});f.requestSubmit();`, false},
		{"direct-denied-popup", `const h=document.createElement('div');document.body.append(h);const s=h.attachShadow({mode:'closed'});const a=document.createElement('a');a.href='/outside';a.target='_blank';s.append(a);a.click();`, true},
		{"window-open", `window.open('/api/redirect','_blank');`, false},
		{"blank-then-navigate", `const p=window.open('about:blank','_blank');if(p)p.location='/api/redirect';`, false},
		{"submitter-override", `const f=document.createElement('form');f.action='/api/redirect';const b=document.createElement('button');b.formTarget='_blank';f.append(b);document.body.append(f);b.click();`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var start, outside atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/page":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, `<!doctype html><body>popup boundary</body>`)
				case "/api/redirect":
					start.Add(1)
					http.Redirect(w, r, "/outside", http.StatusFound)
				case "/outside":
					outside.Add(1)
					fmt.Fprint(w, "outside")
				default:
					http.NotFound(w, r)
				}
			}))
			t.Logf("OWNED_LISTENER=%s", srv.URL)
			defer srv.Close()
			for _, scoped := range []bool{false, true} {
				opts := browser.ContextOptions{}
				if scoped {
					opts.AllowRequest = func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") }
				} else {
					// This is the NON-scoped control: it must let the POST form
					// shape actually run, so the shape is shown to be
					// discriminating rather than inert. State-changing requests
					// are therefore explicitly allowed here.
					opts.AllowStateChanging = true
				}
				c, err := m.NewContext(context.Background(), opts)
				if err != nil {
					t.Fatal(err)
				}
				p, err := c.NewPage(context.Background())
				if err != nil {
					c.Close()
					t.Fatal(err)
				}
				if _, err := p.Navigate(context.Background(), srv.URL+"/api/page", browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 5 * time.Second}); err != nil {
					c.Close()
					t.Fatal(err)
				}
				if _, err := p.Evaluate(context.Background(), `(() => {`+tc.script+`;return true})()`); err != nil {
					c.Close()
					t.Fatal(err)
				}
				// Give first-navigation redirects time to escape; close the whole context
				// before reading final counters so no request can outlive the assertion.
				time.Sleep(350 * time.Millisecond)
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				t.Logf("RESULT scoped=%v redirect_hits=%d outside_hits=%d", scoped, start.Load(), outside.Load())
				if scoped {
					if start.Load() != 0 || outside.Load() != 0 {
						t.Fatalf("unapproved target sent traffic: redirect_hits=%d outside_hits=%d", start.Load(), outside.Load())
					}
				} else {
					wantStart := int64(1)
					if tc.direct {
						wantStart = 0
					}
					if start.Load() != wantStart || outside.Load() != 1 {
						t.Fatalf("nondiscriminating control: redirect_hits=%d outside_hits=%d", start.Load(), outside.Load())
					}
					start.Store(0)
					outside.Store(0)
				}
			}
		})
	}
}

func TestIntegrationScopeGatePreservesBodyReplay(t *testing.T) {
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	for _, kind := range []string{"form", "json"} {
		t.Run(kind, func(t *testing.T) {
			type request struct{ method, body, contentType, cookie string }
			seen := make(chan request, 2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/replay" {
					http.NotFound(w, r)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
				if err != nil {
					http.Error(w, "body", 400)
					return
				}
				cookie, _ := r.Cookie("lab")
				value := ""
				if cookie != nil {
					value = cookie.Value
				}
				seen <- request{r.Method, string(body), r.Header.Get("Content-Type"), value}
				w.Header().Set("Content-Type", "text/html")
				if r.Method != http.MethodPost {
					// The same-origin warm-up GET only needs a document. Keep it
					// script-free so the execution assertion below can only be
					// satisfied by the replayed POST response.
					fmt.Fprint(w, `<!doctype html><body>warm-up</body>`)
					return
				}
				fmt.Fprint(w, `<!doctype html><body>replayed<script>indScopeReplayMarker</script>`)
			}))
			t.Logf("OWNED_LISTENER=%s", srv.URL)
			defer srv.Close()
			c, err := m.NewContext(context.Background(), browser.ContextOptions{AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") }, AllowStateChanging: true})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.SetCookies(context.Background(), []browser.Cookie{{Name: "lab", Value: "dummy", URL: srv.URL}}); err != nil {
				t.Fatal(err)
			}
			p, err := c.NewPage(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			opts := browser.NavOptions{WaitUntil: browser.WaitLoad, Timeout: 5 * time.Second}
			if kind == "form" {
				_, err = p.NavigateForm(context.Background(), "POST", srv.URL+"/api/replay", map[string]string{"q": "one & two"}, opts)
			} else {
				_, err = p.NavigateJSON(context.Background(), srv.URL+"/api/replay", []byte(`{"q":"one & two","n":2}`), "application/json", opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			// A POST/form replay first warms the page up on the target's own
			// origin with one readable GET (without it the form would be
			// submitted cross-site from about:blank and lose SameSite=Lax
			// cookies — see browser.Page.NavigateForm), so the fixture
			// legitimately sees that GET before the POST asserted on here.
			var warmUps []request
			var got request
			deadline := time.After(2 * time.Second)
		readEvents:
			for {
				select {
				case ev := <-seen:
					if ev.method == "POST" {
						got = ev
						break readEvents
					}
					warmUps = append(warmUps, ev)
				case <-deadline:
					t.Fatal("replay did not reach fixture")
				}
			}
			if kind == "form" {
				if len(warmUps) != 1 || warmUps[0].method != "GET" {
					t.Fatalf("form replay warm-up requests = %+v, want exactly one same-origin GET", warmUps)
				}
			} else if len(warmUps) != 0 {
				t.Fatalf("unexpected requests before the JSON replay: %+v", warmUps)
			}
			body, media := "q=one+%26+two", "application/x-www-form-urlencoded"
			if kind == "json" {
				body, media = `{"q":"one & two","n":2}`, "application/json"
			}
			if got.method != "POST" || got.body != body || !strings.HasPrefix(got.contentType, media) || got.cookie != "dummy" {
				t.Fatalf("replay mismatch: %+v", got)
			}
			t.Logf("RESULT kind=%s warmUps=%d method=%s body=%q media=%s cookie_present=%v", kind, len(warmUps), got.method, got.body, got.contentType, got.cookie != "")
			if !strings.Contains(strings.Join(p.PageErrors(), "\n"), "indScopeReplayMarker is not defined") {
				t.Fatalf("replayed response did not execute: %v", p.PageErrors())
			}
		})
	}
}

func TestIntegrationScopeGateManagedFramesAndSubresources(t *testing.T) {
	var frameStart, frameFinal, imageStart, imageFinal, deniedStart, outside atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/page":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!doctype html><iframe src="/api/frame-start"></iframe><iframe src="/api/frame-denied"></iframe><img src="/api/image-start">`)
		case "/api/frame-start":
			frameStart.Add(1)
			http.Redirect(w, r, "/api/frame-final", 302)
		case "/api/frame-final":
			frameFinal.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "child frame")
		case "/api/frame-denied":
			deniedStart.Add(1)
			http.Redirect(w, r, "/outside", 302)
		case "/api/image-start":
			imageStart.Add(1)
			http.Redirect(w, r, "/api/image-final", 302)
		case "/api/image-final":
			imageFinal.Add(1)
			w.WriteHeader(204)
		case "/outside":
			outside.Add(1)
			fmt.Fprint(w, "outside")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Logf("OWNED_LISTENER=%s", srv.URL)
	defer srv.Close()
	m := newManagerOrSkip(t, browser.DefaultConfig())
	defer m.Close()
	_, err := m.Render(context.Background(), srv.URL+"/api/page", browser.RenderOptions{WaitUntil: browser.WaitNetworkIdle, AllowRequest: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/api/") }})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT frame_start=%d frame_final=%d denied_start=%d image_start=%d image_final=%d outside=%d", frameStart.Load(), frameFinal.Load(), deniedStart.Load(), imageStart.Load(), imageFinal.Load(), outside.Load())
	if frameStart.Load() != 1 || frameFinal.Load() != 1 || deniedStart.Load() != 1 || imageStart.Load() != 1 || imageFinal.Load() != 1 || outside.Load() != 0 {
		t.Fatal("managed frame/subresource redirect compatibility failed")
	}
}

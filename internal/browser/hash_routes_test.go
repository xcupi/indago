package browser

import (
	"context"
	"strings"
	"testing"
	"time"
)

type hashTestDriver struct {
	contexts int
	gotos    int
	evals    []string
}

func (d *hashTestDriver) Launch(bool) (browserHandle, error) { return d, nil }
func (d *hashTestDriver) Stop() error                        { return nil }
func (d *hashTestDriver) NewContext(string, string, map[string]string, func(string) bool, bool, bool) (contextHandle, error) {
	d.contexts++
	return d, nil
}
func (d *hashTestDriver) NewPage() (pageHandle, error)  { return &hashTestPage{drv: d}, nil }
func (d *hashTestDriver) AddCookies([]Cookie) error     { return nil }
func (d *hashTestDriver) Cookies() ([]Cookie, error)    { return nil, nil }
func (d *hashTestDriver) SaveStorageState(string) error { return nil }
func (d *hashTestDriver) Close() error                  { return nil }

type hashTestPage struct {
	drv   *hashTestDriver
	hash  string
	onReq func(NetworkEvent)
}

func (p *hashTestPage) EnableRuntimeProvenance(string, string) error { return nil }
func (p *hashTestPage) RuntimeObservations() RuntimeObservations     { return RuntimeObservations{} }
func (p *hashTestPage) Goto(url, _, _ string, _ time.Duration) (int, string, error) {
	p.drv.gotos++
	if p.onReq != nil {
		p.onReq(NetworkEvent{URL: url, Method: "GET"})
	}
	return 200, url, nil
}
func (p *hashTestPage) Content() (string, error) {
	return "<html><body>" + p.hash + "</body></html>", nil
}
func (p *hashTestPage) Screenshot(bool) ([]byte, error) { return nil, nil }
func (p *hashTestPage) Evaluate(script string, arg any) (any, error) {
	if strings.Contains(script, "window.location.hash") {
		if h, ok := arg.(string); ok {
			p.hash = h
			p.drv.evals = append(p.drv.evals, h)
			if p.onReq != nil {
				p.onReq(NetworkEvent{
					URL:    "http://example.test/api/" + strings.TrimPrefix(h, "#/"),
					Method: "GET",
				})
			}
		}
	}
	return nil, nil
}
func (p *hashTestPage) OnRequest(cb func(NetworkEvent), _ func(string) bool) error {
	p.onReq = cb
	return nil
}
func (p *hashTestPage) OnConsole(func(ConsoleMessage)) {}
func (p *hashTestPage) OnDialog(func(string))          {}
func (p *hashTestPage) OnPageError(func(string))       {}
func (p *hashTestPage) WaitForURL(string, time.Duration) error {
	return nil
}
func (p *hashTestPage) AddInitScript(string) error { return nil }
func (p *hashTestPage) Close() error               { return nil }

func TestManagerRenderHashRoutesSingleContext(t *testing.T) {
	drv := &hashTestDriver{}
	m, err := newManager(DefaultConfig(), quiet(), func() (driver, error) { return drv, nil })
	if err != nil {
		t.Fatalf("newManager: %v", err)
	}
	defer m.Close()

	frags := []string{"#/one", "#/two", "lesson/Three.lesson"}
	res, err := m.RenderHashRoutes(context.Background(), "http://example.test/start.mvc", frags, RenderOptions{
		ObservationWindow: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RenderHashRoutes: %v", err)
	}
	if drv.contexts != 1 || drv.gotos != 1 {
		t.Fatalf("contexts=%d gotos=%d, want 1 and 1", drv.contexts, drv.gotos)
	}
	if len(res) != 3 {
		t.Fatalf("len(res)=%d, want 3", len(res))
	}
	if res[0].FinalURL != "http://example.test/start.mvc#/one" || len(res[0].Network) != 1 || res[0].Network[0].URL != "http://example.test/api/one" {
		t.Fatalf("res[0] = %+v", res[0])
	}
	if res[2].FinalURL != "http://example.test/start.mvc#lesson/Three.lesson" || !strings.Contains(res[2].HTML, "#lesson/Three.lesson") {
		t.Fatalf("res[2] = %+v", res[2])
	}
}

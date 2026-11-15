package fingerprint_test

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/fingerprint"
)

// sample is a compact description of one observed response for table tests.
type sample struct {
	url     string
	status  int
	server  string
	ct      string
	header  map[string]string // extra headers (single value)
	cookies []string          // Set-Cookie values, in order
	body    string
}

func (s sample) profile(t *testing.T) fingerprint.Profile {
	t.Helper()
	h := http.Header{}
	if s.server != "" {
		h.Set("Server", s.server)
	}
	if s.ct != "" {
		h.Set("Content-Type", s.ct)
	}
	for k, v := range s.header {
		h.Set(k, v)
	}
	for _, c := range s.cookies {
		h.Add("Set-Cookie", c)
	}
	u := s.url
	if u == "" {
		u = "https://example.test/"
	}
	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	return fingerprint.Analyze(fingerprint.Observation{
		URL:    u,
		Status: status,
		Header: h,
		Body:   []byte(s.body),
	})
}

func containsSignal(p fingerprint.Profile, class, source, tech string) bool {
	for _, s := range p.Signals {
		if s.Class == class && s.Source == source && s.Tech == tech {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Stack detection
// ---------------------------------------------------------------------------

func TestAnalyzeWordPressPHP(t *testing.T) {
	p := sample{
		url:    "https://example.test/wp-login.php",
		server: "nginx/1.24.0",
		ct:     "text/html; charset=UTF-8",
		header: map[string]string{"X-Powered-By": "PHP/8.2.1"},
		cookies: []string{
			"PHPSESSID=supersecretvalue123; path=/; HttpOnly",
			"wordpress_test_cookie=WP+Cookie+check",
		},
		body: `<!DOCTYPE html><html><head>` +
			`<link rel="stylesheet" href="/wp-content/themes/x/style.css">` +
			`</head><body>log in</body></html>`,
	}.profile(t)

	if p.ContentKind != fingerprint.KindHTML {
		t.Errorf("ContentKind = %q, want html", p.ContentKind)
	}
	if p.ContentType != "text/html" {
		t.Errorf("ContentType = %q, want text/html (parameters stripped)", p.ContentType)
	}
	if !reflect.DeepEqual(p.Languages, []fingerprint.Language{fingerprint.LangPHP}) {
		t.Errorf("Languages = %v, want [php]", p.Languages)
	}
	if !reflect.DeepEqual(p.Frameworks, []fingerprint.Framework{fingerprint.FwWordPress}) {
		t.Errorf("Frameworks = %v, want [wordpress]", p.Frameworks)
	}
	wantHints := []string{fingerprint.TplTwig, fingerprint.TplSmarty, fingerprint.TplBlade}
	if !reflect.DeepEqual(p.TemplateHints, wantHints) {
		t.Errorf("TemplateHints = %v, want %v", p.TemplateHints, wantHints)
	}
	if p.Server != "nginx/1.24.0" || p.PoweredBy != "PHP/8.2.1" {
		t.Errorf("server/powered-by = %q/%q", p.Server, p.PoweredBy)
	}
	if p.StaticAsset {
		t.Error("StaticAsset = true, want false for an HTML page")
	}
	if !p.Dynamic {
		t.Error("Dynamic = false, want true for an identified application")
	}
	for _, want := range []struct{ class, source, tech string }{
		{fingerprint.ClassLanguage, fingerprint.SourceHeader, "php"},
		{fingerprint.ClassLanguage, fingerprint.SourceCookie, "php"},
		{fingerprint.ClassFramework, fingerprint.SourceBody, "wordpress"},
		{fingerprint.ClassFramework, fingerprint.SourceURL, "wordpress"},
	} {
		if !containsSignal(p, want.class, want.source, want.tech) {
			t.Errorf("missing %s signal for %s from %s; signals: %+v", want.class, want.tech, want.source, p.Signals)
		}
	}
}

func TestAnalyzeJavaSpring(t *testing.T) {
	p := sample{
		server:  "Apache-Coyote/1.1",
		ct:      "text/html;charset=UTF-8",
		header:  map[string]string{"X-Application-Context": "application:prod"},
		cookies: []string{"JSESSIONID=node01abc.node0"},
		body:    `<html><body><h1>Whitelabel Error Page</h1><p>org.springframework.web.servlet</p></body></html>`,
	}.profile(t)

	if !reflect.DeepEqual(p.Languages, []fingerprint.Language{fingerprint.LangJava}) {
		t.Errorf("Languages = %v, want [java]", p.Languages)
	}
	if !p.HasFramework(fingerprint.FwSpring) {
		t.Errorf("Frameworks = %v, want spring", p.Frameworks)
	}
	want := []string{fingerprint.TplThymeleaf, fingerprint.TplFreemarker, fingerprint.TplVelocity, fingerprint.TplSpEL}
	if !reflect.DeepEqual(p.TemplateHints, want) {
		t.Errorf("TemplateHints = %v, want %v", p.TemplateHints, want)
	}

	ok, engines := fingerprint.ShouldProbeSSTI(p)
	if !ok {
		t.Fatal("ShouldProbeSSTI = false, want true for a Spring HTML page")
	}
	if !reflect.DeepEqual(engines, want) {
		t.Errorf("recommended engines = %v, want %v", engines, want)
	}
}

func TestAnalyzeJSONFlask(t *testing.T) {
	p := sample{
		server: "Werkzeug/3.0.1 Python/3.12.1",
		ct:     "application/json; charset=utf-8",
		body:   `{"ok":true,"items":[1,2,3]}`,
	}.profile(t)

	if p.ContentKind != fingerprint.KindJSON {
		t.Fatalf("ContentKind = %q, want json", p.ContentKind)
	}
	if !p.HasLanguage(fingerprint.LangPython) || !p.HasFramework(fingerprint.FwFlask) {
		t.Errorf("languages/frameworks = %v/%v, want python/flask", p.Languages, p.Frameworks)
	}
	want := []string{fingerprint.TplJinja2, fingerprint.TplDjango, fingerprint.TplMako}
	if !reflect.DeepEqual(p.TemplateHints, want) {
		t.Errorf("TemplateHints = %v, want %v", p.TemplateHints, want)
	}

	if ok, engines := fingerprint.ShouldProbeSSTI(p); ok || engines != nil {
		t.Errorf("ShouldProbeSSTI = %v,%v; want false,nil — JSON is not a rendered template", ok, engines)
	}
	if !fingerprint.ShouldProbeXSS(p) {
		t.Error("ShouldProbeXSS = false; JSON responses are still probed")
	}
	if !fingerprint.ShouldProbeCommandInjection(p) {
		t.Error("ShouldProbeCommandInjection = false; want true for an identified app")
	}
	if fingerprint.ShouldProbeXXE(p, "application/json", `{"id":1}`) {
		t.Error("ShouldProbeXXE = true for a JSON request/response pair")
	}
}

func TestAnalyzeBinaryDownload(t *testing.T) {
	p := sample{
		url: "https://example.test/files/quarterly.pdf",
		ct:  "application/pdf",
		header: map[string]string{
			"Content-Disposition": `attachment; filename="quarterly.pdf"`,
		},
		body: "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
	}.profile(t)

	if p.ContentKind != fingerprint.KindBinary {
		t.Fatalf("ContentKind = %q, want binary", p.ContentKind)
	}
	if !p.StaticAsset {
		t.Fatal("StaticAsset = false, want true for an attachment")
	}
	if !reflect.DeepEqual(p.TemplateHints, []string{fingerprint.TplNone}) {
		t.Errorf("TemplateHints = %v, want [none]", p.TemplateHints)
	}
	if fingerprint.ShouldProbeXSS(p) {
		t.Error("ShouldProbeXSS = true for a binary download")
	}
	if ok, engines := fingerprint.ShouldProbeSSTI(p); ok || engines != nil {
		t.Errorf("ShouldProbeSSTI = %v,%v for a binary download", ok, engines)
	}
	if fingerprint.ShouldProbeCommandInjection(p) {
		t.Error("ShouldProbeCommandInjection = true for a binary download")
	}
	if fingerprint.ShouldProbeXXE(p, "", "") {
		t.Error("ShouldProbeXXE = true with no XML anywhere")
	}
}

func TestAnalyzeNoEvidence(t *testing.T) {
	p := fingerprint.Analyze(fingerprint.Observation{})
	if p.ContentKind != fingerprint.KindUnknown {
		t.Errorf("ContentKind = %q, want unknown", p.ContentKind)
	}
	if !reflect.DeepEqual(p.TemplateHints, []string{fingerprint.TplNone}) {
		t.Errorf("TemplateHints = %v, want [none]", p.TemplateHints)
	}
	if p.Dynamic {
		t.Error("Dynamic = true with no evidence")
	}
	if !fingerprint.ShouldProbeXSS(p) {
		t.Error("ShouldProbeXSS = false for an ambiguous response; want true")
	}
	if ok, _ := fingerprint.ShouldProbeSSTI(p); ok {
		t.Error("ShouldProbeSSTI = true with no stack evidence")
	}
	if fingerprint.ShouldProbeCommandInjection(p) {
		t.Error("ShouldProbeCommandInjection = true with no evidence at all")
	}
}

func TestFrameworkImpliesLanguage(t *testing.T) {
	p := sample{
		ct:   "text/html",
		body: `<html><body><img src="/wp-content/uploads/x.png"></body></html>`,
	}.profile(t)
	if !p.HasFramework(fingerprint.FwWordPress) {
		t.Fatalf("Frameworks = %v, want wordpress", p.Frameworks)
	}
	if !p.HasLanguage(fingerprint.LangPHP) {
		t.Errorf("Languages = %v, want php implied by WordPress", p.Languages)
	}
}

func TestLanguageFromURLExtension(t *testing.T) {
	cases := []struct {
		url  string
		want fingerprint.Language
	}{
		{"https://example.test/index.php", fingerprint.LangPHP},
		{"https://example.test/app.PHP", fingerprint.LangPHP},
		{"https://example.test/account.aspx", fingerprint.LangDotNet},
		{"https://example.test/report.jsp", fingerprint.LangJava},
		{"https://example.test/login.do", fingerprint.LangJava},
		{"https://example.test/job.py", fingerprint.LangPython},
		{"https://example.test/x.rb", fingerprint.LangRuby},
		{"https://example.test/x.cgi", fingerprint.LangPerl},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			p := sample{url: c.url, ct: "text/html", body: "<html></html>"}.profile(t)
			if !p.HasLanguage(c.want) {
				t.Errorf("Languages = %v, want %s", p.Languages, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Content classification
// ---------------------------------------------------------------------------

func TestContentKind(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		kind fingerprint.ContentKind
		mt   string
	}{
		{"html", "text/html; charset=utf-8", "<html></html>", fingerprint.KindHTML, "text/html"},
		{"xhtml", "application/xhtml+xml", "<html xmlns='http://www.w3.org/1999/xhtml'></html>", fingerprint.KindHTML, "application/xhtml+xml"},
		{"json", "application/json", `{"a":1}`, fingerprint.KindJSON, "application/json"},
		{"json suffix", "application/problem+json", `{"title":"x"}`, fingerprint.KindJSON, "application/problem+json"},
		{"ndjson", "application/x-ndjson", "{\"a\":1}\n{\"a\":2}\n", fingerprint.KindJSON, "application/x-ndjson"},
		{"xml", "text/xml", "<a/>", fingerprint.KindXML, "text/xml"},
		{"soap", "application/soap+xml", "<a/>", fingerprint.KindXML, "application/soap+xml"},
		{"svg", "image/svg+xml", "<svg></svg>", fingerprint.KindXML, "image/svg+xml"},
		{"text", "text/plain", "hello", fingerprint.KindText, "text/plain"},
		{"csv", "text/csv; header=present", "a,b\n1,2\n", fingerprint.KindText, "text/csv"},
		{"javascript", "application/javascript", "var a=1;", fingerprint.KindText, "application/javascript"},
		{"octet-stream", "application/octet-stream", "<html>not really</html>", fingerprint.KindBinary, "application/octet-stream"},
		{"pdf", "application/pdf", "%PDF-1.7", fingerprint.KindBinary, "application/pdf"},
		{"png", "image/png", "\x89PNG\r\n\x1a\n", fingerprint.KindBinary, "image/png"},
		{"excel", "application/vnd.ms-excel", "\xd0\xcf\x11\xe0", fingerprint.KindBinary, "application/vnd.ms-excel"},
		{"sniff json", "", `{"a":1}`, fingerprint.KindJSON, ""},
		{"sniff xml", "", `<?xml version="1.0"?><a/>`, fingerprint.KindXML, ""},
		{"sniff svg", "", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`, fingerprint.KindXML, ""},
		{"sniff doctype", "", "<!DOCTYPE html><html></html>", fingerprint.KindHTML, ""},
		{"sniff html fragment", "", "<div>hi</div>", fingerprint.KindHTML, ""},
		{"sniff text", "", "plain words", fingerprint.KindText, ""},
		{"sniff binary nul", "", "abc\x00def", fingerprint.KindBinary, ""},
		{"sniff empty", "", "", fingerprint.KindUnknown, ""},
		{"malformed ct", "text/html; charset", "<html></html>", fingerprint.KindHTML, "text/html"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample{ct: c.ct, body: c.body}.profile(t)
			if p.ContentKind != c.kind {
				t.Errorf("ContentKind = %q, want %q", p.ContentKind, c.kind)
			}
			if p.ContentType != c.mt {
				t.Errorf("ContentType = %q, want %q", p.ContentType, c.mt)
			}
		})
	}
}

func TestStaticAssetClassification(t *testing.T) {
	cases := []struct {
		name string
		s    sample
		want bool
	}{
		{"css bundle", sample{url: "https://example.test/assets/app.css", ct: "text/css", body: "body{}"}, true},
		{"js bundle", sample{url: "https://example.test/assets/app.js", ct: "application/javascript", body: "var a;"}, true},
		{"image", sample{url: "https://example.test/logo.png", ct: "image/png", body: "\x89PNG"}, true},
		{"attachment labelled html", sample{url: "https://example.test/export", ct: "text/html", header: map[string]string{"Content-Disposition": "attachment; filename=x.html"}, body: "<html></html>"}, true},
		{"svg is a document", sample{url: "https://example.test/logo.svg", ct: "image/svg+xml", body: "<svg></svg>"}, false},
		{"html page", sample{url: "https://example.test/page.css", ct: "text/html", body: "<html></html>"}, false},
		{"json api", sample{url: "https://example.test/api/users", ct: "application/json", body: `{"a":1}`}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.profile(t).StaticAsset; got != c.want {
				t.Errorf("StaticAsset = %v, want %v", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

func TestShouldProbeXSS(t *testing.T) {
	cases := []struct {
		name string
		s    sample
		want bool
	}{
		{"html", sample{ct: "text/html", body: "<html></html>"}, true},
		{"json", sample{ct: "application/json", body: `{"a":1}`}, true},
		{"xml", sample{ct: "text/xml", body: "<a/>"}, true},
		{"text", sample{ct: "text/plain", body: "hi"}, true},
		{"svg", sample{ct: "image/svg+xml", body: "<svg></svg>"}, true},
		{"no content type", sample{body: "hi"}, true},
		{"empty response", sample{}, true},
		{"binary", sample{ct: "application/zip", body: "PK\x03\x04"}, false},
		{"image", sample{ct: "image/jpeg", body: "\xff\xd8\xff"}, false},
		{"download", sample{ct: "text/html", header: map[string]string{"Content-Disposition": "attachment"}, body: "<html></html>"}, false},
		{"css asset", sample{url: "https://example.test/a.css", ct: "text/css", body: "a{}"}, false},
		{"not modified", sample{status: http.StatusNotModified, ct: "text/html", body: ""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fingerprint.ShouldProbeXSS(c.s.profile(t)); got != c.want {
				t.Errorf("ShouldProbeXSS = %v, want %v", got, c.want)
			}
		})
	}
}

func TestShouldProbeSSTI(t *testing.T) {
	cases := []struct {
		name    string
		s       sample
		want    bool
		engines []string
	}{
		{
			name:    "php",
			s:       sample{ct: "text/html", server: "Apache/2.4", header: map[string]string{"X-Powered-By": "PHP/8.1"}, body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplTwig, fingerprint.TplSmarty, fingerprint.TplBlade},
		},
		{
			name:    "python",
			s:       sample{ct: "text/html", server: "gunicorn/21.2.0", body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplJinja2, fingerprint.TplDjango, fingerprint.TplMako},
		},
		{
			name:    "java",
			s:       sample{ct: "text/html", server: "Apache Tomcat/10.1", body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplFreemarker, fingerprint.TplVelocity, fingerprint.TplSpEL, fingerprint.TplThymeleaf},
		},
		{
			name:    "ruby",
			s:       sample{ct: "text/html", server: "WEBrick/1.8.1", body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplERB, fingerprint.TplHaml},
		},
		{
			name:    "node express",
			s:       sample{ct: "text/html", header: map[string]string{"X-Powered-By": "Express"}, body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplEJS, fingerprint.TplHandlebars, fingerprint.TplPug, fingerprint.TplNunjucks},
		},
		{
			name:    "dotnet",
			s:       sample{ct: "text/html", cookies: []string{"ASP.NET_SessionId=abc"}, body: "<html></html>"},
			want:    true,
			engines: []string{fingerprint.TplRazor},
		},
		{
			name: "unknown static stack",
			s:    sample{ct: "text/html", server: "nginx/1.24.0", body: "<html><body>hello</body></html>"},
			want: false,
		},
		{
			name: "perl has no modelled engine",
			s:    sample{ct: "text/html", server: "Apache/2.4 (Unix) mod_perl/2.0.12", body: "<html></html>"},
			want: false,
		},
		{
			name: "binary php",
			s:    sample{ct: "application/pdf", header: map[string]string{"X-Powered-By": "PHP/8.1"}, body: "%PDF"},
			want: false,
		},
		{
			name: "json php",
			s:    sample{ct: "application/json", header: map[string]string{"X-Powered-By": "PHP/8.1"}, body: `{"a":1}`},
			want: false,
		},
		{
			name: "nextjs shell",
			s:    sample{ct: "text/html", header: map[string]string{"X-Powered-By": "Express"}, body: `<html><body><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>`},
			want: false,
		},
		{
			name:    "nextjs shell with explicit engine evidence",
			s:       sample{ct: "text/html", header: map[string]string{"X-Powered-By": "Express"}, body: `<html><body><script id="__NEXT_DATA__" type="application/json">{}</script><pre>jinja2.exceptions.UndefinedError</pre></body></html>`},
			want:    true,
			engines: []string{fingerprint.TplJinja2, fingerprint.TplEJS, fingerprint.TplHandlebars, fingerprint.TplPug, fingerprint.TplNunjucks},
		},
		{
			name:    "json with explicit engine evidence",
			s:       sample{ct: "application/json", body: `{"error":"TemplateSyntaxError in jinja2"}`},
			want:    true,
			engines: []string{fingerprint.TplJinja2},
		},
		{
			name:    "explicit engine without a known language",
			s:       sample{ct: "text/html", body: "<p>Handlebars RuntimeError</p>"},
			want:    true,
			engines: []string{fingerprint.TplHandlebars},
		},
		{
			name: "not modified",
			s:    sample{status: http.StatusNotModified, ct: "text/html", header: map[string]string{"X-Powered-By": "PHP/8.1"}, body: ""},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, engines := fingerprint.ShouldProbeSSTI(c.s.profile(t))
			if ok != c.want {
				t.Fatalf("ShouldProbeSSTI = %v, want %v (engines %v)", ok, c.want, engines)
			}
			if !ok {
				if engines != nil {
					t.Errorf("engines = %v, want nil when not probing", engines)
				}
				return
			}
			if !reflect.DeepEqual(engines, c.engines) {
				t.Errorf("engines = %v, want %v", engines, c.engines)
			}
		})
	}
}

func TestShouldProbeSSTIHandBuiltProfile(t *testing.T) {
	// A caller that constructs a Profile by hand (no Signals) still gets a
	// useful answer from the hints it supplied.
	p := fingerprint.Profile{
		ContentKind:   fingerprint.KindHTML,
		TemplateHints: []string{fingerprint.TplJinja2, fingerprint.TplNone},
	}
	ok, engines := fingerprint.ShouldProbeSSTI(p)
	if !ok {
		t.Fatal("ShouldProbeSSTI = false for an explicit jinja2 hint")
	}
	if !reflect.DeepEqual(engines, []string{fingerprint.TplJinja2}) {
		t.Errorf("engines = %v, want [jinja2] (the none placeholder is dropped)", engines)
	}
}

func TestShouldProbeXXE(t *testing.T) {
	html := sample{ct: "text/html", body: "<html></html>"}.profile(t)
	jsonPage := sample{ct: "application/json", body: `{"a":1}`}.profile(t)
	xmlPage := sample{ct: "application/xml", body: "<a/>"}.profile(t)
	binary := sample{ct: "application/octet-stream", body: "\x00\x01"}.profile(t)
	formCT := "application/x-www-form-urlencoded"

	cases := []struct {
		name string
		p    fingerprint.Profile
		ct   string
		body string
		want bool
	}{
		{"xml request", html, "application/xml", "<a/>", true},
		{"text/xml request", html, "text/xml; charset=utf-8", "<a/>", true},
		{"soap request", html, "application/soap+xml", "<a/>", true},
		{"xml suffix request", html, "application/atom+xml", "<feed/>", true},
		{"xml response", xmlPage, "", "", true},
		{"xml declaration in body", html, "", `<?xml version="1.0"?><a/>`, true},
		{"xml in multipart body", html, "multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n<?xml version=\"1.0\"?><a/>\r\n--x--", true},
		{"percent-encoded xml", html, formCT, "data=%3C%3Fxml+version%3D%221.0%22%3F%3E%3Cnote%3E%3C%2Fnote%3E", true},
		{"bare xml document", html, formCT, "<stockCheck><productId>1</productId></stockCheck>", true},
		{"html fragment in form", html, formCT, "comment=<div>hello</div>", false},
		{"json request and response", jsonPage, "application/json", `{"a":1}`, false},
		{"nothing xml", html, "", "id=1&name=two", false},
		{"binary with no xml", binary, "", "", false},
		{"json body with xml declaration", jsonPage, "application/json", `<?xml version="1.0"?><a/>`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fingerprint.ShouldProbeXXE(c.p, c.ct, c.body); got != c.want {
				t.Errorf("ShouldProbeXXE = %v, want %v", got, c.want)
			}
		})
	}
}

func TestShouldProbeCommandInjection(t *testing.T) {
	cases := []struct {
		name string
		s    sample
		want bool
	}{
		{"php html", sample{ct: "text/html", header: map[string]string{"X-Powered-By": "PHP/8.1"}, body: "<html></html>"}, true},
		{"unknown html document", sample{ct: "text/html", server: "nginx", body: "<html><body>x</body></html>"}, true},
		{"json api with session", sample{ct: "application/json", cookies: []string{"session=abc"}, body: `{"a":1}`}, true},
		{"binary", sample{ct: "application/zip", body: "PK"}, false},
		{"attachment", sample{ct: "text/html", header: map[string]string{"Content-Disposition": "attachment"}, body: "<html></html>"}, false},
		{"empty response", sample{body: ""}, false},
		{"not modified", sample{status: http.StatusNotModified, ct: "text/html", body: ""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fingerprint.ShouldProbeCommandInjection(c.s.profile(t)); got != c.want {
				t.Errorf("ShouldProbeCommandInjection = %v, want %v", got, c.want)
			}
		})
	}
}

func TestGatesNeverPanicOnZeroProfile(t *testing.T) {
	var p fingerprint.Profile
	_ = fingerprint.ShouldProbeXSS(p)
	_, _ = fingerprint.ShouldProbeSSTI(p)
	_ = fingerprint.ShouldProbeXXE(p, "", "")
	_ = fingerprint.ShouldProbeCommandInjection(p)
}

// ---------------------------------------------------------------------------
// WAF
// ---------------------------------------------------------------------------

func TestWAFDetection(t *testing.T) {
	cases := []struct {
		name   string
		s      sample
		vendor string
		conf   fingerprint.Confidence
	}{
		{"cloudflare ray", sample{header: map[string]string{"CF-Ray": "8a1b2c3d4e5f-LHR"}}, fingerprint.WAFCloudflare, fingerprint.ConfidenceHigh},
		{"cloudflare server", sample{server: "cloudflare"}, fingerprint.WAFCloudflare, fingerprint.ConfidenceHigh},
		{"akamai", sample{header: map[string]string{"X-Akamai-Transformed": "9 - 0 pmb=mRUM,2"}}, fingerprint.WAFAkamai, fingerprint.ConfidenceHigh},
		{"imperva", sample{header: map[string]string{"X-Iinfo": "9-12345-12346 PNSNRT"}}, fingerprint.WAFImperva, fingerprint.ConfidenceHigh},
		{"imperva cookie", sample{cookies: []string{"visid_incap_123=abc; path=/"}}, fingerprint.WAFImperva, fingerprint.ConfidenceHigh},
		{"aws waf", sample{header: map[string]string{"X-Amzn-Waf-Action": "block"}}, fingerprint.WAFAWS, fingerprint.ConfidenceHigh},
		{"f5", sample{header: map[string]string{"X-WA-Info": "-2000000000"}}, fingerprint.WAFF5, fingerprint.ConfidenceHigh},
		{"sucuri", sample{header: map[string]string{"X-Sucuri-ID": "12345"}}, fingerprint.WAFSucuri, fingerprint.ConfidenceHigh},
		{"modsecurity body", sample{ct: "text/html", body: "<h1>Not Acceptable!</h1><p>This error was generated by Mod_Security.</p>"}, fingerprint.WAFModSecurity, fingerprint.ConfidenceHigh},
		{"wordfence body", sample{ct: "text/html", body: "<p>Your access to this site has been limited by Wordfence.</p>"}, fingerprint.WAFWordfence, fingerprint.ConfidenceMedium},
		{"none", sample{server: "nginx/1.24.0", ct: "text/html", body: "<html></html>"}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.s.profile(t)
			if p.WAFVendor != c.vendor {
				t.Errorf("WAFVendor = %q, want %q (signals: %+v)", p.WAFVendor, c.vendor, p.Signals)
			}
			if p.WAFConfidence != c.conf {
				t.Errorf("WAFConfidence = %q, want %q", p.WAFConfidence, c.conf)
			}
		})
	}
}

func TestWAFPrefersHighestConfidenceThenCatalogOrder(t *testing.T) {
	// Two high-confidence vendors: the earlier catalog entry wins, stably.
	p := sample{header: map[string]string{
		"X-Iinfo":              "9-1-2",
		"X-Akamai-Transformed": "9 - 0",
	}}.profile(t)
	if p.WAFVendor != fingerprint.WAFAkamai {
		t.Errorf("WAFVendor = %q, want akamai (catalog order before imperva)", p.WAFVendor)
	}

	// A medium-confidence marker must not override an already-seen high one,
	// regardless of rule order.
	p = sample{
		header:  map[string]string{"CF-Ray": "abc-LHR"},
		cookies: []string{"ak_bmsc=xyz"},
	}.profile(t)
	if p.WAFVendor != fingerprint.WAFCloudflare {
		t.Errorf("WAFVendor = %q, want cloudflare", p.WAFVendor)
	}
}

func TestEdgeCookiesDoNotImplyAnApplication(t *testing.T) {
	p := sample{cookies: []string{
		"__cfduid=d1234567890",
		"cf_clearance=abc",
	}}.profile(t)
	if p.WAFVendor != fingerprint.WAFCloudflare {
		t.Errorf("WAFVendor = %q, want cloudflare", p.WAFVendor)
	}
	if p.Dynamic {
		t.Error("Dynamic = true; an edge cookie is not application evidence")
	}
}

// ---------------------------------------------------------------------------
// Evidence hygiene
// ---------------------------------------------------------------------------

func TestCookieValuesNeverReachTheProfile(t *testing.T) {
	const secret = "S3SS1ON-T0KEN-do-not-leak"
	p := sample{
		ct:   "text/html",
		body: "<html></html>",
		cookies: []string{
			"PHPSESSID=" + secret + "; path=/; HttpOnly",
			"laravel_session=" + secret + "; path=/",
		},
	}.profile(t)

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("cookie value leaked into the profile JSON: %s", raw)
	}
	for _, s := range p.Signals {
		if s.Source == fingerprint.SourceCookie && s.Value != "" {
			t.Errorf("cookie signal carries a value: %+v", s)
		}
	}
	if !strings.Contains(string(raw), "PHPSESSID") {
		t.Error("cookie NAME missing from the evidence trail")
	}
}

func TestHeaderValuesAreTruncated(t *testing.T) {
	long := strings.Repeat("A", 1000)
	p := sample{server: long}.profile(t)
	if len(p.Server) != 200 {
		t.Errorf("len(Server) = %d, want 200", len(p.Server))
	}
	for _, s := range p.Signals {
		if len(s.Value) > 200 {
			t.Errorf("signal value not truncated: %d bytes", len(s.Value))
		}
	}
}

func TestBodyScanIsBounded(t *testing.T) {
	padding := strings.Repeat("a", 128<<10)
	early := sample{ct: "text/html", body: "<p>jinja2</p>" + padding}.profile(t)
	if !containsSignal(early, fingerprint.ClassTemplate, fingerprint.SourceBody, fingerprint.TplJinja2) {
		t.Error("engine marker near the start of the body was not detected")
	}

	late := sample{ct: "text/html", body: padding + "<p>jinja2</p>"}.profile(t)
	if containsSignal(late, fingerprint.ClassTemplate, fingerprint.SourceBody, fingerprint.TplJinja2) {
		t.Error("engine marker beyond the scan limit was detected; the scan must stay bounded")
	}
}

// ---------------------------------------------------------------------------
// Determinism, purity, serialization
// ---------------------------------------------------------------------------

func TestAnalyzeIsDeterministic(t *testing.T) {
	s := sample{
		server:  "Apache-Coyote/1.1",
		ct:      "text/html",
		header:  map[string]string{"X-Application-Context": "app", "X-Powered-By": "PHP/8.1"},
		cookies: []string{"JSESSIONID=a", "PHPSESSID=b", "csrftoken=c"},
		body:    `<html><body>wp-content/ __NEXT_DATA__ jinja2 ${7*7}</body></html>`,
	}
	first, err := json.Marshal(s.profile(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := json.Marshal(s.profile(t))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(first) {
			t.Fatalf("run %d serialized differently:\n%s\n%s", i, got, first)
		}
	}
}

func TestHeaderInsertionOrderDoesNotMatter(t *testing.T) {
	build := func(order []string) []byte {
		h := http.Header{}
		values := map[string]string{
			"Server":                "Apache",
			"X-Powered-By":          "PHP/8.1",
			"X-AspNet-Version":      "4.0.30319",
			"CF-Ray":                "abc-LHR",
			"X-Application-Context": "app",
		}
		for _, k := range order {
			h.Set(k, values[k])
		}
		h.Add("Set-Cookie", "PHPSESSID=x")
		h.Add("Set-Cookie", "csrftoken=y")
		p := fingerprint.Analyze(fingerprint.Observation{
			URL:    "https://example.test/a.php",
			Status: 200,
			Header: h,
			Body:   []byte("<html></html>"),
		})
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	a := build([]string{"Server", "X-Powered-By", "X-AspNet-Version", "CF-Ray", "X-Application-Context"})
	b := build([]string{"X-Application-Context", "CF-Ray", "X-AspNet-Version", "X-Powered-By", "Server"})
	if string(a) != string(b) {
		t.Fatalf("output depends on header insertion order:\n%s\n%s", a, b)
	}
}

func TestProfileJSONRoundTrip(t *testing.T) {
	p := sample{
		url:    "https://example.test/app.aspx",
		server: "Microsoft-IIS/10.0",
		ct:     "text/html",
		header: map[string]string{"X-AspNet-Version": "4.0.30319"},
		body:   "<html></html>",
	}.profile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back fingerprint.Profile
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, back) {
		t.Errorf("round trip changed the profile:\n%+v\n%+v", p, back)
	}
}

func TestAnalyzeResponseUsesRequestURL(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/account.php?id=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("X-Powered-By", "PHP/8.1")
	h.Set("Content-Type", "text/html")
	p := fingerprint.AnalyzeResponse(&http.Response{StatusCode: 200, Header: h, Request: req}, []byte("<html></html>"))
	if p.URL != "https://example.test/account.php?id=1" {
		t.Errorf("URL = %q", p.URL)
	}
	if p.ContentKind != fingerprint.KindHTML || !p.HasLanguage(fingerprint.LangPHP) {
		t.Errorf("profile = %+v", p)
	}

	if got := fingerprint.AnalyzeResponse(nil, nil); got.ContentKind != fingerprint.KindUnknown {
		t.Errorf("nil response ContentKind = %q, want unknown", got.ContentKind)
	}
}

// TestFingerprintIsPure fails if the package ever grows the ability to make a
// request. Fingerprinting must stay passive: it reads an observation that some
// other layer already fetched (AGENTS.md §2).
func TestFingerprintIsPure(t *testing.T) {
	allowed := map[string]bool{
		"bytes": true, "encoding/json": true, "mime": true,
		"net/http": true, // the Header/Response TYPES only; no client is used
		"net/url":  true, "path": true, "strings": true,
	}
	f, err := parser.ParseFile(token.NewFileSet(), "tech.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse tech.go: %v", err)
	}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if !allowed[p] {
			t.Errorf("unexpected import %q: fingerprinting must stay pure and offline", p)
		}
	}

	src, err := os.ReadFile("tech.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"http.Get(", "http.Post(", "http.Head(", "http.Do(",
		"http.NewRequest(", "http.Client{", "http.DefaultClient",
		"http.DefaultTransport", "net.Dial", "exec.Command",
		"math/rand", "time.Now",
	} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("tech.go contains %q: fingerprinting must not perform work outside its input", forbidden)
		}
	}
}

// TestTemplateHintsAreNeverEmpty keeps the "none" contract: every profile names
// either at least one engine or exactly the placeholder.
func TestTemplateHintsAreNeverEmpty(t *testing.T) {
	samples := []sample{
		{},
		{ct: "text/html", body: "<html></html>"},
		{ct: "application/pdf"},
		{ct: "text/html", server: "gunicorn"},
		{ct: "text/html", body: "<html>__NEXT_DATA__</html>"},
	}
	for i, s := range samples {
		p := s.profile(t)
		if len(p.TemplateHints) == 0 {
			t.Fatalf("sample %d: TemplateHints is empty", i)
		}
		if len(p.TemplateHints) == 1 && p.TemplateHints[0] == fingerprint.TplNone {
			continue
		}
		for _, h := range p.TemplateHints {
			if h == fingerprint.TplNone {
				t.Errorf("sample %d: placeholder mixed with real engines: %v", i, p.TemplateHints)
			}
		}
	}
}

func TestURLShapes(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want fingerprint.Language // "" = no language expected
	}{
		{"absolute", "https://example.test/a/index.php", fingerprint.LangPHP},
		{"relative", "/app/account.aspx", fingerprint.LangDotNet},
		{"scheme-relative", "//example.test/x.jsp", fingerprint.LangJava},
		{"bare host and path", "example.test/job.py", fingerprint.LangPython},
		{"query only", "https://example.test/?next=/a.php", ""},
		{"origin only", "https://example.test", ""},
		{"fragment", "https://example.test#/a.php", ""},
		{"unparseable", "http://[::1", ""},
		{"garbage", "://", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := fingerprint.Analyze(fingerprint.Observation{
				URL:    c.url,
				Status: 200,
				Header: http.Header{"Content-Type": {"text/html"}},
				Body:   []byte("<html></html>"),
			})
			if c.want == "" {
				if len(p.Languages) != 0 {
					t.Errorf("Languages = %v, want none (the path must not be read from the query/fragment)", p.Languages)
				}
				return
			}
			if !p.HasLanguage(c.want) {
				t.Errorf("Languages = %v, want %s", p.Languages, c.want)
			}
		})
	}
}

func TestSniffingEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		body string
		kind fingerprint.ContentKind
	}{
		{"rss", "", `<?xml version="1.0"?><rss version="2.0"></rss>`, fingerprint.KindXML},
		{"bare rss root", "", "<rss version=\"2.0\"><channel></channel></rss>", fingerprint.KindXML},
		{"atom", "", `<feed xmlns="http://www.w3.org/2005/Atom"></feed>`, fingerprint.KindXML},
		{"graphql", "application/graphql", "query { __typename }", fingerprint.KindText},
		{"wasm", "application/wasm", "\x00asm\x01\x00\x00\x00", fingerprint.KindBinary},
		{"font", "font/woff2", "wOF2", fingerprint.KindBinary},
		{"video", "video/mp4", "\x00\x00\x00\x18ftyp", fingerprint.KindBinary},
		{"control-heavy", "", "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17", fingerprint.KindBinary},
		{"bom json", "", "\ufeff{\"a\":1}", fingerprint.KindJSON},
		{"json array", "", "[1,2,3]", fingerprint.KindJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := sample{ct: c.ct, body: c.body}.profile(t)
			if p.ContentKind != c.kind {
				t.Errorf("ContentKind = %q, want %q", p.ContentKind, c.kind)
			}
		})
	}
}

func TestBareXMLHeuristics(t *testing.T) {
	html := sample{ct: "text/html", body: "<html></html>"}.profile(t)
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"soap envelope", "<soap:Envelope><soap:Body/></soap:Envelope>", true},
		{"unknown root", "<stockCheck><productId>1</productId></stockCheck>", true},
		{"self-closing root", "<stockCheck/>", true},
		{"self-closing html root", "<div/>", false},
		{"html fragment", "<div>x</div>", false},
		{"doctype", "<!DOCTYPE html><html></html>", false},
		{"processing instruction", "<?php echo 1; ?>", false},
		{"unclosed root", "<stockCheck><productId>1</productId>", false},
		{"plain text", "hello", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fingerprint.ShouldProbeXXE(html, "application/x-www-form-urlencoded", c.body); got != c.want {
				t.Errorf("ShouldProbeXXE = %v, want %v", got, c.want)
			}
		})
	}
}

func TestMultipleDetectedLanguagesKeepServerLanguage(t *testing.T) {
	// A Next.js page served by a PHP backend: the SPA suppression must not
	// apply, because a server-side language is present too.
	p := sample{
		ct:     "text/html",
		header: map[string]string{"X-Powered-By": "PHP/8.1"},
		body:   `<html><script id="__NEXT_DATA__">{}</script></html>`,
	}.profile(t)
	if !p.HasLanguage(fingerprint.LangPHP) || !p.HasFramework(fingerprint.FwNextJS) {
		t.Fatalf("languages/frameworks = %v/%v", p.Languages, p.Frameworks)
	}
	if ok, _ := fingerprint.ShouldProbeSSTI(p); !ok {
		t.Error("ShouldProbeSSTI = false; a PHP backend keeps the endpoint template-capable")
	}
}

func TestAnalyzeNeverPanicsOnHostileInput(t *testing.T) {
	hostile := []fingerprint.Observation{
		{},
		{URL: "http://[::1", Status: -1},
		{URL: "://", Status: 999, Header: http.Header{"Content-Type": {""}}},
		{URL: "https://example.test/\x00", Header: http.Header{"Server": {""}, "Set-Cookie": {"=;", "novalue", "a=b=c", ";;;"}}},
		{Header: http.Header{"Content-Type": {"text/html; charset=\xff"}}, Body: []byte("\xff\xfe\xfd")},
		{Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"a":`)},
		{Body: []byte(strings.Repeat("<", 5000))},
		{Body: []byte(strings.Repeat("a", 1<<20))},
		{Body: []byte("\x00\x01\x02")},
	}
	for i, o := range hostile {
		p := fingerprint.Analyze(o)
		fingerprint.ShouldProbeXSS(p)
		fingerprint.ShouldProbeSSTI(p)
		fingerprint.ShouldProbeXXE(p, "application/xml", "\x00")
		fingerprint.ShouldProbeCommandInjection(p)
		if _, err := json.Marshal(p); err != nil {
			t.Errorf("observation %d: profile does not serialize: %v", i, err)
		}
	}
}

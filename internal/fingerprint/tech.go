// Package fingerprint is Indago's passive technology-stack fingerprinter and
// adaptive payload gate.
//
// # What it does
//
// Analyze turns one already-captured HTTP observation — URL, status, response
// headers and response body bytes — into a Profile: the server-side languages
// and frameworks the response betrays, the coarse ContentKind of the body
// (html/json/xml/text/binary/unknown), the server-side TemplateHints that are
// plausible for that stack, and the WAFVendor that answered, if any. Every
// conclusion is also recorded as a Signal naming the exact evidence (header,
// cookie NAME, URL fragment, body needle) that produced it, so a report can
// show why the scanner believed something instead of asking a reader to trust
// a label.
//
// # What it never does
//
//   - No network. There is no client in this package: no socket, no browser, no
//     extra request. An endpoint's fingerprint is read out of a response that
//     was already fetched (AGENTS.md §2: this layer must never widen what may
//     be targeted).
//   - No payload and no verdict. The gates answer only "is this class of probe
//     worth spending a request on here?"; they never say a target is vulnerable
//     and never generate a probe. Verification stays where it belongs
//     (internal/verification), and no LLM is involved (AGENTS.md §2.5).
//   - No secrets. Cookie VALUES are never copied into a Profile or a Signal —
//     only cookie names — and header values are truncated. Session material
//     must not leak into a report through a fingerprint.
//   - No lab-specific knowledge. The catalogs hold general vendor/product
//     markers (PHPSESSID, JSESSIONID, wp-content, cf-ray, ...); nothing here
//     knows about a particular engagement or test target.
//
// # Purity and determinism
//
// Analyze is a pure function of its input: no clock, no randomness, no
// goroutines, and no map iteration in any output path. Rule tables are ordered
// slices and catalogs are emitted in a fixed order, so the same observation
// always serializes to the same JSON. TestFingerprintIsPure enforces the import
// set so a future edit cannot quietly add a network client.
//
// # Bounds
//
// Body hints are scanned only in the first bodyScanLimit bytes, the request
// body for ShouldProbeXXE only in its first xxeBodyScan bytes, and at most
// maxSignals signals are retained, so a hostile or gigantic response cannot
// turn fingerprinting into a memory/CPU problem on the scanner's hot path.
//
// # Gating
//
//	ShouldProbeXSS              any response a browser could render as markup or
//	                            script; never a binary body or a file download.
//	ShouldProbeSSTI             only where a server-side template engine is
//	                            plausible for the detected stack (ordered
//	                            language/framework first); never JSON without
//	                            explicit engine evidence, never a client-rendered
//	                            SPA shell.
//	ShouldProbeXXE              only when the REQUEST accepts or contains XML, or
//	                            the response itself is XML.
//	ShouldProbeCommandInjection only where application code — not a static file
//	                            or download — is handling the request.
//
// See docs/tech-fingerprint.md for the full rationale and the known limits.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	// bodyScanLimit bounds how much of the RESPONSE body is inspected. Template
	// and framework markers always live in the head/early body of a document;
	// scanning a whole multi-megabyte download would be pure overhead.
	bodyScanLimit = 128 << 10

	// xxeBodyScan bounds how much of a REQUEST body ShouldProbeXXE inspects.
	// XXE bodies are tiny SOAP/XML documents, not uploads.
	xxeBodyScan = 8 << 10

	// valueLimit bounds every header value copied into a Profile, so an
	// attacker-controlled header cannot balloon a stored record.
	valueLimit = 200

	// maxSignals bounds the evidence retained per Profile. A real response
	// produces a handful; the ceiling only exists so a pathological body full
	// of markers cannot grow the struct without limit.
	maxSignals = 96
)

// ContentKind is the coarse family of a response body. It is deliberately
// coarse: the gates only need to know whether a browser would render the bytes
// as markup/script, whether an XML parser is in play, or whether this is an
// opaque download.
type ContentKind string

const (
	KindHTML    ContentKind = "html"
	KindJSON    ContentKind = "json"
	KindXML     ContentKind = "xml"
	KindText    ContentKind = "text"
	KindBinary  ContentKind = "binary"
	KindUnknown ContentKind = "unknown" // no usable evidence (empty body, no type)
)

// Language is a server-side language identified from response evidence.
type Language string

const (
	LangPHP    Language = "php"
	LangPython Language = "python"
	LangRuby   Language = "ruby"
	LangJava   Language = "java"
	LangNode   Language = "node"
	LangDotNet Language = "dotnet"
	LangPerl   Language = "perl"
)

// Framework is a server-side web framework identified from response evidence.
// Client-side libraries are deliberately out of scope: this package gates
// server-side injection classes, and DOM/client analysis has its own paths.
type Framework string

const (
	FwLaravel     Framework = "laravel"
	FwSymfony     Framework = "symfony"
	FwCodeIgniter Framework = "codeigniter"
	FwWordPress   Framework = "wordpress"
	FwDjango      Framework = "django"
	FwFlask       Framework = "flask"
	FwRails       Framework = "rails"
	FwSpring      Framework = "spring"
	FwExpress     Framework = "express"
	FwNextJS      Framework = "nextjs"
	FwNuxt        Framework = "nuxt"
	FwAspNet      Framework = "aspnet"
)

// Template engine names. TemplateNone is reported when the stack exposes no
// plausible server-side template engine.
const (
	TplJinja2     = "jinja2"
	TplDjango     = "django"
	TplMako       = "mako"
	TplTwig       = "twig"
	TplSmarty     = "smarty"
	TplBlade      = "blade"
	TplFreemarker = "freemarker"
	TplVelocity   = "velocity"
	TplSpEL       = "spel"
	TplThymeleaf  = "thymeleaf"
	TplERB        = "erb"
	TplHaml       = "haml"
	TplEJS        = "ejs"
	TplHandlebars = "handlebars"
	TplPug        = "pug"
	TplNunjucks   = "nunjucks"
	TplMustache   = "mustache"
	TplRazor      = "razor"
	TplNone       = "none"
)

// WAF vendors. A vendor is reported when the response carries a marker that is
// specific to that WAF/edge product; "the edge answered" is not the same claim
// as "a rule blocked us" (see docs/tech-fingerprint.md).
const (
	WAFCloudflare  = "cloudflare"
	WAFAkamai      = "akamai"
	WAFImperva     = "imperva"
	WAFAWS         = "aws"
	WAFF5          = "f5"
	WAFAzure       = "azure"
	WAFSucuri      = "sucuri"
	WAFModSecurity = "modsecurity"
	WAFWordfence   = "wordfence"
	WAFFortiWeb    = "fortiweb"
	WAFBarracuda   = "barracuda"
)

// Confidence grades a single fingerprint signal.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Signal classes: what kind of conclusion a piece of evidence supports.
const (
	ClassLanguage  = "language"
	ClassFramework = "framework"
	ClassTemplate  = "template"
	ClassWAF       = "waf"
)

// Signal sources: where the evidence was read from.
const (
	SourceURL    = "url"
	SourceHeader = "header"
	SourceCookie = "cookie"
	SourceBody   = "body"
)

// Signal is one piece of evidence and the conclusion drawn from it. Value is
// only ever a truncated header value or a body NEEDLE — never a cookie value.
type Signal struct {
	Class      string     `json:"class"`
	Source     string     `json:"source"`
	Name       string     `json:"name,omitempty"`
	Match      string     `json:"match,omitempty"`
	Value      string     `json:"value,omitempty"`
	Tech       string     `json:"tech"`
	Confidence Confidence `json:"confidence"`
}

// Profile is the fingerprint of one observed HTTP response. It is data only:
// no method here sends anything.
type Profile struct {
	URL    string `json:"url,omitempty"`
	Status int    `json:"status,omitempty"`

	// ContentType is the normalized media type (parameters stripped), e.g.
	// "text/html". ContentKind is the coarse family derived from it (or from
	// the body when the header is missing/unusable).
	ContentType string      `json:"content_type,omitempty"`
	ContentKind ContentKind `json:"content_kind"`
	BodyBytes   int         `json:"body_bytes"`

	// Server and PoweredBy echo the two headers that most often carry a stack
	// version. They are truncated and are never interpreted as a secret.
	Server    string `json:"server,omitempty"`
	PoweredBy string `json:"powered_by,omitempty"`

	// StaticAsset reports that the response is a file download or a static
	// asset (image, font, archive, CSS/JS bundle, Content-Disposition:
	// attachment) rather than an application-generated document.
	StaticAsset bool `json:"static_asset,omitempty"`

	// Languages and Frameworks are deduplicated and emitted in a fixed
	// canonical order. A framework also implies its language.
	Languages  []Language  `json:"languages,omitempty"`
	Frameworks []Framework `json:"frameworks,omitempty"`

	// TemplateHints lists the server-side template engines plausible for this
	// stack, most likely first. It is never empty: when no engine is plausible
	// it holds exactly [TplNone]. The list names engines, not payload syntax —
	// choosing a payload shape stays with the caller.
	TemplateHints []string `json:"template_hints"`

	// WAFVendor is the highest-confidence WAF/edge vendor observed, or "".
	WAFVendor     string     `json:"waf_vendor,omitempty"`
	WAFConfidence Confidence `json:"waf_confidence,omitempty"`

	// Dynamic reports that the response looks application-generated rather than
	// a static file: a language/framework was identified, or the server issued
	// a cookie that is not a known WAF/edge cookie.
	Dynamic bool `json:"dynamic"`

	// Signals is the evidence trail, in deterministic rule order.
	Signals []Signal `json:"signals,omitempty"`
}

// HasLanguage reports whether lang was identified (directly or via a
// framework).
func (p Profile) HasLanguage(lang Language) bool {
	for _, l := range p.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// HasFramework reports whether fw was identified.
func (p Profile) HasFramework(fw Framework) bool {
	for _, f := range p.Frameworks {
		if f == fw {
			return true
		}
	}
	return false
}

// Observation is one HTTP response that was already fetched by the caller.
// Body must be the response body bytes (not a stream to consume): Analyze never
// reads from it as a reader, it only inspects the bytes.
type Observation struct {
	URL    string
	Status int
	Header http.Header
	Body   []byte
}

// AnalyzeResponse is a convenience for callers holding a *http.Response whose
// body was already read into body. It does not read or close the response body.
func AnalyzeResponse(resp *http.Response, body []byte) Profile {
	if resp == nil {
		return Analyze(Observation{Body: body})
	}
	o := Observation{Status: resp.StatusCode, Header: resp.Header, Body: body}
	if resp.Request != nil && resp.Request.URL != nil {
		o.URL = resp.Request.URL.String()
	}
	return Analyze(o)
}

// Analyze derives a Profile from one observation. It never panics on hostile
// input: a zero Observation yields a Profile whose ContentKind is "unknown".
func Analyze(o Observation) Profile {
	a := &analyzer{
		obs:       o,
		langs:     make(map[Language]Confidence, 4),
		fws:       make(map[Framework]Confidence, 4),
		tpls:      make(map[string]Confidence, 4),
		seen:      make(map[string]bool, 32),
		cookies:   cookieNames(o.Header),
		lowerPath: strings.ToLower(urlPath(o.URL)),
	}
	if len(o.Body) > bodyScanLimit {
		a.lowerBody = bytes.ToLower(o.Body[:bodyScanLimit])
	} else {
		a.lowerBody = bytes.ToLower(o.Body)
	}
	a.ext = strings.ToLower(path.Ext(a.lowerPath))

	p := Profile{
		URL:       o.URL,
		Status:    o.Status,
		Server:    headerValue(o.Header, "Server"),
		PoweredBy: headerValue(o.Header, "X-Powered-By"),
		BodyBytes: len(o.Body),
	}
	p.ContentKind, p.ContentType = classifyContent(o.Header.Get("Content-Type"), o.Body)
	p.StaticAsset = isStaticAsset(p.ContentKind, a.ext, o.Header)

	a.run(ClassLanguage, languageRules)
	a.run(ClassFramework, frameworkRules)
	a.run(ClassTemplate, templateRules)
	a.run(ClassWAF, wafRules)
	a.appCookieSeen = a.countAppCookie()

	// A framework implies its language (WordPress is PHP, Rails is Ruby, ...)
	// even when no language-specific marker was present.
	for _, fw := range frameworkOrder {
		conf, ok := a.fws[fw]
		if !ok {
			continue
		}
		if lang := frameworkLanguage[fw]; lang != "" {
			if _, exists := a.langs[lang]; !exists {
				a.langs[lang] = conf
			}
		}
	}

	for _, lang := range languageOrder {
		if _, ok := a.langs[lang]; ok {
			p.Languages = append(p.Languages, lang)
		}
	}
	for _, fw := range frameworkOrder {
		if _, ok := a.fws[fw]; ok {
			p.Frameworks = append(p.Frameworks, fw)
		}
	}
	p.TemplateHints = a.templateHints()
	p.WAFVendor = a.wafVendor
	p.WAFConfidence = a.wafConf
	p.Dynamic = len(p.Languages) > 0 || len(p.Frameworks) > 0 || a.appCookieSeen
	p.Signals = a.signals
	return p
}

// analyzer accumulates the result so the rule engine stays a handful of loops.
type analyzer struct {
	obs       Observation
	lowerBody []byte
	lowerPath string
	ext       string
	cookies   []string

	langs map[Language]Confidence
	fws   map[Framework]Confidence
	tpls  map[string]Confidence
	// tplOrder preserves first-seen order of explicit template evidence so the
	// output never depends on map iteration.
	tplOrder []string

	wafVendor string
	wafConf   Confidence
	wafRank   int

	appCookieSeen bool

	signals []Signal
	seen    map[string]bool
}

// run applies one rule table. Tables are ordered slices, so iteration — and
// therefore the signal order — is deterministic.
func (a *analyzer) run(class string, rules []rule) {
	for _, r := range rules {
		if r.needle == "" && r.where != whereHeader && r.where != whereCookie {
			continue // a marker rule without a marker would match everything
		}
		value, ok := a.match(r)
		if !ok {
			continue
		}
		a.record(class, r, value)
	}
}

// match reports whether r fires for this observation and returns the value to
// record alongside the signal ("" when the evidence is a name/URL, never a
// cookie value).
func (a *analyzer) match(r rule) (string, bool) {
	switch r.where {
	case whereHeader:
		for _, v := range a.obs.Header.Values(r.name) {
			if r.needle == "" || strings.Contains(strings.ToLower(v), r.needle) {
				return truncate(v), true
			}
		}
	case whereCookie:
		for _, name := range a.cookies {
			if matchCookie(name, r.name) {
				return name, true // the cookie NAME is the evidence; never its value
			}
		}
	case whereBody:
		if bytes.Contains(a.lowerBody, []byte(r.needle)) {
			return r.needle, true
		}
	case whereURL:
		if strings.Contains(a.lowerPath, r.needle) {
			return r.needle, true
		}
	case whereExt:
		if a.ext == r.needle {
			return r.needle, true
		}
	}
	return "", false
}

func (a *analyzer) record(class string, r rule, value string) {
	tech := r.techName()
	switch class {
	case ClassLanguage:
		if _, ok := a.langs[r.lang]; !ok {
			a.langs[r.lang] = r.conf
		}
	case ClassFramework:
		if _, ok := a.fws[r.fw]; !ok {
			a.fws[r.fw] = r.conf
		}
	case ClassTemplate:
		if _, ok := a.tpls[tech]; !ok {
			a.tpls[tech] = r.conf
			a.tplOrder = append(a.tplOrder, tech)
		}
	case ClassWAF:
		a.considerWAF(tech, r.conf)
	}
	a.addSignal(class, r, value)
}

// considerWAF keeps the highest-confidence vendor; ties keep the earlier entry
// in the catalog, which makes the result stable.
func (a *analyzer) considerWAF(vendor string, conf Confidence) {
	rank := confidenceRank(conf)
	if a.wafVendor != "" && rank <= a.wafRank {
		return
	}
	a.wafVendor, a.wafConf, a.wafRank = vendor, conf, rank
}

func (a *analyzer) addSignal(class string, r rule, evidence string) {
	if len(a.signals) >= maxSignals {
		return
	}
	s := Signal{
		Class:      class,
		Source:     r.source(),
		Name:       r.sourceName(),
		Match:      r.needle,
		Tech:       r.techName(),
		Confidence: r.conf,
	}
	switch r.where {
	case whereHeader:
		s.Value = evidence
	case whereCookie:
		// The matched name is the evidence; a cookie value is never copied.
		s.Name = evidence
		s.Value = ""
	default:
		s.Match = evidence
	}
	key := s.Class + "|" + s.Source + "|" + s.Name + "|" + s.Match + "|" + s.Tech
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	a.signals = append(a.signals, s)
}

// templateHints builds the ordered engine list: explicit engine evidence first
// (an error page naming the engine beats a guess), then engines pinned by a
// detected framework, then the defaults for each detected language. The result
// is never empty.
func (a *analyzer) templateHints() []string {
	seen := make(map[string]bool, 6)
	out := make([]string, 0, 6)
	add := func(e string) {
		if e == "" || e == TplNone || seen[e] {
			return
		}
		seen[e] = true
		out = append(out, e)
	}
	for _, e := range a.tplOrder {
		add(e)
	}
	for _, fw := range frameworkOrder {
		if _, ok := a.fws[fw]; !ok {
			continue
		}
		for _, e := range frameworkEngines[fw] {
			add(e)
		}
	}
	for _, lang := range languageOrder {
		if _, ok := a.langs[lang]; !ok {
			continue
		}
		for _, e := range languageEngines[lang] {
			add(e)
		}
	}
	if len(out) == 0 {
		return []string{TplNone}
	}
	return out
}

// rule is one catalog entry: a marker, where to look for it, and what it means.
type rule struct {
	where  matchWhere
	name   string // header/cookie name (cookie names may use one '*')
	needle string // lower-case substring, or an exact extension
	conf   Confidence
	lang   Language
	fw     Framework
	tech   string
}

type matchWhere int

const (
	whereHeader matchWhere = iota
	whereCookie
	whereBody
	whereURL
	whereExt
)

func (r rule) techName() string {
	switch {
	case r.lang != "":
		return string(r.lang)
	case r.fw != "":
		return string(r.fw)
	default:
		return r.tech
	}
}

func (r rule) source() string {
	switch r.where {
	case whereHeader:
		return SourceHeader
	case whereCookie:
		return SourceCookie
	case whereBody:
		return SourceBody
	default:
		return SourceURL
	}
}

func (r rule) sourceName() string {
	switch r.where {
	case whereHeader:
		return r.name
	case whereCookie:
		return "" // replaced by the matched cookie name in addSignal
	case whereBody:
		return "body"
	default:
		return "url"
	}
}

// ---------------------------------------------------------------------------
// Catalogs
//
// Every entry is a general product/vendor marker, never engagement-specific
// data. Confidence reflects how specific the marker is, not how much the author
// likes the product: a PHP-SESSID cookie is high, "Server: Puma" is medium
// (it identifies the app server, not the language), a bare product word in a
// body is medium.
// ---------------------------------------------------------------------------

var languageOrder = []Language{LangPHP, LangPython, LangRuby, LangJava, LangNode, LangDotNet, LangPerl}

var languageRules = []rule{
	// PHP
	{where: whereHeader, name: "X-Powered-By", needle: "php", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereHeader, name: "Server", needle: "php/", conf: ConfidenceMedium, lang: LangPHP},
	{where: whereCookie, name: "phpsessid", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereExt, needle: ".php", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereExt, needle: ".phtml", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereExt, needle: ".php5", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereExt, needle: ".php7", conf: ConfidenceHigh, lang: LangPHP},
	{where: whereExt, needle: ".php8", conf: ConfidenceHigh, lang: LangPHP},

	// Python
	{where: whereHeader, name: "Server", needle: "werkzeug", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "gunicorn", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "uvicorn", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "wsgiref", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "hypercorn", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "daphne", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "Server", needle: "uwsgi", conf: ConfidenceHigh, lang: LangPython},
	{where: whereHeader, name: "X-Powered-By", needle: "python", conf: ConfidenceMedium, lang: LangPython},
	{where: whereExt, needle: ".py", conf: ConfidenceHigh, lang: LangPython},

	// Ruby
	{where: whereHeader, name: "Server", needle: "webrick", conf: ConfidenceHigh, lang: LangRuby},
	{where: whereHeader, name: "Server", needle: "puma", conf: ConfidenceMedium, lang: LangRuby},
	{where: whereExt, needle: ".rb", conf: ConfidenceHigh, lang: LangRuby},

	// Java
	{where: whereHeader, name: "Server", needle: "apache-coyote", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "tomcat", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "jetty", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "undertow", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "glassfish", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "wildfly", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "jboss", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "Server", needle: "websphere", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "X-Powered-By", needle: "servlet", conf: ConfidenceHigh, lang: LangJava},
	{where: whereHeader, name: "X-Powered-By", needle: "jsp", conf: ConfidenceHigh, lang: LangJava},
	{where: whereCookie, name: "jsessionid", conf: ConfidenceHigh, lang: LangJava},
	{where: whereExt, needle: ".jsp", conf: ConfidenceHigh, lang: LangJava},
	{where: whereExt, needle: ".jspx", conf: ConfidenceHigh, lang: LangJava},
	{where: whereExt, needle: ".do", conf: ConfidenceMedium, lang: LangJava},
	{where: whereExt, needle: ".action", conf: ConfidenceMedium, lang: LangJava},
	{where: whereExt, needle: ".jsf", conf: ConfidenceHigh, lang: LangJava},

	// Node
	{where: whereHeader, name: "X-Powered-By", needle: "express", conf: ConfidenceHigh, lang: LangNode},
	{where: whereCookie, name: "connect.sid", conf: ConfidenceHigh, lang: LangNode},

	// .NET
	{where: whereHeader, name: "X-Powered-By", needle: "asp.net", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereHeader, name: "X-AspNet-Version", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereHeader, name: "X-AspNetMvc-Version", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereHeader, name: "Server", needle: "microsoft-iis", conf: ConfidenceMedium, lang: LangDotNet},
	{where: whereCookie, name: "asp.net_sessionid", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereCookie, name: ".aspxauth", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereExt, needle: ".aspx", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereExt, needle: ".ashx", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereExt, needle: ".asmx", conf: ConfidenceHigh, lang: LangDotNet},
	{where: whereExt, needle: ".asp", conf: ConfidenceMedium, lang: LangDotNet},
	{where: whereExt, needle: ".svc", conf: ConfidenceMedium, lang: LangDotNet},

	// Perl
	{where: whereHeader, name: "Server", needle: "mod_perl", conf: ConfidenceHigh, lang: LangPerl},
	{where: whereHeader, name: "X-Powered-By", needle: "perl", conf: ConfidenceHigh, lang: LangPerl},
	{where: whereExt, needle: ".pl", conf: ConfidenceMedium, lang: LangPerl},
	{where: whereExt, needle: ".cgi", conf: ConfidenceMedium, lang: LangPerl},
}

var frameworkOrder = []Framework{
	FwLaravel, FwSymfony, FwCodeIgniter, FwWordPress,
	FwDjango, FwFlask, FwRails,
	FwSpring, FwExpress, FwNextJS, FwNuxt, FwAspNet,
}

var frameworkLanguage = map[Framework]Language{
	FwLaravel:     LangPHP,
	FwSymfony:     LangPHP,
	FwCodeIgniter: LangPHP,
	FwWordPress:   LangPHP,
	FwDjango:      LangPython,
	FwFlask:       LangPython,
	FwRails:       LangRuby,
	FwSpring:      LangJava,
	FwExpress:     LangNode,
	FwNextJS:      LangNode,
	FwNuxt:        LangNode,
	FwAspNet:      LangDotNet,
}

var frameworkRules = []rule{
	// PHP
	{where: whereCookie, name: "laravel_session", conf: ConfidenceHigh, fw: FwLaravel},
	{where: whereHeader, name: "X-Debug-Token", conf: ConfidenceHigh, fw: FwSymfony},
	{where: whereHeader, name: "X-Debug-Token-Link", conf: ConfidenceHigh, fw: FwSymfony},
	{where: whereCookie, name: "symfony", conf: ConfidenceHigh, fw: FwSymfony},
	{where: whereBody, needle: "sf-toolbar", conf: ConfidenceHigh, fw: FwSymfony},
	{where: whereCookie, name: "ci_session", conf: ConfidenceHigh, fw: FwCodeIgniter},
	{where: whereBody, needle: "wp-content/", conf: ConfidenceHigh, fw: FwWordPress},
	{where: whereBody, needle: "wp-includes/", conf: ConfidenceHigh, fw: FwWordPress},
	{where: whereBody, needle: "/wp-json/", conf: ConfidenceHigh, fw: FwWordPress},
	{where: whereCookie, name: "wordpress_*", conf: ConfidenceHigh, fw: FwWordPress},
	{where: whereCookie, name: "wp-settings-*", conf: ConfidenceHigh, fw: FwWordPress},
	{where: whereURL, needle: "/wp-login.php", conf: ConfidenceHigh, fw: FwWordPress},

	// Python
	{where: whereBody, needle: "csrfmiddlewaretoken", conf: ConfidenceHigh, fw: FwDjango},
	{where: whereCookie, name: "csrftoken", conf: ConfidenceHigh, fw: FwDjango},
	{where: whereBody, needle: "disallowedhost", conf: ConfidenceHigh, fw: FwDjango},
	{where: whereBody, needle: "django version", conf: ConfidenceMedium, fw: FwDjango},
	{where: whereHeader, name: "Server", needle: "werkzeug", conf: ConfidenceMedium, fw: FwFlask},

	// Ruby
	{where: whereBody, needle: `name="csrf-token"`, conf: ConfidenceHigh, fw: FwRails},
	{where: whereBody, needle: "action_dispatch", conf: ConfidenceHigh, fw: FwRails},

	// Java
	{where: whereHeader, name: "X-Application-Context", conf: ConfidenceHigh, fw: FwSpring},
	{where: whereBody, needle: "whitelabel error page", conf: ConfidenceHigh, fw: FwSpring},
	{where: whereBody, needle: "org.springframework", conf: ConfidenceHigh, fw: FwSpring},

	// Node
	{where: whereHeader, name: "X-Powered-By", needle: "express", conf: ConfidenceHigh, fw: FwExpress},
	{where: whereCookie, name: "connect.sid", conf: ConfidenceHigh, fw: FwExpress},
	{where: whereBody, needle: "__next_data__", conf: ConfidenceHigh, fw: FwNextJS},
	{where: whereBody, needle: "/_next/static/", conf: ConfidenceHigh, fw: FwNextJS},
	{where: whereBody, needle: "__nuxt__", conf: ConfidenceHigh, fw: FwNuxt},
	{where: whereBody, needle: "/_nuxt/", conf: ConfidenceMedium, fw: FwNuxt},

	// .NET
	{where: whereHeader, name: "X-AspNet-Version", conf: ConfidenceHigh, fw: FwAspNet},
	{where: whereHeader, name: "X-AspNetMvc-Version", conf: ConfidenceHigh, fw: FwAspNet},
	{where: whereBody, needle: "__viewstate", conf: ConfidenceHigh, fw: FwAspNet},
	{where: whereCookie, name: "asp.net_sessionid", conf: ConfidenceHigh, fw: FwAspNet},
}

// templateRules are EXPLICIT engine evidence — mostly a framework error page or
// debug toolbar that names the engine. A bare product word in a body is kept at
// medium confidence because documentation pages mention engines too.
var templateRules = []rule{
	{where: whereBody, needle: "jinja2.exceptions", conf: ConfidenceHigh, tech: TplJinja2},
	{where: whereBody, needle: "jinja2", conf: ConfidenceMedium, tech: TplJinja2},
	{where: whereBody, needle: "undefinederror", conf: ConfidenceMedium, tech: TplJinja2},
	{where: whereBody, needle: "django.template", conf: ConfidenceHigh, tech: TplDjango},
	{where: whereBody, needle: "templatedoesnotexist", conf: ConfidenceHigh, tech: TplDjango},
	{where: whereBody, needle: "variabledoesnotexist", conf: ConfidenceHigh, tech: TplDjango},
	{where: whereBody, needle: `twig\error`, conf: ConfidenceHigh, tech: TplTwig},
	{where: whereBody, needle: "twig_error", conf: ConfidenceHigh, tech: TplTwig},
	{where: whereBody, needle: `twig\environment`, conf: ConfidenceHigh, tech: TplTwig},
	{where: whereBody, needle: "freemarker.template", conf: ConfidenceHigh, tech: TplFreemarker},
	{where: whereBody, needle: "freemarker.core", conf: ConfidenceHigh, tech: TplFreemarker},
	{where: whereBody, needle: "freemarker", conf: ConfidenceMedium, tech: TplFreemarker},
	{where: whereBody, needle: "org.apache.velocity", conf: ConfidenceHigh, tech: TplVelocity},
	{where: whereBody, needle: "velocityengine", conf: ConfidenceHigh, tech: TplVelocity},
	{where: whereBody, needle: "velocity template", conf: ConfidenceMedium, tech: TplVelocity},
	{where: whereBody, needle: "smarty error", conf: ConfidenceHigh, tech: TplSmarty},
	{where: whereBody, needle: "smarty_compile", conf: ConfidenceHigh, tech: TplSmarty},
	{where: whereBody, needle: "thymeleaf", conf: ConfidenceMedium, tech: TplThymeleaf},
	{where: whereBody, needle: "handlebars", conf: ConfidenceMedium, tech: TplHandlebars},
	{where: whereBody, needle: "mustache", conf: ConfidenceMedium, tech: TplMustache},
	{where: whereBody, needle: "mako.template", conf: ConfidenceHigh, tech: TplMako},
	{where: whereBody, needle: "mako.exceptions", conf: ConfidenceHigh, tech: TplMako},
}

// wafRules are ordered by catalog priority: when two vendors are equally
// confident the earlier entry wins, so the result is stable.
var wafRules = []rule{
	// Cloudflare
	{where: whereHeader, name: "CF-Ray", conf: ConfidenceHigh, tech: WAFCloudflare},
	{where: whereHeader, name: "Server", needle: "cloudflare", conf: ConfidenceHigh, tech: WAFCloudflare},
	{where: whereCookie, name: "__cfduid", conf: ConfidenceHigh, tech: WAFCloudflare},
	{where: whereCookie, name: "cf_clearance", conf: ConfidenceHigh, tech: WAFCloudflare},
	{where: whereBody, needle: "attention required! | cloudflare", conf: ConfidenceHigh, tech: WAFCloudflare},
	{where: whereBody, needle: "cf-error-details", conf: ConfidenceMedium, tech: WAFCloudflare},

	// Akamai
	{where: whereHeader, name: "X-Akamai-Transformed", conf: ConfidenceHigh, tech: WAFAkamai},
	{where: whereHeader, name: "Akamai-GRN", conf: ConfidenceHigh, tech: WAFAkamai},
	{where: whereHeader, name: "Server", needle: "akamaighost", conf: ConfidenceHigh, tech: WAFAkamai},
	{where: whereCookie, name: "ak_bmsc", conf: ConfidenceMedium, tech: WAFAkamai},
	{where: whereCookie, name: "bm_sz", conf: ConfidenceMedium, tech: WAFAkamai},

	// Imperva / Incapsula
	{where: whereHeader, name: "X-Iinfo", conf: ConfidenceHigh, tech: WAFImperva},
	{where: whereHeader, name: "Server", needle: "incapsula", conf: ConfidenceHigh, tech: WAFImperva},
	{where: whereCookie, name: "visid_incap*", conf: ConfidenceHigh, tech: WAFImperva},
	{where: whereCookie, name: "incap_ses*", conf: ConfidenceHigh, tech: WAFImperva},
	{where: whereBody, needle: "incapsula incident id", conf: ConfidenceHigh, tech: WAFImperva},

	// AWS WAF
	{where: whereHeader, name: "X-Amzn-Waf-Action", conf: ConfidenceHigh, tech: WAFAWS},
	{where: whereBody, needle: "awswaf", conf: ConfidenceHigh, tech: WAFAWS},

	// F5 BIG-IP ASM
	{where: whereHeader, name: "X-WA-Info", conf: ConfidenceHigh, tech: WAFF5},
	{where: whereHeader, name: "Server", needle: "big-ip", conf: ConfidenceHigh, tech: WAFF5},
	{where: whereCookie, name: "bigipserver*", conf: ConfidenceMedium, tech: WAFF5},
	{where: whereCookie, name: "ts01*", conf: ConfidenceMedium, tech: WAFF5},

	// Azure (Application Gateway WAF / Front Door)
	{where: whereHeader, name: "Server", needle: "microsoft-azure-application-gateway", conf: ConfidenceHigh, tech: WAFAzure},
	{where: whereHeader, name: "X-Azure-Ref", conf: ConfidenceMedium, tech: WAFAzure},

	// Sucuri
	{where: whereHeader, name: "X-Sucuri-ID", conf: ConfidenceHigh, tech: WAFSucuri},
	{where: whereHeader, name: "Server", needle: "sucuri", conf: ConfidenceHigh, tech: WAFSucuri},
	{where: whereHeader, name: "X-Sucuri-Cache", conf: ConfidenceMedium, tech: WAFSucuri},
	{where: whereBody, needle: "sucuri website firewall", conf: ConfidenceHigh, tech: WAFSucuri},

	// ModSecurity (any deployment)
	{where: whereBody, needle: "mod_security", conf: ConfidenceHigh, tech: WAFModSecurity},
	{where: whereBody, needle: "modsecurity", conf: ConfidenceHigh, tech: WAFModSecurity},
	{where: whereBody, needle: "this error was generated by mod_security", conf: ConfidenceHigh, tech: WAFModSecurity},

	// WordPress plugins / appliances
	{where: whereCookie, name: "wfwaf-authcookie*", conf: ConfidenceHigh, tech: WAFWordfence},
	{where: whereBody, needle: "wordfence", conf: ConfidenceMedium, tech: WAFWordfence},
	{where: whereCookie, name: "fortiwafsid", conf: ConfidenceHigh, tech: WAFFortiWeb},
	{where: whereCookie, name: "barra_counter_session", conf: ConfidenceHigh, tech: WAFBarracuda},
}

var languageEngines = map[Language][]string{
	LangPHP:    {TplTwig, TplSmarty, TplBlade},
	LangPython: {TplJinja2, TplDjango, TplMako},
	LangRuby:   {TplERB, TplHaml},
	LangJava:   {TplFreemarker, TplVelocity, TplSpEL, TplThymeleaf},
	LangNode:   {TplEJS, TplHandlebars, TplPug, TplNunjucks},
	LangDotNet: {TplRazor},
	LangPerl:   nil,
}

var frameworkEngines = map[Framework][]string{
	FwLaravel:     {TplBlade, TplTwig, TplSmarty},
	FwSymfony:     {TplTwig, TplSmarty},
	FwCodeIgniter: {TplTwig, TplSmarty},
	FwWordPress:   {TplTwig, TplSmarty},
	FwDjango:      {TplDjango, TplJinja2},
	FwFlask:       {TplJinja2},
	FwRails:       {TplERB, TplHaml},
	FwSpring:      {TplThymeleaf, TplFreemarker, TplVelocity, TplSpEL},
	FwExpress:     {TplEJS, TplHandlebars, TplPug, TplNunjucks},
	FwNextJS:      nil,
	FwNuxt:        nil,
	FwAspNet:      {TplRazor},
}

// ---------------------------------------------------------------------------
// Gates
//
// A gate is advisory triage, never a verdict and never a scope decision: it
// only answers whether spending a probe on this class here is worth it. Each
// gate is fail-open on genuinely ambiguous input (an unlabelled response can
// still be the vulnerable one) and fail-closed only on positive evidence that
// the class cannot apply (an opaque download cannot reflect markup).
// ---------------------------------------------------------------------------

// ShouldProbeXSS reports whether reflected-XSS probing makes sense for this
// response. A binary body or a file download can never be rendered as markup,
// so it is skipped; everything else — HTML, XML/SVG, plain text, JSON (clients
// re-render JSON fields into the DOM, and the same parameter may be served as
// HTML on another request), and a response with no usable content type at all —
// is allowed, because ambiguity is not evidence that the parameter is safe.
func ShouldProbeXSS(p Profile) bool {
	if p.Status == http.StatusNotModified {
		return false // the handler did not run; this is a cache reply
	}
	if p.StaticAsset || p.ContentKind == KindBinary {
		return false
	}
	return true
}

// ShouldProbeSSTI reports whether server-side template injection probing makes
// sense, together with the template engines worth trying in order.
//
// It is deliberately narrow. A template engine has to be plausible for the
// response before a probe is worth sending: an unknown stack (a bare static
// file server, an unmarked edge) yields (false, nil) rather than a spray of
// every syntax, and a serialized JSON reply is not a rendered template unless
// the response itself names an engine. A client-rendered SPA shell (Next.js,
// Nuxt) is not a server-side template surface either.
//
// The returned engine list comes from the response, never from a fixed list:
// explicit engine evidence (an error page) first, then the engines pinned by a
// detected framework, then the defaults for each detected language — e.g. PHP
// → twig/smarty/blade, Python → jinja2/django/mako, Java →
// thymeleaf/freemarker/velocity/spel.
func ShouldProbeSSTI(p Profile) (bool, []string) {
	if p.Status == http.StatusNotModified || p.StaticAsset || p.ContentKind == KindBinary {
		return false, nil
	}
	engines := probeEngines(p)
	if len(engines) == 0 {
		return false, nil
	}
	if explicitTemplateEvidence(p) {
		// An error page that names the engine outranks the heuristics below,
		// including the JSON/SPA suppressions.
		return true, engines
	}
	if p.ContentKind == KindJSON {
		return false, nil // serialized data, not a rendered template
	}
	if clientRenderedOnly(p) {
		return false, nil
	}
	return true, engines
}

// ShouldProbeXXE reports whether XML External Entity probing applies. The
// decisive question is on the REQUEST side: does this endpoint accept or carry
// XML at all? A response-side XML content type corroborates it. A JSON-only
// endpoint is never probed, and neither is a request without any XML.
func ShouldProbeXXE(p Profile, reqContentType string, reqBody string) bool {
	if acceptsXML(reqContentType) {
		return true
	}
	if p.ContentKind == KindXML {
		return true
	}
	return bodyLooksXML(reqBody)
}

// ShouldProbeCommandInjection reports whether shell/command-injection probing
// makes sense. It requires evidence that application code — not a static file
// server — handles the request: an identified language/framework, an issued
// (non-edge) cookie, or a body that is a real document rather than an opaque
// download.
func ShouldProbeCommandInjection(p Profile) bool {
	if p.Status == http.StatusNotModified || p.StaticAsset || p.ContentKind == KindBinary {
		return false
	}
	if p.Dynamic {
		return true
	}
	// No fingerprint at all: many frameworks emit none. A document body is
	// still plausibly generated by application code; an empty/unknown response
	// is not worth a blind probe.
	switch p.ContentKind {
	case KindHTML, KindJSON, KindXML, KindText:
		return true
	}
	return false
}

// probeEngines flattens TemplateHints into a deduplicated, ordered list and
// drops the "none" placeholder.
func probeEngines(p Profile) []string {
	seen := make(map[string]bool, len(p.TemplateHints))
	out := make([]string, 0, len(p.TemplateHints))
	for _, e := range p.TemplateHints {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == TplNone || seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// explicitTemplateEvidence reports whether an engine was named by evidence in
// the response rather than merely derived from the language/framework.
func explicitTemplateEvidence(p Profile) bool {
	for _, s := range p.Signals {
		if s.Class == ClassTemplate {
			return true
		}
	}
	return false
}

// clientRenderedOnly reports a stack that renders in the browser (or at build
// time) with no server-side templating: Next.js/Nuxt with no other server-side
// language detected.
func clientRenderedOnly(p Profile) bool {
	client := false
	for _, f := range p.Frameworks {
		switch f {
		case FwNextJS, FwNuxt:
			client = true
		}
	}
	if !client {
		return false
	}
	for _, l := range p.Languages {
		if l != LangNode {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

// classifyContent maps the Content-Type header to a ContentKind, falling back to
// body sniffing when the header is absent or not decisive.
func classifyContent(rawCT string, body []byte) (ContentKind, string) {
	mt := mediaType(rawCT)
	if k, ok := kindForMediaType(mt); ok {
		return k, mt
	}
	return sniffContent(body), mt
}

func mediaType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(raw)
	if err != nil {
		if i := strings.IndexByte(raw, ';'); i >= 0 {
			raw = raw[:i]
		}
		return strings.ToLower(strings.TrimSpace(raw))
	}
	return strings.ToLower(mt)
}

func kindForMediaType(mt string) (ContentKind, bool) {
	switch {
	case mt == "":
		return "", false
	case mt == "text/html", mt == "application/xhtml+xml":
		return KindHTML, true
	case mt == "application/json", mt == "text/json", mt == "application/x-ndjson",
		strings.HasSuffix(mt, "+json"):
		return KindJSON, true
	// SVG is XML that a browser executes as a document; it is deliberately not
	// treated as an opaque image (see isStaticAsset).
	case mt == "image/svg+xml", mt == "application/xml", mt == "text/xml",
		strings.HasSuffix(mt, "+xml"):
		return KindXML, true
	case strings.HasPrefix(mt, "text/"):
		return KindText, true
	case mt == "application/javascript", mt == "application/x-javascript",
		mt == "application/ecmascript", mt == "application/x-www-form-urlencoded",
		mt == "application/graphql", mt == "application/sql",
		mt == "application/x-sh", mt == "application/x-httpd-php":
		return KindText, true
	case mt == "application/octet-stream", mt == "application/pdf",
		mt == "application/zip", mt == "application/gzip", mt == "application/x-tar",
		mt == "application/x-7z-compressed", mt == "application/x-rar-compressed",
		mt == "application/wasm", mt == "application/msword",
		mt == "application/vnd.android.package-archive", mt == "application/java-archive",
		strings.HasPrefix(mt, "image/"), strings.HasPrefix(mt, "audio/"),
		strings.HasPrefix(mt, "video/"), strings.HasPrefix(mt, "font/"),
		strings.HasPrefix(mt, "application/vnd.ms-"),
		strings.HasPrefix(mt, "application/vnd.openxmlformats-"):
		return KindBinary, true
	}
	return "", false
}

// sniffContent is the body-only fallback. It is a heuristic by construction, so
// it only claims the kinds it can recognize from the first bytes.
func sniffContent(body []byte) ContentKind {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), " \t\r\n\f")
	if len(trimmed) == 0 {
		return KindUnknown
	}
	switch trimmed[0] {
	case '{', '[':
		if len(body) <= bodyScanLimit && json.Valid(trimmed) {
			return KindJSON
		}
		// A leading object/array bracket is still the strongest hint available;
		// a truncated or oversized JSON document lands here too.
		return KindJSON
	case '<':
		head := trimmed
		if len(head) > 512 {
			head = head[:512]
		}
		lower := bytes.ToLower(head)
		switch {
		case bytes.HasPrefix(lower, []byte("<?xml")):
			return KindXML
		case bytes.HasPrefix(lower, []byte("<svg")):
			return KindXML
		case bytes.HasPrefix(lower, []byte("<rss")),
			bytes.HasPrefix(lower, []byte("<feed")),
			bytes.HasPrefix(lower, []byte("<soap")),
			bytes.HasPrefix(lower, []byte("<envelope")):
			return KindXML
		case bytes.Contains(lower, []byte("<!doctype html")),
			bytes.Contains(lower, []byte("<html")):
			return KindHTML
		default:
			// An unlabelled '<' prefix is a markup fragment; HTML is the useful
			// reading because that is what a browser would do with it.
			return KindHTML
		}
	}
	if looksBinary(body) {
		return KindBinary
	}
	return KindText
}

// looksBinary reports whether the body is unlikely to be text: a NUL byte or a
// high proportion of control bytes in the first 512 bytes.
func looksBinary(body []byte) bool {
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	control := 0
	for _, b := range head {
		switch {
		case b == 0:
			return true
		case b == '\t', b == '\n', b == '\r', b == '\f', b == '\b':
		case b < 0x20, b == 0x7f:
			control++
		}
	}
	return len(head) > 0 && control*10 > len(head)
}

// textAssetExts are text files that are still opaque to the injection classes
// here: a stylesheet or a JS bundle is not a document the server renders.
var textAssetExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true,
}

// assetExts are paths whose content is a file rather than a page, even when the
// server mislabels it as text.
var assetExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".avif": true, ".bmp": true, ".ico": true, ".tif": true, ".tiff": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mov": true, ".avi": true, ".mkv": true,
	".mp3": true, ".wav": true, ".ogg": true, ".flac": true,
	".pdf": true, ".zip": true, ".gz": true, ".tgz": true, ".tar": true,
	".7z": true, ".rar": true, ".exe": true, ".msi": true, ".dmg": true,
	".iso": true, ".apk": true, ".jar": true, ".bin": true, ".wasm": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".odt": true, ".ods": true, ".odp": true,
}

// isStaticAsset reports that the response is a file/download rather than a
// document. An HTML-labelled response always wins: SPAs serve routes, not
// assets, even under an asset-looking path.
func isStaticAsset(kind ContentKind, ext string, header http.Header) bool {
	if strings.Contains(strings.ToLower(header.Get("Content-Disposition")), "attachment") {
		return true
	}
	if kind == KindBinary {
		return true
	}
	if kind == KindHTML {
		return false
	}
	if textAssetExts[ext] || assetExts[ext] {
		return true
	}
	return false
}

// acceptsXML reports whether a request media type is an XML one.
func acceptsXML(contentType string) bool {
	mt := mediaType(contentType)
	switch {
	case mt == "":
		return false
	case mt == "application/xml", mt == "text/xml", mt == "application/soap+xml":
		return true
	case strings.HasSuffix(mt, "+xml"):
		return true
	}
	// application/x-www-form-urlencoded and multipart/form-data carry a field
	// rather than a document; bodyLooksXML covers an XML value inside them.
	return false
}

// bodyLooksXML reports whether a request body carries an XML document. It
// recognizes a declaration, a document embedded in a multipart/form field, a
// percent-encoded declaration, and a bare element whose name is not an HTML
// element.
func bodyLooksXML(body string) bool {
	if body == "" {
		return false
	}
	if len(body) > xxeBodyScan {
		body = body[:xxeBodyScan]
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<?xml") {
		return true
	}
	if dec, err := url.QueryUnescape(body); err == nil && dec != body {
		if strings.Contains(strings.ToLower(dec), "<?xml") {
			return true
		}
	}
	return bareXMLDocument(strings.TrimLeft(strings.TrimPrefix(body, "\ufeff"), " \t\r\n"))
}

// htmlElementNames keeps bareXMLDocument from reading an HTML fragment in a form
// field as an XML document. Anything not in this set is treated as XML, because
// a non-HTML root element in a body is a much stronger XML hint than an HTML
// one is an HTML hint.
var htmlElementNames = map[string]bool{
	"html": true, "head": true, "body": true, "div": true, "span": true,
	"p": true, "a": true, "img": true, "script": true, "style": true,
	"table": true, "tr": true, "td": true, "th": true, "thead": true,
	"tbody": true, "ul": true, "ol": true, "li": true, "br": true,
	"hr": true, "form": true, "input": true, "button": true, "label": true,
	"section": true, "article": true, "header": true, "footer": true,
	"nav": true, "main": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "meta": true, "link": true, "title": true,
	"iframe": true, "textarea": true, "select": true, "option": true,
	"video": true, "audio": true, "source": true, "canvas": true,
}

func bareXMLDocument(body string) bool {
	if !strings.HasPrefix(body, "<") {
		return false
	}
	end := strings.IndexAny(body, " \t\r\n/>")
	if end <= 1 {
		return false
	}
	name := strings.ToLower(body[1:end])
	if strings.HasPrefix(name, "!") || strings.HasPrefix(name, "?") {
		// <!DOCTYPE ...> or a processing instruction we did not recognize.
		return false
	}
	if htmlElementNames[name] {
		return false
	}
	if body[end] == '/' {
		// A self-closing root, e.g. <stockCheck/>.
		return strings.HasSuffix(strings.TrimSpace(body), "/>")
	}
	return strings.Contains(strings.ToLower(body[end:]), "</"+name+">")
}

// cookieNames extracts Set-Cookie names. Values are deliberately dropped here,
// at the only place cookies are read, so they can never reach a Profile.
func cookieNames(h http.Header) []string {
	raw := h.Values("Set-Cookie")
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, sc := range raw {
		name, _, ok := strings.Cut(sc, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// matchCookie matches a cookie name against a lower-case pattern. A pattern may
// use one '*' wildcard (prefix, suffix, or both) — enough for family cookies
// such as wordpress_* without a regexp engine.
func matchCookie(name, pattern string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if name == "" || pattern == "" {
		return false
	}
	if i := strings.IndexByte(pattern, '*'); i >= 0 {
		prefix, suffix := pattern[:i], pattern[i+1:]
		return len(name) >= len(prefix)+len(suffix) &&
			strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
	}
	return name == pattern
}

// edgeCookies are set by WAFs/CDNs rather than by the application, so they must
// not be mistaken for evidence that application code handled the request.
var edgeCookiePatterns = []string{
	"__cfduid", "__cf_bm", "cf_clearance",
	"visid_incap*", "incap_ses*", "nlbi_*", "ak_bmsc", "bm_sz", "_abck",
	"bigipserver*", "ts01*", "wfwaf-authcookie*", "fortiwafsid",
	"barra_counter_session",
}

func isEdgeCookie(name string) bool {
	for _, pattern := range edgeCookiePatterns {
		if matchCookie(name, pattern) {
			return true
		}
	}
	return false
}

func (a *analyzer) countAppCookie() bool {
	for _, name := range a.cookies {
		if !isEdgeCookie(name) {
			return true
		}
	}
	return false
}

// urlPath returns the path of a URL, tolerating relative or malformed values.
func urlPath(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return u.Path
	}
	p := raw
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.Index(p, "://"); i >= 0 {
		p = p[i+3:]
		if j := strings.IndexByte(p, '/'); j >= 0 {
			return p[j:]
		}
		return ""
	}
	return p
}

func headerValue(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return truncate(h.Get(name))
}

func truncate(s string) string {
	if len(s) <= valueLimit {
		return s
	}
	return s[:valueLimit]
}

func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

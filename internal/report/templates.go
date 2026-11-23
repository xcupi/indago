package report

// The two deliverable templates. See doc.go for the model and renderers.

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/indago/indago/internal/domain"
)

// docFor builds the document for the selected template. An unknown template
// (only reachable by bypassing Template.IsValid) falls back to pentest rather
// than producing a technical dump under a deliverable label.
func docFor(data Data) doc {
	var d doc
	if data.Template == TemplateBugBounty {
		d = buildBugBountyDoc(data)
	} else {
		d = buildPentestDoc(data)
	}
	d.PageNumbers = data.TOCPageNumbers
	return d
}

// writeDocHTML renders the selected template as a self-contained HTML page.
func writeDocHTML(w io.Writer, data Data) error {
	var b strings.Builder
	docFor(data).renderHTML(&b)
	_, err := io.WriteString(w, b.String())
	return err
}

// Template selects the document layout a generator renders.
type Template string

const (
	// TemplateTechnical is the evidence-first layout the engine has always
	// produced (confirmed / needs review / diagnostics, with candidates).
	TemplateTechnical Template = ""
	TemplatePentest   Template = "pentest"
	TemplateBugBounty Template = "bug_bounty"
	// TemplateYesWeHack is the platform-specific submission layout: one
	// Markdown section per confirmed finding, with the platform's five
	// sections and its form fields as metadata. Markdown is its native
	// format; HTML/PDF fall back to the pentest document.
	TemplateYesWeHack Template = "yeswehack"
	// TemplateHackerOne is the HackerOne platform submission layout (Markdown
	// native; HTML/PDF fall back to the pentest document).
	TemplateHackerOne Template = "hackerone"
	// TemplateBugcrowd is the Bugcrowd platform submission layout (Markdown
	// native; HTML/PDF fall back to the pentest document).
	TemplateBugcrowd Template = "bugcrowd"
	// TemplateIntigriti is the Intigriti platform submission layout (Markdown
	// native; HTML/PDF fall back to the pentest document).
	TemplateIntigriti Template = "intigriti"
)

// IsValid reports whether the template is known. The empty value is the
// technical layout, so an older caller that never sets it keeps working.
func (t Template) IsValid() bool {
	switch t {
	case TemplateTechnical, TemplatePentest, TemplateBugBounty, TemplateYesWeHack, TemplateHackerOne, TemplateBugcrowd, TemplateIntigriti:
		return true
	}
	return false
}

// classIntel is the factual per-class context a deliverable needs: the CWE the
// class maps to, the impact a reader should understand, and the remediation
// that class is normally fixed with. It is reference material — the finding's
// own verdict and evidence remain authoritative.
type classIntel struct {
	CWE         string
	Name        string
	Impact      string
	Remediation string
	References  []string
}

const refOWASPXSS = "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"

var classIntelByClass = map[domain.VulnClass]classIntel{
	domain.VulnReflectedXSS: {
		CWE:  "CWE-79",
		Name: "Reflected cross-site scripting",
		Impact: "An attacker can run script in a victim's browser in the context of this origin: read the " +
			"session, act as the user, or pivot to the user's other sessions. The payload is delivered in a " +
			"crafted link, so exploitation needs the victim to follow it.",
		Remediation: "Apply context-aware output encoding at the exact sink (HTML body, attribute, JS string, " +
			"URL), prefer framework auto-escaping, and add a Content-Security-Policy as defence in depth.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", refOWASPXSS},
	},
	domain.VulnStoredXSS: {
		CWE:  "CWE-79",
		Name: "Stored cross-site scripting",
		Impact: "Script is persisted by the application and executes for every viewer: session theft, " +
			"action-on-behalf, or worm-like spread without a per-victim lure.",
		Remediation: "Encode on OUTPUT at the sink (not only on input), sanitise rich text with an allow-list, " +
			"and add a Content-Security-Policy.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", refOWASPXSS},
	},
	domain.VulnDOMXSS: {
		CWE:  "CWE-79",
		Name: "DOM-based cross-site scripting",
		Impact: "Client-side code moves attacker-controlled data into an executable sink, so the server never " +
			"sees the payload and server-side filters do not apply.",
		Remediation: "Use safe sinks (textContent, setAttribute for non-URL attributes), validate URL schemes, " +
			"and avoid eval/Function/string timers with untrusted data.",
		References: []string{"https://cwe.mitre.org/data/definitions/79.html", "https://owasp.org/www-community/attacks/DOM_Based_XSS"},
	},
	domain.VulnIDOR: {
		CWE:  "CWE-639",
		Name: "Insecure direct object reference",
		Impact: "An authenticated user can read or act on another principal's object by changing an " +
			"identifier, exposing data across accounts.",
		Remediation: "Authorize every object access server-side against the caller's identity (not the " +
			"supplied id), and prefer unguessable identifiers as defence in depth.",
		References: []string{"https://cwe.mitre.org/data/definitions/639.html", "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
	},
	domain.VulnAccessControl: {
		CWE:  "CWE-862",
		Name: "Broken access control",
		Impact: "A privileged surface or action is reachable by a caller who should be denied, enabling " +
			"function-level escalation (admin actions, role changes, protected endpoints).",
		Remediation: "Enforce authorization server-side on every route and method (deny by default), and do " +
			"not trust client-supplied path/method/header overrides for the decision.",
		References: []string{"https://cwe.mitre.org/data/definitions/862.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/"},
	},
	domain.VulnOpenRedirect: {
		CWE:  "CWE-601",
		Name: "Open redirect",
		Impact: "A link on the trusted origin sends the user to an attacker-chosen destination, which " +
			"enables phishing under the real brand and can bypass link filters that trust this host.",
		Remediation: "Redirect only to an allow-listed destination or to a relative path; never take the " +
			"whole target from a request parameter without validating its origin.",
		References: []string{"https://cwe.mitre.org/data/definitions/601.html", "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards"},
	},
	domain.VulnInfoDisclosure: {
		CWE:  "CWE-200",
		Name: "Information disclosure",
		Impact: "Configuration, source code, credentials or version data reachable by the caller shortens " +
			"the path to a deeper compromise.",
		Remediation: "Remove debug artefacts and served metadata from production, return generic errors, and " +
			"exclude repository/VCS files at the web root.",
		References: []string{"https://cwe.mitre.org/data/definitions/200.html"},
	},
	domain.VulnPathTraversal: {
		CWE:  "CWE-22",
		Name: "Path traversal / local file inclusion",
		Impact: "A request parameter reaches a filesystem path, so the caller reads files outside the directory " +
			"the endpoint intended: configuration, credentials, source code or key material. The response is an " +
			"ordinary successful read, so the exposure leaves no error behind to notice.",
		Remediation: "Resolve the requested name against a fixed base directory and reject the request when the " +
			"resolved path leaves it (clean the path, then require it to stay under the base prefix, or serve " +
			"only an allow-list of known files). Never pass a user-supplied name straight to a file API.",
		References: []string{"https://cwe.mitre.org/data/definitions/22.html", "https://owasp.org/www-community/attacks/Path_Traversal"},
	},
	domain.VulnCommandInjection: {
		CWE:  "CWE-78",
		Name: "OS command injection",
		Impact: "A parameter value reaches a shell command, so the caller can run commands as the web process: read " +
			"files, reach internal services, or take the host. Indago's own probe executes only a benign marker " +
			"command; the weakness is command execution regardless of how gently it was proved.",
		Remediation: "Never build a shell command from user input. Use an API that takes an argument vector, " +
			"allow-list any value that must reach a process, and run the service with least privilege.",
		References: []string{"https://cwe.mitre.org/data/definitions/78.html", "https://owasp.org/www-community/attacks/Command_Injection"},
	},
	domain.VulnSSTI: {
		CWE:  "CWE-1336",
		Name: "Server-side template injection",
		Impact: "A template expression supplied by the caller is evaluated by the server's template engine. Depending " +
			"on the engine that is a read of server-side objects, a path to command execution, or both. Indago's " +
			"probe only evaluates a benign arithmetic marker.",
		Remediation: "Keep user data out of template source. Pass untrusted values as template context variables and " +
			"render them with the engine's escaping; never compile a template from request input.",
		References: []string{"https://cwe.mitre.org/data/definitions/1336.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"},
	},
	domain.VulnSQLi: {
		CWE:  "CWE-89",
		Name: "SQL injection",
		Impact: "A parameter changes the SQL statement the server executes. That can bypass authentication, read or " +
			"modify other users' rows, and in some configurations reach the filesystem or the database host. The " +
			"engine confirms the divergence with read-only marker payloads.",
		Remediation: "Use parameterized queries or prepared statements for every value, never string concatenation; " +
			"validate types and allow-list sort/column names; give the database user only the privileges it needs.",
		References: []string{"https://cwe.mitre.org/data/definitions/89.html", "https://owasp.org/www-community/attacks/SQL_Injection"},
	},
	domain.VulnXXE: {
		CWE:  "CWE-611",
		Name: "XML external entity processing",
		Impact: "An XML parser resolves an external entity supplied inside the request, so the caller can read local " +
			"files or make the server issue outbound requests (SSRF). Indago's probe uses a self-contained marker " +
			"entity and never reads a real file.",
		Remediation: "Disable DTDs and external entity resolution in every XML parser (for example disallow-doctype-decl " +
			"and external-general-entities off), and reject documents that declare a DOCTYPE unless the format " +
			"requires it.",
		References: []string{"https://cwe.mitre.org/data/definitions/611.html", "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"},
	},
	domain.VulnSSRF: {
		CWE:  "CWE-918",
		Name: "Server-side request forgery",
		Impact: "A parameter makes the server issue an outbound request to a destination the attacker chooses, which " +
			"can reach internal services, cloud metadata endpoints or localhost-only admin interfaces the attacker " +
			"cannot address directly.",
		Remediation: "Resolve and validate the destination against an allow-list (scheme, host, port and resolved IP; " +
			"reject private, link-local and metadata ranges), disable redirects or re-validate every hop, and do " +
			"not return the raw response body to the caller.",
		References: []string{"https://cwe.mitre.org/data/definitions/918.html", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
	},
	domain.VulnCORS: {
		CWE:  "CWE-942",
		Name: "Permissive cross-origin resource sharing",
		Impact: "A permissive cross-origin policy lets an attacker's page read authenticated responses from this " +
			"origin, so data the victim can see is exposed to the attacker's site. The engine observes the policy " +
			"headers only; it never exfiltrates data.",
		Remediation: "Allow only explicit trusted origins on credentialed endpoints. Never reflect an arbitrary Origin " +
			"and never combine that with Access-Control-Allow-Credentials: true; keep the allowed methods and " +
			"headers minimal.",
		References: []string{"https://cwe.mitre.org/data/definitions/942.html", "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"},
	},
	domain.VulnGraphQL: {
		CWE:  "CWE-200",
		Name: "GraphQL schema or error disclosure",
		Impact: "GraphQL introspection, verbose errors or unbounded queries expose the schema and data the caller was " +
			"not meant to see, which shortens the path to a targeted query or mutation. The engine observes the " +
			"endpoint's own responses, read-only.",
		Remediation: "Disable introspection in production where it is not needed, return generic errors, enforce query " +
			"depth/complexity and cost limits, and authorize every field and mutation server-side.",
		References: []string{"https://cwe.mitre.org/data/definitions/200.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"},
	},
	domain.VulnNoSQLi: {
		CWE:  "CWE-943",
		Name: "NoSQL query-operator injection",
		Impact: "The caller controls the database query's own structure, not just a value: array-shaped or operator-shaped input " +
			"reaches the document store and changes the predicate. That bypasses a login filter or filters the whole " +
			"collection into the response, so stored data is exposed and, where the same query also writes, altered.",
		Remediation: "Cast every user-supplied query value to its expected scalar type (or reject arrays/objects at the edge), " +
			"validate against an allow-list of queryable fields, and never pass a request object straight into a query " +
			"predicate. Use the driver's schema/ODM validation and least-privileged database users.",
		References: []string{"https://cwe.mitre.org/data/definitions/943.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"},
	},
	domain.VulnSecurityHeaders: {
		CWE:  "CWE-693",
		Name: "Missing or weak response security headers",
		Impact: "The browser is given no instruction to refuse a TLS downgrade (HSTS), no instruction to stop " +
			"MIME sniffing (X-Content-Type-Options), and no framing policy (CSP/X-Frame-Options). Each removal " +
			"turns a separate browser defence off, which makes an injection or a clickjacking lure easier to land.",
		Remediation: "Send Strict-Transport-Security on every HTTPS response, X-Content-Type-Options: nosniff, a " +
			"Content-Security-Policy that includes frame-ancestors, and remove Server/X-Powered-By version strings " +
			"at the application or the edge.",
		References: []string{"https://cwe.mitre.org/data/definitions/693.html", "https://owasp.org/www-project-secure-headers/"},
	},
	domain.VulnCookiePolicy: {
		CWE:  "CWE-614",
		Name: "Cookie missing security attributes",
		Impact: "A session-like cookie without HttpOnly can be read by any script running on the origin; a cookie " +
			"without Secure is also sent over plain HTTP; a cookie without SameSite is attached to cross-site " +
			"requests. Together these expose the session to script access, network interception and CSRF.",
		Remediation: "Set every session cookie with HttpOnly, Secure and SameSite=Lax or Strict (None only when a " +
			"genuine cross-site flow needs it, and then together with Secure).",
		References: []string{"https://cwe.mitre.org/data/definitions/614.html", "https://owasp.org/www-community/controls/SecureCookieAttribute"},
	},
	domain.VulnHostHeader: {
		CWE:  "CWE-644",
		Name: "Host header injection",
		Impact: "The server uses the client-supplied Host / X-Forwarded-Host value when it builds a redirect " +
			"target or an absolute URL, so a crafted request makes the site point at an attacker-controlled " +
			"host. That enables phishing under the real brand, password-reset links that lead to the attacker, " +
			"and poisoning of a shared cache that then serves the malicious host to other users.",
		Remediation: "Never derive a redirect target, an absolute link or a cache key from the request's Host or " +
			"X-Forwarded-Host header. Configure the canonical hostname server-side, validate any incoming Host " +
			"against that allow-list and reject (or ignore) anything else, and make sure a front proxy does not " +
			"pass an unvalidated X-Forwarded-Host through.",
		References: []string{"https://cwe.mitre.org/data/definitions/644.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"},
	},
	domain.VulnJWT: {
		CWE:  "CWE-347",
		Name: "JWT validation and hygiene weakness",
		Impact: "A token whose signature the server never verifies is not an authentication boundary: any caller can " +
			"mint a token naming any subject and be treated as that user. Claim-level weaknesses are weaker but still " +
			"real: a token with no expiry never stops working, a very long lifetime widens the window a leak is " +
			"usable in, and secret material in the payload is readable by everyone who sees the token, because a JWT " +
			"payload is only base64url-encoded.",
		Remediation: "Verify every token's signature before trusting a claim, pin the accepted algorithms to an " +
			"explicit allow-list that excludes none, reject failures with 401, keep access-token lifetimes short " +
			"with a revocable refresh token, and never place passwords, API keys or other secrets in the payload.",
		References: []string{"https://cwe.mitre.org/data/definitions/347.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens"},
	},
	domain.VulnHTTPMethods: {
		CWE:  "CWE-749",
		Name: "Exposed dangerous HTTP method",
		Impact: "The origin answers, or advertises, methods a page never needs. A TRACE that echoes the request hands " +
			"back the headers the client sent — session cookies included — to whoever can make that client issue " +
			"TRACE (the cross-site tracing primitive). An unauthenticated OPTIONS response advertising PUT, DELETE or " +
			"PATCH tells an attacker the resource accepts writes; whether it truly does without authorization has to " +
			"be confirmed separately, because Indago never sends the write itself.",
		Remediation: "Disable TRACE at the server or reverse proxy (Apache: TraceEnable off; nginx: return 405 for " +
			"TRACE). Answer OPTIONS with only the methods the route implements for that caller, require " +
			"authentication before advertising write methods, and turn WebDAV off on origins that do not serve it.",
		References: []string{"https://cwe.mitre.org/data/definitions/749.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_HTTP_Verb_Tampering"},
	},
	domain.VulnTLSConfig: {
		CWE:  "CWE-326",
		Name: "Inadequate TLS transport configuration",
		Impact: "A transport that cannot negotiate TLS 1.2 or better — or that negotiated a broken cipher or serves " +
			"an expired certificate — does not provide the confidentiality and integrity its users assume. TLS 1.0 " +
			"and 1.1 have known protocol weaknesses and are refused by current browsers, and an expired certificate " +
			"makes every verifying client refuse the origin or train its users to click through warnings.",
		Remediation: "Require TLS 1.2 as the minimum protocol version (prefer TLS 1.3), restrict the listener to AEAD " +
			"cipher suites, disable export and NULL suites entirely, and automate certificate renewal so a " +
			"certificate cannot expire unnoticed.",
		References: []string{"https://cwe.mitre.org/data/definitions/326.html", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"},
	},
	domain.VulnWebSocket: {
		CWE:  "CWE-1385",
		Name: "Missing Origin validation in WebSockets",
		Impact: "A browser sends cookies with a WebSocket handshake to any origin that opens the socket, and the " +
			"server's only defence is validating the handshake's Origin header (CWE-1385, an instance of " +
			"CWE-346 origin validation error). A server that answers 101 Switching Protocols for an arbitrary Origin " +
			"lets a page on an attacker-controlled site open an authenticated socket as the victim: the attacker can " +
			"read whatever the socket pushes and send whatever the application accepts. An upgrade that needs no " +
			"session at all exposes the same socket to anyone who can reach it, and a plaintext ws:// endpoint " +
			"carries all of it in the clear.",
		Remediation: "Validate the Origin header of every Upgrade request against an explicit allow-list of the " +
			"application's own origins before answering 101, require the same authentication on the socket that the " +
			"HTTP application requires, keep an authorization check on every message, and serve the endpoint over " +
			"wss:// only.",
		References: []string{"https://cwe.mitre.org/data/definitions/1385.html", "https://cwe.mitre.org/data/definitions/346.html", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"},
	},
	domain.VulnCSRF: {
		CWE:  "CWE-352",
		Name: "Cross-Site Request Forgery (CSRF)",
		Impact: "A state-changing endpoint that relies on ambient session cookies without a per-session or per-request " +
			"anti-CSRF token, strict SameSite cookie attribute, or Origin/Referer verification lets an attacker-controlled " +
			"page trigger unintended state changes in the victim's authenticated session.",
		Remediation: "Require an unpredictable, session-bound anti-CSRF token (synchronizer token or double-submit with " +
			"__Host- cookie) on all state-changing requests, set SameSite=Lax or SameSite=Strict on session cookies, " +
			"and validate the Origin/Referer header on state-changing endpoints.",
		References: []string{"https://cwe.mitre.org/data/definitions/352.html", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
	},
	domain.VulnPrototypePollution: {
		CWE:  "CWE-1321",
		Name: "Client-side Prototype Pollution",
		Impact: "Client-side JavaScript merges attacker-controlled query or URL fragment keys into plain objects " +
			"without filtering __proto__, constructor, or prototype, allowing properties on Object.prototype to be " +
			"polluted and potentially chained into DOM XSS or application logic bypass.",
		Remediation: "Use Object.create(null) or Map for key-value lookups, reject or strip __proto__, constructor, " +
			"and prototype keys during recursive merge/query parsing, and consider Object.freeze(Object.prototype) " +
			"where compatible.",
		References: []string{"https://cwe.mitre.org/data/definitions/1321.html", "https://portswigger.net/web-security/prototype-pollution"},
	},
	domain.VulnCachePoisoning: {
		CWE:  "CWE-349",
		Name: "Web Cache Poisoning",
		Impact: "An unkeyed request header (such as X-Forwarded-Host or X-Original-URL) alters the cached response " +
			"and is served to subsequent users requesting the same cache key, enabling stored XSS, open redirect, or " +
			"resource hijacking at the cache layer.",
		Remediation: "Ignore unkeyed forwarding headers unless explicitly required from a trusted reverse proxy, or " +
			"include any header that influences response generation in the cache Vary key.",
		References: []string{"https://cwe.mitre.org/data/definitions/349.html", "https://portswigger.net/web-security/web-cache-poisoning"},
	},
	domain.VulnFileUpload: {
		CWE:  "CWE-434",
		Name: "Unrestricted File Upload",
		Impact: "An upload endpoint that accepts dangerous file extensions, double extensions, or active MIME types " +
			"(such as .php, .jsp, .html, or .svg) without server-side allow-list validation can lead to stored XSS " +
			"or remote code execution if uploaded files are served from the application origin.",
		Remediation: "Enforce a strict server-side extension and magic-byte allow-list, rename uploaded files to " +
			"random identifiers without user-supplied extensions, and serve user uploads from a separate sandboxed " +
			"domain with Content-Disposition: attachment.",
		References: []string{"https://cwe.mitre.org/data/definitions/434.html", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"},
	},
}

func intelFor(class domain.VulnClass) classIntel {
	if in, ok := classIntelByClass[class]; ok {
		return in
	}
	name := strings.ReplaceAll(string(class), "_", " ")
	if name == "" {
		name = "finding"
	}
	return classIntel{
		CWE:         "n/a",
		Name:        name,
		Impact:      "Impact depends on the finding's own evidence; see the technical detail.",
		Remediation: "Fix the root cause identified in the finding and re-test the same request.",
		References:  []string{},
	}
}

// deliverableFindings returns the findings a deliverable reports: confirmed
// first, then those awaiting review. Rejected diagnostics are not
// vulnerabilities and stay out of the deliverable body; their count is noted.
func deliverableFindings(data Data) ([]*domain.Finding, int) {
	all := Prioritized(data.Findings)
	out := make([]*domain.Finding, 0, len(all))
	diagnostics := 0
	for _, f := range all {
		if f.Verdict == domain.VerdictRejected {
			diagnostics++
			continue
		}
		out = append(out, f)
	}
	return out, diagnostics
}

func severityCounts(findings []*domain.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		out[string(f.Severity)]++
	}
	return out
}

func severityLine(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	if len(parts) == 0 {
		return "no confirmed findings"
	}
	return strings.Join(parts, ", ")
}

func scopeSeeds(data Data) []string {
	if len(data.Scan.SeedURLs) > 0 {
		return data.Scan.SeedURLs
	}
	return []string{string(data.Scan.ID) + " (target base URL)"}
}

// buildPentestDoc is the client-deliverable layout: confidentiality, engagement,
// executive summary, approach, summary table, technical findings, remediation
// roadmap, appendices.
func buildPentestDoc(data Data) doc {
	findings, diagnostics := deliverableFindings(data)
	idx := EvidenceIndex(data.Evidence)
	coverage := coverageFor(data)
	view := NewFindingView
	counts := severityCounts(findings)
	seedLabel := seedLabelFor(len(scopeSeeds(data)))

	d := doc{
		Title:    fmt.Sprintf("Penetration Test Report — %s", nonEmpty(data.Project.Name, string(data.Project.ID))),
		Subtitle: nonEmpty(data.Scan.Name, string(data.Scan.ID)),
		Meta:     docPreamble(data),
		Highlights: [][2]string{
			{"Confirmed findings", fmt.Sprintf("%d", len(confirmedOnly(findings)))},
			{"High / critical", fmt.Sprintf("%d", counts["high"]+counts["critical"])},
			{"Coverage", coverageShort(coverage)},
			{seedLabel, fmt.Sprintf("%d", len(scopeSeeds(data)))},
		},
	}

	d.Sections = append(d.Sections, section("Statement of Confidentiality",
		para("This report contains confidential security information about the target described below. "+
			"It is provided to the commissioning party for the purpose of remediating the issues it documents, "+
			"and must not be redistributed outside that party without written consent. The assessment was "+
			"performed with authorization against the scope recorded here; findings describe the state observed "+
			"at the time of testing and are not a guarantee that the target is free of other issues."),
	))

	scope := []string{}
	for _, seed := range scopeSeeds(data) {
		scope = append(scope, "In-scope seed: "+seed)
	}
	scope = append(scope,
		fmt.Sprintf("Profile: %s · scan %s", data.Scan.Profile, data.Scan.ID),
		fmt.Sprintf("Findings included: %s", selectionLine(dataSummary(data, findings))),
	)
	if data.Scan.StartedAt != nil {
		scope = append(scope, "Testing started: "+data.Scan.StartedAt.UTC().Format("2006-01-02 15:04"))
	}
	if data.Scan.EndedAt != nil {
		scope = append(scope, "Testing ended: "+data.Scan.EndedAt.UTC().Format("2006-01-02 15:04"))
	}
	d.Sections = append(d.Sections, section("Engagement & Scope", list(scope...)))

	execHeadline := fmt.Sprintf("%d confirmed finding(s): %s.", len(confirmedOnly(findings)), severityLine(counts))
	var execFindings []string
	for _, f := range findings {
		if f.Verdict != domain.VerdictConfirmed {
			continue
		}
		execFindings = append(execFindings, fmt.Sprintf("%s — %s (%s)", f.Title, strings.ToUpper(string(f.Severity)), intelFor(f.VulnClass).CWE))
	}
	exec := execFindings
	if len(exec) == 0 {
		exec = append(exec, "No confirmed findings were recorded in the selected set.")
	}
	if diagnostics > 0 {
		exec = append(exec, fmt.Sprintf("%d rejected diagnostic attempt(s) are excluded from this body; they are not vulnerabilities.", diagnostics))
	}
	execBlocks := []docBlock{
		para(fmt.Sprintf("%s was assessed with indago. %s", nonEmpty(data.Project.Name, "The target"), coverageSentence(coverage))),
	}
	execBlocks = append(execBlocks, para(execHeadline))
	if strings.TrimSpace(data.AISummary) != "" {
		execBlocks = append(execBlocks, para("AI-assisted draft (unverified, advisory only — the findings below are the authoritative record): "+data.AISummary))
	}
	if len(exec) > 0 {
		execBlocks = append(execBlocks, list(exec...))
	}
	d.Sections = append(d.Sections, section("Executive Summary", execBlocks...))

	approach := []string{
		"Discovery enumerated endpoints and parameters from the in-scope seeds, then classified each response position.",
		"Reflected and DOM XSS candidates are confirmed only by a real browser execution signal (a marker-specific ReferenceError), never by reflection alone.",
		"Access-control probes are differential and read-only: a denied surface must answer differently to the bypass variant, and the reachable surface must expose a privileged action.",
		"IDOR probes compare the caller's own object against a harvested foreign identifier and require a different principal's data.",
		"Information-disclosure probes classify bytes the scan already reached (debug pages, backup source, stack traces, served .git metadata).",
	}
	d.Sections = append(d.Sections, section("Approach & Methodology", list(approach...)))

	summaryRows := make([][]string, 0, len(findings))
	for i, f := range findings {
		summaryRows = append(summaryRows, []string{
			fmt.Sprintf("%d", i+1),
			strings.ToUpper(string(f.Severity)),
			intelFor(f.VulnClass).Name,
			f.Title,
			endpointLabel(f, view(f, idx), data.Endpoints[f.EndpointID]),
		})
	}
	if len(summaryRows) == 0 {
		summaryRows = append(summaryRows, []string{"—", "—", "—", "No findings in this selection", "—"})
	}
	targetLine := "Target: " + strings.Join(uniqueHosts(findings, view, idx), ", ")
	d.Sections = append(d.Sections, section("Summary of Findings",
		para(targetLine),
		sizedTable(
			[]string{"#", "Severity", "Class", "Finding", "Endpoint"},
			[]string{"5%", "11%", "17%", "50%", "17%"},
			summaryRows),
	))

	tech := []docBlock{}
	for i, f := range findings {
		v := view(f, idx)
		in := intelFor(f.VulnClass)
		tech = append(tech, sub(fmt.Sprintf("%d. %s — %s", i+1, f.Title, strings.ToUpper(string(f.Severity)))))
		tech = append(tech, list(
			"CWE: "+in.CWE+" ("+in.Name+")",
			"Verdict: "+strings.ToUpper(string(f.Verdict))+" · severity "+string(f.Severity)+" · confidence "+string(f.Confidence),
			"Affected asset: "+findingAsset(f, v),
		))
		if f.Summary != "" {
			tech = append(tech, para("Description: "+f.Summary))
		}
		tech = append(tech, para("Impact: "+in.Impact))
		tech = append(tech, para("Remediation: "+in.Remediation))
		if len(in.References) > 0 {
			tech = append(tech, list(prefixed("Reference: ", in.References)...))
		}
		if v.Verified != nil && v.Verified.CandidateValue != "" {
			tech = append(tech, para("Verified request / payload:"), code(candidateProof(v)))
		}
		if len(f.EvidenceIDs) > 0 {
			tech = append(tech, sub("Evidence"), evidenceTable(f, idx))
		} else {
			tech = append(tech, para("Evidence: no stored artifacts for this finding."))
		}
	}
	if len(tech) == 0 {
		tech = append(tech, para("No confirmed or reviewable findings in this selection."))
	}
	d.Sections = append(d.Sections, section("Technical Findings Details", tech...))

	short, medium, long := []string{}, []string{}, []string{}
	shortM, mediumM, longM := map[string]*roadmapItem{}, map[string]*roadmapItem{}, map[string]*roadmapItem{}
	for _, f := range findings {
		in := intelFor(f.VulnClass)
		switch f.Severity {
		case domain.SeverityCritical, domain.SeverityHigh:
			addRoadmap(shortM, in, f.Title)
		case domain.SeverityMedium:
			addRoadmap(mediumM, in, f.Title)
		default:
			addRoadmap(longM, in, f.Title)
		}
	}
	short, medium, long = roadmapLines(shortM), roadmapLines(mediumM), roadmapLines(longM)
	roadmap := [][]string{
		{"Immediate", "0-7 days", joinOr(short, "None in this selection.")},
		{"Planned", "30 days", joinOr(medium, "None in this selection.")},
		{"Backlog", "90 days", joinOr(long, "None in this selection.")},
	}
	d.Sections = append(d.Sections, section("Remediation Summary",
		para("Ordered by the severity of the finding each item fixes. Timeframes are the usual triage windows, not a commitment made by this report."),
		sizedTable([]string{"Priority", "Timeframe", "Action"}, []string{"16%", "13%", "71%"}, roadmap),
	))

	d.Sections = append(d.Sections, section("Appendix A — Finding Severities",
		table([]string{"Severity", "Meaning"}, [][]string{
			{"Critical", "Direct path to broad compromise; fix before further exposure."},
			{"High", "Serious impact with realistic exploitation; fix in the short term."},
			{"Medium", "Material weakness requiring specific conditions; schedule a fix."},
			{"Low", "Limited impact or defence-in-depth gap."},
			{"Info", "Observation without a demonstrated security impact."},
		}),
	))

	evRows := [][]string{}
	for _, f := range findings {
		for _, id := range f.EvidenceIDs {
			kind, size := "—", ""
			if ev := idx[id]; ev != nil {
				kind = string(ev.Kind)
				size = fmt.Sprintf("%d bytes", ev.Size)
			}
			evRows = append(evRows, []string{string(id), f.Title, kind, size})
		}
	}
	if len(evRows) == 0 {
		evRows = append(evRows, []string{"—", "No evidence referenced by this selection", "—", "—"})
	}
	d.Sections = append(d.Sections, section("Appendix B — Evidence Inventory",
		sizedTable([]string{"Evidence", "Finding", "Kind", "Size"}, []string{"38%", "34%", "16%", "12%"}, evRows),
	))

	d.Sections = append(d.Sections, section("Appendix C — Coverage",
		para(coverageSentence(coverage)),
		list(coverageBullets(coverage)...),
	))
	return d
}

// buildBugBountyDoc renders one submission-shaped block per finding: asset,
// severity, CWE, reproduction, impact, remediation, references, evidence.
func buildBugBountyDoc(data Data) doc {
	findings, diagnostics := deliverableFindings(data)
	idx := EvidenceIndex(data.Evidence)
	view := NewFindingView
	seedLabel := seedLabelFor(len(scopeSeeds(data)))

	d := doc{
		Title:    fmt.Sprintf("Bug Bounty Report — %s", nonEmpty(data.Project.Name, string(data.Project.ID))),
		Subtitle: "Submission-ready findings from one authorized scan",
		Meta:     docPreamble(data),
		Highlights: [][2]string{
			{"Findings", fmt.Sprintf("%d", len(findings))},
			{"Confirmed", fmt.Sprintf("%d", len(confirmedOnly(findings)))},
			{"Highest severity", highestSeverity(findings)},
			{seedLabel, fmt.Sprintf("%d", len(scopeSeeds(data)))},
		},
	}

	assetList := []string{}
	for _, seed := range scopeSeeds(data) {
		assetList = append(assetList, seed)
	}
	if diagnostics > 0 {
		assetList = append(assetList, fmt.Sprintf("%d rejected diagnostic attempt(s) excluded (not vulnerabilities).", diagnostics))
	}
	d.Sections = append(d.Sections, section("Scope & Asset",
		list(assetList...),
		para("All testing was authorized and limited to the seeds above. Requests were rate-limited and read-only except where a probe required a benign form submission; no destructive action was performed."),
	))

	if len(findings) == 0 {
		d.Sections = append(d.Sections, section("Result", para("No confirmed or reviewable findings were recorded in this selection.")))
		return d
	}

	for i, f := range findings {
		v := view(f, idx)
		in := intelFor(f.VulnClass)
		body := []docBlock{
			list(
				"Asset: "+findingAsset(f, v),
				"Severity: "+strings.ToUpper(string(f.Severity))+" · confidence "+string(f.Confidence),
				"CWE: "+in.CWE+" ("+in.Name+")",
				"CVSS: not scored — severity is the engine's verdict, not a CVSS computation",
				"Vulnerability class: "+string(f.VulnClass),
			),
			sub("Description"),
			para(sentenceCase(nonEmpty(f.Summary, f.Title))),
		}
		body = append(body, sub("Steps to reproduce"))
		steps := []string{
			"Request the affected asset recorded above.",
		}
		if v.Method != "" && v.ParamName != "" {
			steps = append(steps, fmt.Sprintf("Inject into %s parameter %q.", v.Method, v.ParamName))
		}
		if v.Verified != nil && v.Verified.URL != "" {
			steps = append(steps, "Use the exact verified request below.")
		} else {
			steps = append(steps, "Use the candidate recorded in the evidence bundle.")
		}
		steps = append(steps, "Observe the browser signal recorded in the result block below.")
		body = append(body, list(steps...))
		if v.Verified != nil && v.Verified.CandidateValue != "" {
			body = append(body, code(candidateProof(v)))
		}
		body = append(body,
			sub("Impact"),
			para(in.Impact),
			sub("Remediation"),
			para(in.Remediation),
		)
		if len(in.References) > 0 {
			body = append(body, sub("References"), list(in.References...))
		}
		body = append(body, sub("Evidence"))
		if len(f.EvidenceIDs) > 0 {
			body = append(body, evidenceTable(f, idx))
		} else {
			body = append(body, para("No stored artifacts for this finding."))
		}

		heading := fmt.Sprintf("Finding %d — %s", i+1, f.Title)
		d.Sections = append(d.Sections, section(heading, body...))
	}

	d.Sections = append(d.Sections, section("Appendix — Severity Ratings",
		table([]string{"Severity", "Typical bounty band"}, [][]string{
			{"Critical", "Remote compromise of the asset's core trust boundary"},
			{"High", "Account/session compromise or privileged action as another user"},
			{"Medium", "Limited data exposure or action requiring user interaction"},
			{"Low", "Defence-in-depth or low-impact disclosure"},
			{"Info", "Observation without demonstrated impact"},
		}),
	))
	return d
}

// sub is a sub-heading block (h3 in HTML, "###" in Markdown).
func sub(text string) docBlock { return docBlock{Kind: docSubheading, Text: text} }

func prefixed(prefix string, items []string) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, prefix+s)
	}
	return out
}

// roadmapItem groups the findings that share one fix, so a table cell does not
// repeat the same remediation paragraph once per finding.
type roadmapItem struct {
	fix    string
	cwe    string
	titles []string
}

func addRoadmap(m map[string]*roadmapItem, in classIntel, title string) {
	key := in.CWE + "|" + in.Remediation
	it := m[key]
	if it == nil {
		it = &roadmapItem{fix: in.Remediation, cwe: in.CWE}
		m[key] = it
	}
	it.titles = append(it.titles, title)
}

// roadmapLines renders one line per distinct fix, sorted so the report stays
// byte-identical between runs (map iteration order is not stable).
func roadmapLines(m map[string]*roadmapItem) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		it := m[k]
		out = append(out, fmt.Sprintf("%s — %s (%s)", strings.Join(it.titles, "; "), it.fix, it.cwe))
	}
	return out
}

// joinOr renders a roadmap cell: the items separated by "; ", or the fallback
// when the bucket is empty.
func joinOr(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, "; ")
}

// seedLabel keeps the KPI label grammatical for one seed.
func seedLabelFor(n int) string {
	if n == 1 {
		return "In-scope seed"
	}
	return "In-scope seeds"
}

// coverageShort is the cover's one-word coverage state.
func coverageShort(c Completeness) string {
	switch {
	case c.Complete():
		return "Complete"
	case c.State == "":
		return "Unknown"
	default:
		return "Incomplete"
	}
}

// highestSeverity is the worst severity among the reported findings, for the
// bounty cover. It never derives a new rating: it is the max of stored values.
func highestSeverity(findings []*domain.Finding) string {
	rank := map[domain.Severity]int{
		domain.SeverityCritical: 5, domain.SeverityHigh: 4,
		domain.SeverityMedium: 3, domain.SeverityLow: 2, domain.SeverityInfo: 1,
	}
	best := domain.SeverityInfo
	bestRank := 0
	for _, f := range findings {
		if r := rank[f.Severity]; r > bestRank {
			best, bestRank = f.Severity, r
		}
	}
	if bestRank == 0 {
		return "—"
	}
	return strings.ToUpper(string(best))
}

// evidenceTable renders one finding's artifacts as rows, instead of the dense
// semicolon-separated paragraph the same data produces in the appendix note.
func evidenceTable(f *domain.Finding, idx map[domain.ID]*domain.Evidence) docBlock {
	rows := make([][]string, 0, len(f.EvidenceIDs))
	for _, id := range f.EvidenceIDs {
		kind, size := "artifact", ""
		if ev := idx[id]; ev != nil {
			kind = string(ev.Kind)
			size = humanBytes(ev.Size)
		}
		typ := kind
		if size != "" {
			typ = kind + " · " + size
		}
		rows = append(rows, []string{string(id), typ})
	}
	return sizedTable([]string{"Artifact", "Type"}, []string{"58%", "42%"}, rows)
}

// humanBytes keeps the size column short enough that an artefact table does
// not push a following section onto its own page.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// sentenceCase capitalises the first letter of an engine note used as a
// sentence ("the browser reported…" reads like a typo in a report body).
func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
	}
	return string(r)
}

// endpointLabel is the summary table's Endpoint cell: method plus path, with
// the query dropped (the injected value there is huge and differs per row
// only by the marker, so it hides which endpoint is which).
func endpointLabel(f *domain.Finding, v FindingView, endpointURL string) string {
	method := strings.TrimSpace(v.Method)
	u := endpointURL
	if u == "" {
		u = verifiedURL(v)
	}
	if u != "" {
		path := "/"
		if parsed, err := url.Parse(u); err == nil {
			if parsed.Path != "" {
				path = parsed.Path
			}
			// Keep the query KEYS (they say which parameter is exercised) but
			// drop the values, which are the injected payload.
			if keys := queryKeys(parsed.RawQuery); keys != "" {
				path += "?" + keys
			}
		}
		if method == "" {
			return path
		}
		return method + " " + path
	}
	if method != "" && v.ParamName != "" {
		return method + " · " + v.ParamName
	}
	return "—"
}

// queryKeys lists the parameter names in a raw query, without their values.
func queryKeys(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 2 {
		keys = keys[:2]
	}
	return strings.Join(keys, "&")
}

// verifiedURL is the exact request the verifier replayed, when there is one.
func verifiedURL(v FindingView) string {
	if v.Verified != nil {
		return v.Verified.URL
	}
	return ""
}

// uniqueHosts lists the distinct hosts the reported findings touch, so the
// summary table can be read without a (truncated) URL in every row.
func uniqueHosts(findings []*domain.Finding, view func(*domain.Finding, map[domain.ID]*domain.Evidence) FindingView, idx map[domain.ID]*domain.Evidence) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		u := verifiedURL(view(f, idx))
		if u == "" {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			continue
		}
		if !seen[parsed.Host] {
			seen[parsed.Host] = true
			out = append(out, parsed.Host)
		}
	}
	if len(out) == 0 {
		return []string{"see scope"}
	}
	sort.Strings(out)
	return out
}

func confirmedOnly(findings []*domain.Finding) []*domain.Finding {
	out := make([]*domain.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Verdict == domain.VerdictConfirmed {
			out = append(out, f)
		}
	}
	return out
}

// candidateProof is the copy-paste proof block: URL first (when the verifier
// navigated), then the exact candidate value.
func candidateProof(v FindingView) string {
	parts := []string{}
	if v.Verified != nil {
		if v.Verified.URL != "" {
			parts = append(parts, "URL: "+v.Verified.URL)
		}
		if v.Verified.CandidateValue != "" {
			parts = append(parts, "Candidate: "+v.Verified.CandidateValue)
		}
		if v.Verified.Notes != "" {
			parts = append(parts, "Result: "+v.Verified.Notes)
		}
	}
	if len(parts) == 0 {
		return "No verified request recorded for this finding."
	}
	return strings.Join(parts, "\n")
}

func verificationSignal(v FindingView) string {
	if v.Verified != nil && v.Verified.Notes != "" {
		return v.Verified.Notes
	}
	if v.ReviewReasonLabel != "" {
		return v.ReviewReasonLabel
	}
	return "the stored evidence for this finding"
}

func coverageSentence(c Completeness) string {
	if c.Complete() {
		if c.HasTestCaseGaps() {
			return fmt.Sprintf("Scan reached the completed state; %s (worker retry may have recovered some).", c.testCaseGapText())
		}
		return "Scan completed without job-level coverage gaps."
	}
	return fmt.Sprintf("Coverage is INCOMPLETE: scan state %s, dead jobs %d, failed jobs %d, canceled jobs %d, error test cases %d, timeout test cases %d. Absence of findings does not mean the target is clean.",
		nonEmpty(string(c.State), "unknown"), c.DeadJobs, c.FailedJobs, c.CanceledJobs, c.ErrorTestCases, c.TimeoutTestCases)
}

func coverageBullets(c Completeness) []string {
	return []string{
		fmt.Sprintf("Scan state: %s", nonEmpty(string(c.State), "unknown")),
		fmt.Sprintf("Dead / failed / canceled jobs: %d / %d / %d", c.DeadJobs, c.FailedJobs, c.CanceledJobs),
		fmt.Sprintf("Error / timeout test cases: %d / %d", c.ErrorTestCases, c.TimeoutTestCases),
	}
}

// sortedSeverities is used by tests to keep deterministic output when checking
// severity keys.
func sortedSeverities(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

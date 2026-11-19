package report_test

// Classification (CWE + CVSS v3.1) and curl PoC tests.
//
// The CVSS tests pin the base score to PUBLISHED reference vectors, so a change
// to the scoring maths has to disagree with the specification to pass. The PoC
// tests pin both directions of the credential rule: parameterized by default
// (no secret can leak into a report), verbatim only when explicitly requested.

import (
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/report"
)

func TestClassifyCoversEveryIndagoClass(t *testing.T) {
	want := map[domain.VulnClass]struct {
		cwe   int
		score float64
	}{
		domain.VulnReflectedXSS:     {79, 6.1},
		domain.VulnStoredXSS:        {79, 6.1},
		domain.VulnDOMXSS:           {79, 6.1},
		domain.VulnSSTI:             {1336, 9.8},
		domain.VulnCommandInjection: {78, 9.8},
		domain.VulnSQLi:             {89, 9.8},
		domain.VulnNoSQLi:           {943, 9.8},
		domain.VulnXXE:              {611, 7.5},
		report.ClassSSRF:            {918, 8.6},
		domain.VulnIDOR:             {639, 6.5},
		domain.VulnAccessControl:    {862, 8.1},
		report.ClassCORS:            {942, 4.3},
		domain.VulnOpenRedirect:     {601, 4.3},
		report.ClassGraphQL:         {200, 5.3},
		domain.VulnInfoDisclosure:   {200, 7.5},
		domain.VulnPathTraversal:    {22, 7.5},
		domain.VulnSecurityHeaders:  {693, 4.2},
		domain.VulnCookiePolicy:     {614, 3.7},
		domain.VulnHostHeader:       {644, 4.7},
		domain.VulnJWT:              {347, 9.1},
	}
	classes := report.Classes()
	if len(classes) != len(want) {
		t.Fatalf("Classes() returned %d classes, want %d", len(classes), len(want))
	}
	for _, class := range classes {
		exp, ok := want[class]
		if !ok {
			t.Fatalf("Classes() returned unclassified class %q", class)
		}
		got, ok := report.Classify(class)
		if !ok {
			t.Fatalf("Classify(%q) = not classified", class)
		}
		if got.CWE.ID != exp.cwe {
			t.Errorf("%s: CWE-%d, want CWE-%d", class, got.CWE.ID, exp.cwe)
		}
		if got.CVSS.BaseScore != exp.score {
			t.Errorf("%s: base score %v, want %v (%s)", class, got.CVSS.BaseScore, exp.score, got.CVSS.Vector)
		}
		if got.CVSS.Severity != report.SeverityForScore(exp.score) {
			t.Errorf("%s: severity %q does not match its score band", class, got.CVSS.Severity)
		}
		// The stored score must be what the vector itself computes: a
		// hand-typed number and a vector are allowed to disagree silently
		// otherwise.
		parsed, err := report.ParseCVSS31(got.CVSS.Vector)
		if err != nil {
			t.Fatalf("%s: built-in vector does not parse: %v", class, err)
		}
		if parsed.BaseScore() != got.CVSS.BaseScore {
			t.Errorf("%s: stored score %v != computed %v", class, got.CVSS.BaseScore, parsed.BaseScore())
		}
		if parsed.Vector() != got.CVSS.Vector {
			t.Errorf("%s: vector is not canonical: %q", class, got.CVSS.Vector)
		}
		if got.Note == "" {
			t.Errorf("%s: classification carries no caveat note", class)
		}
	}
}

func TestClassifyUnknownClassIsNotInvented(t *testing.T) {
	for _, class := range []domain.VulnClass{"", "not_a_class", "rce"} {
		if c, ok := report.Classify(class); ok {
			t.Fatalf("Classify(%q) invented a classification: %+v", class, c)
		}
	}
}

// TestClassifyPathTraversal pins the exact vector and result an operator will
// paste into a submission: CWE-22 and the read-only 7.5 baseline. The table
// test above only checks the score, so a silent vector edit would slip past it.
func TestClassifyPathTraversal(t *testing.T) {
	c, ok := report.Classify(domain.VulnPathTraversal)
	if !ok {
		t.Fatal("path traversal is not classified")
	}
	if c.CWE.ID != 22 || !strings.Contains(c.CWE.Name, "Path Traversal") {
		t.Fatalf("CWE = %s, want CWE-22 Path Traversal", c.CWE)
	}
	const wantVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
	if c.CVSS.Vector != wantVector {
		t.Fatalf("vector = %q, want %q", c.CVSS.Vector, wantVector)
	}
	if c.CVSS.Score() != "7.5" || c.CVSS.Severity != report.CVSSSeverityHigh {
		t.Fatalf("score = %s (%s), want 7.5 high", c.CVSS.Score(), c.CVSS.Severity)
	}
	if !strings.HasPrefix(c.CWE.URL(), "https://cwe.mitre.org/data/definitions/22") {
		t.Fatalf("CWE.URL() = %q", c.CWE.URL())
	}
	if got := c.String(); !strings.Contains(got, "CWE-22") || !strings.Contains(got, "7.5 high") {
		t.Fatalf("Classification.String() = %q", got)
	}
}

func TestClassificationString(t *testing.T) {
	c, ok := report.Classify(domain.VulnReflectedXSS)
	if !ok {
		t.Fatal("reflected xss is not classified")
	}
	got := c.String()
	for _, want := range []string{"CWE-79", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1", "medium"} {
		if !strings.Contains(got, want) {
			t.Errorf("Classification.String() = %q, missing %q", got, want)
		}
	}
	if !strings.HasPrefix(c.CWE.URL(), "https://cwe.mitre.org/data/definitions/79") {
		t.Errorf("CWE.URL() = %q", c.CWE.URL())
	}
	if c.CVSS.Score() != "6.1" {
		t.Errorf("CVSS31.Score() = %q, want \"6.1\"", c.CVSS.Score())
	}
}

// TestCVSS31ReferenceVectors pins the implementation to the specification's
// published base scores. These numbers are the standard anchors every CVSS
// calculator agrees on.
func TestCVSS31ReferenceVectors(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
		band   report.CVSSSeverity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, report.CVSSSeverityMedium},   // reflected XSS
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, report.CVSSSeverityCritical}, // unauthenticated RCE
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, report.CVSSSeverityHigh},     // high-confidentiality read
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6, report.CVSSSeverityHigh},     // SSRF into an internal network
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, report.CVSSSeverityMedium},   // read-only IDOR
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, report.CVSSSeverityHigh},     // missing authorization with write
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, report.CVSSSeverityMedium},   // metadata disclosure
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, report.CVSSSeverityMedium},   // low-impact authenticated read
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, report.CVSSSeverityNone},     // no impact at all
	}
	for _, tc := range cases {
		m, err := report.ParseCVSS31(tc.vector)
		if err != nil {
			t.Fatalf("ParseCVSS31(%q): %v", tc.vector, err)
		}
		if got := m.BaseScore(); got != tc.score {
			t.Errorf("%s: base score %v, want %v", tc.vector, got, tc.score)
		}
		if got := m.Severity(); got != tc.band {
			t.Errorf("%s: severity %q, want %q", tc.vector, got, tc.band)
		}
	}
}

// TestCVSS31RoundupMatchesSpecification is the one rounding rule that differs
// from CVSS v3.0: always round UP to one decimal. 4.2477 must become 4.3, not
// 4.2 (round-to-nearest) and not 4.2 (truncation).
func TestCVSS31RoundupMatchesSpecification(t *testing.T) {
	m, err := report.ParseCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.BaseScore(); got != 4.3 {
		t.Fatalf("base score %v, want 4.3 (Roundup must round up, not to nearest)", got)
	}
	// An exact one-decimal result is preserved, not bumped to the next tenth.
	exact, err := report.ParseCVSS31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatal(err)
	}
	if got := exact.BaseScore(); got != 9.8 {
		t.Fatalf("base score %v, want 9.8", got)
	}
}

func TestCVSS31ParseCanonicalisesOrder(t *testing.T) {
	m, err := report.ParseCVSS31("CVSS:3.1/A:N/I:L/C:L/S:C/UI:R/PR:N/AC:L/AV:N")
	if err != nil {
		t.Fatal(err)
	}
	const want = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	if got := m.Vector(); got != want {
		t.Fatalf("Vector() = %q, want %q", got, want)
	}
}

func TestParseCVSS31RejectsUnusableVectors(t *testing.T) {
	bad := []string{
		"",
		"AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", // no version prefix
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      // 3.0 uses different rounding
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L",          // missing A
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/AV:A", // duplicate AV
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:U",  // temporal metric
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",      // undefined AV value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:/S:C/C:L/I:L/A:N",       // empty value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/",     // trailing separator
	}
	for _, vector := range bad {
		if _, err := report.ParseCVSS31(vector); err == nil {
			t.Errorf("ParseCVSS31(%q) accepted an unusable vector", vector)
		}
	}
}

func TestSeverityForScoreBands(t *testing.T) {
	cases := []struct {
		score float64
		want  report.CVSSSeverity
	}{
		{0, report.CVSSSeverityNone},
		{0.05, report.CVSSSeverityLow},
		{3.9, report.CVSSSeverityLow},
		{4.0, report.CVSSSeverityMedium},
		{6.9, report.CVSSSeverityMedium},
		{7.0, report.CVSSSeverityHigh},
		{8.9, report.CVSSSeverityHigh},
		{9.0, report.CVSSSeverityCritical},
		{10, report.CVSSSeverityCritical},
	}
	for _, tc := range cases {
		if got := report.SeverityForScore(tc.score); got != tc.want {
			t.Errorf("SeverityForScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// curl PoC
// ---------------------------------------------------------------------------

const storedPostRequest = "POST /api/orders/42 HTTP/1.1\r\n" +
	"Host: shop.example.test\r\n" +
	"Authorization: Bearer s3cr3t-token-value\r\n" +
	"Cookie: session=abc123session; theme=dark\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 13\r\n" +
	"X-Api-Key: key-999-secret\r\n" +
	"Connection: close\r\n" +
	"Accept: application/json\r\n" +
	"\r\n" +
	`{"q":"x"}`

func TestCurlPoCParameterisesCredentialsByDefault(t *testing.T) {
	out, err := report.CurlPoCFromEvidence([]byte(storedPostRequest), report.CurlOptions{})
	if err != nil {
		t.Fatalf("CurlPoCFromEvidence: %v", err)
	}
	for _, want := range []string{
		"curl -sS -i -X POST 'https://shop.example.test/api/orders/42'",
		"--max-time 30",
		`-H "Authorization: Bearer $INDAGO_TOKEN"`,
		`-b "$INDAGO_COOKIE"`,
		`-H "X-Api-Key: $INDAGO_TOKEN"`,
		"-H 'Content-Type: application/json'",
		"-H 'Accept: application/json'",
		`--data-raw '{"q":"x"}'`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PoC missing %q\n---\n%s", want, out)
		}
	}
	for _, secret := range []string{"s3cr3t-token-value", "abc123session", "key-999-secret"} {
		if strings.Contains(out, secret) {
			t.Errorf("PoC leaked the credential %q:\n%s", secret, out)
		}
	}
	// curl sets these itself; reproducing them would change the request.
	for _, unwanted := range []string{"Host:", "Content-Length", "Connection:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("PoC should not emit %q:\n%s", unwanted, out)
		}
	}
}

func TestCurlPoCEmitsLiteralCredentialsOnlyWhenAsked(t *testing.T) {
	out, err := report.CurlPoCFromEvidence([]byte(storedPostRequest), report.CurlOptions{IncludeCredentials: true})
	if err != nil {
		t.Fatalf("CurlPoCFromEvidence: %v", err)
	}
	for _, want := range []string{
		"-H 'Authorization: Bearer s3cr3t-token-value'",
		"-b 'session=abc123session; theme=dark'",
		"-H 'X-Api-Key: key-999-secret'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PoC missing literal %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "$INDAGO_") {
		t.Errorf("IncludeCredentials must not emit placeholders:\n%s", out)
	}
}

func TestCurlPoCEscapesShellQuotes(t *testing.T) {
	req := report.HTTPRequestEvidence{
		Method:  "POST",
		URL:     "https://app.example.test/search?q=it's",
		Headers: []report.HTTPHeader{{Name: "Content-Type", Value: "application/x-www-form-urlencoded"}},
		Body:    "q=it's&x=1",
	}
	out, err := report.CurlPoC(req, report.CurlOptions{})
	if err != nil {
		t.Fatalf("CurlPoC: %v", err)
	}
	if strings.Contains(out, "it's") {
		t.Fatalf("a bare single quote would break the command:\n%s", out)
	}
	if !strings.Contains(out, `it'"'"'s`) {
		t.Fatalf("expected the POSIX quote escape:\n%s", out)
	}
}

func TestCurlPoCEmptyHeaderValueUsesSemicolon(t *testing.T) {
	req := report.HTTPRequestEvidence{
		Method:  "GET",
		URL:     "https://app.example.test/x",
		Headers: []report.HTTPHeader{{Name: "X-Debug", Value: ""}},
	}
	out, err := report.CurlPoC(req, report.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "-H 'X-Debug;'") {
		t.Fatalf("curl needs the semicolon form for an empty header:\n%s", out)
	}
}

func TestCurlPoCOptionsAndNote(t *testing.T) {
	req := report.HTTPRequestEvidence{Method: "GET", URL: "https://lab.example.test:8443/a?b=1"}
	out, err := report.CurlPoC(req, report.CurlOptions{
		Note:            "IDOR: read another account's invoice\nsecond line is flattened",
		MaxTimeSeconds:  5,
		FollowRedirects: true,
		Insecure:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# IDOR: read another account's invoice second line is flattened",
		"curl -sS -i -k -X GET 'https://lab.example.test:8443/a?b=1'",
		"--max-time 5",
		"-L",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("PoC missing %q\n---\n%s", want, out)
		}
	}
	// The note must stay a single comment line: a newline in it would inject a
	// second shell line.
	if strings.Count(out, "\n#") != 0 {
		t.Errorf("note leaked into more than one line:\n%s", out)
	}
}

func TestCurlPoCIsDeterministic(t *testing.T) {
	opts := report.CurlOptions{MaxTimeSeconds: 12}
	first, err := report.CurlPoCFromEvidence([]byte(storedPostRequest), opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := report.CurlPoCFromEvidence([]byte(storedPostRequest), opts)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("iteration %d produced different output:\n%s\n---\n%s", i, first, again)
		}
	}
}

func TestCurlPoCPreservesEvidenceHeaderOrder(t *testing.T) {
	raw := "GET /x HTTP/1.1\nHost: app.example.test\nZeta: 1\nAlpha: 2\n\n"
	out, err := report.CurlPoCFromEvidence([]byte(raw), report.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(out, "-H 'Zeta: 1'") > strings.Index(out, "-H 'Alpha: 2'") {
		t.Fatalf("header order was not preserved:\n%s", out)
	}
	// Bare-LF evidence (a hand-written dump) must parse too.
	if !strings.Contains(out, "'https://app.example.test/x'") {
		t.Fatalf("relative target was not resolved against Host:\n%s", out)
	}
}

func TestParseHTTPRequestEvidenceUsesForwardedScheme(t *testing.T) {
	raw := "GET /account HTTP/1.1\r\nHost: app.example.test\r\nX-Forwarded-Proto: http\r\n\r\n"
	req, err := report.ParseHTTPRequestEvidence([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "http://app.example.test/account" {
		t.Fatalf("URL = %q, want the forwarded http scheme", req.URL)
	}

	httpsReq, err := report.ParseHTTPRequestEvidence([]byte("GET /account HTTP/1.1\r\nHost: app.example.test\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if httpsReq.URL != "https://app.example.test/account" {
		t.Fatalf("URL = %q, want the https default", httpsReq.URL)
	}

	reqHTTP, err := report.ParseHTTPRequestEvidenceWithScheme([]byte(raw), "http")
	if err != nil {
		t.Fatal(err)
	}
	if reqHTTP.URL != "http://app.example.test/account" {
		t.Fatalf("URL = %q", reqHTTP.URL)
	}
}

func TestParseHTTPRequestEvidenceHandlesAbsoluteFormAndFoldedHeaders(t *testing.T) {
	raw := "GET http://plain.example.test:8080/a?b=c HTTP/1.1\r\n" +
		"Host: ignored.example.test\r\n" +
		"X-Long: one\r\n" +
		"  two\r\n" +
		"\r\n"
	req, err := report.ParseHTTPRequestEvidence([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "http://plain.example.test:8080/a?b=c" {
		t.Fatalf("URL = %q, want the absolute-form target", req.URL)
	}
	if got := req.Value("X-Long"); got != "one two" {
		t.Fatalf("folded header = %q, want %q", got, "one two")
	}
}

func TestCurlPoCRejectsUnsafeEvidence(t *testing.T) {
	cases := map[string]report.HTTPRequestEvidence{
		"relative url":    {Method: "GET", URL: "/x"},
		"bad scheme":      {Method: "GET", URL: "file:///etc/passwd"},
		"bad method":      {Method: "GE T", URL: "https://a.example.test/"},
		"header newline":  {Method: "GET", URL: "https://a.example.test/", Headers: []report.HTTPHeader{{Name: "X-A", Value: "a\r\nX-B: b"}}},
		"header bad name": {Method: "GET", URL: "https://a.example.test/", Headers: []report.HTTPHeader{{Name: "X A", Value: "b"}}},
		"binary body":     {Method: "POST", URL: "https://a.example.test/", Body: "a\x00b"},
	}
	for name, req := range cases {
		if out, err := report.CurlPoC(req, report.CurlOptions{}); err == nil {
			t.Errorf("%s: expected an error, got:\n%s", name, out)
		}
	}
	for name, raw := range map[string]string{
		"empty":          "",
		"no host":        "GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n",
		"malformed line": "GET\r\n\r\n",
	} {
		if _, err := report.ParseHTTPRequestEvidence([]byte(raw)); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
}

func TestCurlPoCAddsCustomSensitiveHeaders(t *testing.T) {
	req := report.HTTPRequestEvidence{
		Method:  "GET",
		URL:     "https://api.example.test/me",
		Headers: []report.HTTPHeader{{Name: "X-Tenant-Secret", Value: "tenant-secret-value"}},
	}
	defaultOut, err := report.CurlPoC(req, report.CurlOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(defaultOut, "tenant-secret-value") {
		t.Fatalf("an unknown header should be rendered literally by default:\n%s", defaultOut)
	}
	custom, err := report.CurlPoC(req, report.CurlOptions{SensitiveHeaders: []string{"x-tenant-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(custom, "tenant-secret-value") {
		t.Fatalf("a header named in SensitiveHeaders leaked:\n%s", custom)
	}
	if !strings.Contains(custom, `-H "X-Tenant-Secret: $INDAGO_TOKEN"`) {
		t.Fatalf("sensitive header was not parameterized:\n%s", custom)
	}
}

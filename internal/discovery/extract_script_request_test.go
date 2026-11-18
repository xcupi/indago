package discovery_test

import (
	"testing"

	"github.com/indago/indago/internal/discovery"
	"github.com/indago/indago/internal/domain"
)

// A page that binds its XML POST to a click must still contribute the endpoint
// and the body: a crawl never clicks, so only the declaration is observable.
func TestExtractScriptRequestsXHR(t *testing.T) {
	html := `<html><body>
<p>Reset your secret.</p>
<script type="text/javascript">
function ResetSecret()
{
    var xmlHttp;
    if(window.XMLHttpRequest)
    {
        xmlHttp = new XMLHttpRequest();
    }
    xmlHttp.open("POST","xxe-2.php",true);
    xmlHttp.setRequestHeader("Content-type","text/xml; charset=UTF-8");
    xmlHttp.send("<reset><login>bee</login><secret>Any bugs?</secret></reset>");
}
</script>
</body></html>`

	got := discovery.ExtractScriptRequests(html)
	if len(got) != 1 {
		t.Fatalf("requests = %+v, want 1", got)
	}
	req := got[0]
	if req.URL != "xxe-2.php" {
		t.Errorf("URL = %q, want xxe-2.php", req.URL)
	}
	if req.Method != domain.MethodPOST {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.ContentType != "text/xml; charset=UTF-8" {
		t.Errorf("ContentType = %q", req.ContentType)
	}
	if req.Body != "<reset><login>bee</login><secret>Any bugs?</secret></reset>" {
		t.Errorf("Body = %q", req.Body)
	}
}

func TestExtractScriptRequestsFetch(t *testing.T) {
	html := `<script>
fetch("/api/report", {
  method: "POST",
  headers: {"Content-Type": "application/soap+xml", "X-Trace": "1"},
  body: "<envelope><id>7</id></envelope>"
});
fetch('/api/ping');
</script>`

	got := discovery.ExtractScriptRequests(html)
	if len(got) != 2 {
		t.Fatalf("requests = %+v, want 2", got)
	}
	post := got[0]
	if post.URL != "/api/report" || post.Method != domain.MethodPOST {
		t.Fatalf("first request = %+v", post)
	}
	if post.ContentType != "application/soap+xml" {
		t.Errorf("ContentType = %q", post.ContentType)
	}
	if post.Body != "<envelope><id>7</id></envelope>" {
		t.Errorf("Body = %q", post.Body)
	}
	// A fetch without an options object is a plain GET, and a GET never
	// carries a body even if one was declared.
	ping := got[1]
	if ping.URL != "/api/ping" || ping.Method != domain.MethodGET {
		t.Fatalf("second request = %+v", ping)
	}
	if ping.Body != "" || ping.ContentType != "" {
		t.Errorf("GET kept a body/content type: %+v", ping)
	}
}

// An SPA ships its API calls in an external bundle, not in an inline <script>
// tag: the raw JavaScript must parse exactly like a document's script body.
func TestExtractScriptRequestsFromJSRawBundle(t *testing.T) {
	js := `!function(){var x=new XMLHttpRequest();x.open("POST","/workshop/api/report");` +
		`x.setRequestHeader("Content-Type","application/json");x.send("a=1");}();` +
		`var login=function(){return fetch("api/v2/user/login",{` +
		`method:"PUT",headers:{"Content-Type":"application/json"},body:"{}"})};` +
		`fetch("/community/api/v2/community/posts");`

	got := discovery.ExtractScriptRequestsFromJS(js)
	if len(got) != 3 {
		t.Fatalf("requests = %+v, want 3", got)
	}
	if got[0].URL != "/workshop/api/report" || got[0].Method != domain.MethodPOST ||
		got[0].ContentType != "application/json" || got[0].Body != "a=1" {
		t.Fatalf("XHR shape = %+v", got[0])
	}
	if got[1].URL != "api/v2/user/login" || got[1].Method != domain.MethodPUT || got[1].Body != "{}" {
		t.Fatalf("relative fetch shape = %+v", got[1])
	}
	if got[2].URL != "/community/api/v2/community/posts" || got[2].Method != domain.MethodGET {
		t.Fatalf("fetch GET shape = %+v", got[2])
	}
}

// The raw-JS entry point must not require (or invent) <script> wrappers, and it
// must be bounded and deduplicated exactly like the document extractor.
func TestExtractScriptRequestsFromJSBoundsAndDedupes(t *testing.T) {
	js := `fetch("/api/x");fetch('/api/x');` +
		`var a=new XMLHttpRequest();a.open("POST","/api/x");a.send("<x/>");`
	got := discovery.ExtractScriptRequestsFromJS(js)
	if len(got) != 2 { // GET /api/x and POST /api/x are distinct shapes
		t.Fatalf("requests = %+v, want 2", got)
	}
	if got := discovery.ExtractScriptRequestsFromJS(""); got != nil {
		t.Fatalf("empty input = %+v, want nil", got)
	}
}

func TestExtractScriptRequestsSkipsComputedShapes(t *testing.T) {
	// A URL held in a variable, a template-literal URL and an absolute
	// third-party URL are not literal same-origin shapes this extractor can
	// replay; they are skipped rather than guessed at.
	html := "<script>\n" +
		"function go(u) {\n" +
		"  var x = new XMLHttpRequest();\n" +
		"  x.open('POST', u);\n" +
		"  x.send('a=1');\n" +
		"}\n" +
		"fetch(`/templated`);\n" +
		"</script>"

	if got := discovery.ExtractScriptRequests(html); len(got) != 0 {
		t.Fatalf("requests = %+v, want none", got)
	}
}

func TestExtractScriptRequestsBoundsAndDedupes(t *testing.T) {
	dup := "<script>" +
		"var a = new XMLHttpRequest(); a.open('POST','/api/x'); a.send('<x/>');" +
		"var b = new XMLHttpRequest(); b.open('POST','/api/x'); b.send('<x/>');" +
		"</script>"
	got := discovery.ExtractScriptRequests(dup)
	if len(got) != 1 {
		t.Fatalf("duplicate declaration not collapsed: %+v", got)
	}
}

// An escaped literal is not the string the page sends, so the body is dropped
// rather than replayed as a guessed value. The endpoint itself is still useful.
func TestExtractScriptRequestsDropsEscapedBody(t *testing.T) {
	html := "<script>var x=new XMLHttpRequest();x.open(\"POST\",\"/api/x\");x.send(\"{\\\"a\\\":1}\");</script>"
	got := discovery.ExtractScriptRequests(html)
	if len(got) != 1 {
		t.Fatalf("requests = %+v, want 1", got)
	}
	if got[0].URL != "/api/x" || got[0].Method != domain.MethodPOST {
		t.Fatalf("request = %+v", got[0])
	}
	if got[0].Body != "" {
		t.Fatalf("escaped body kept: %q", got[0].Body)
	}
}

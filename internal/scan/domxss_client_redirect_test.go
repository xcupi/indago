package scan

import (
	"strings"
	"testing"
)

func TestClientRedirectAndCookiePatterns(t *testing.T) {
	redirect := `<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back</a>`
	if !domXSSHasRedirectLink(redirect) {
		t.Fatal("redirect link not detected")
	}
	if domXSSHasRedirectLink(`<a href="/">home</a>`) {
		t.Fatal("ordinary link detected as a redirect")
	}
	cookie := `<script>document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure'</script>`
	if !domXSSCookieWritePattern(cookie) {
		t.Fatal("cookie write not detected")
	}
}

func TestClobberingPayloadPerSanitizer(t *testing.T) {
	domPurify := `<script src='/resources/js/domPurify-2.0.15.js'></script><script>loadComments('/post/comment')</script>`
	if !domXSSClobberingCommentForm(domPurify) {
		t.Fatal("DOMPurify comment page not detected")
	}
	payload, fragment := domXSSClobberingPayload(domPurify, "clbTEST")
	if fragment != "" || !strings.Contains(payload, `id=defaultAvatar`) || !strings.Contains(payload, "onerror=clbTEST") {
		t.Fatalf("dompurify payload = %q fragment %q", payload, fragment)
	}
	janitor := `<script src='/resources/js/htmlJanitor.js'></script><script>loadComments('/post/comment')</script>`
	payload, fragment = domXSSClobberingPayload(janitor, "clbTEST")
	if fragment != "#xclbTEST" || !strings.Contains(payload, "onfocus=clbTEST") || !strings.Contains(payload, "id=attributes") {
		t.Fatalf("janitor payload = %q fragment %q", payload, fragment)
	}
}

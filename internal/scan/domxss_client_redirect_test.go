package scan

import "testing"

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

package scopeproxy

// Control for the resolver hardening: the same browser, with only the
// --host-resolver-rules switch (no proxy), must fail to resolve a NAME while
// still loading an address literal. Without this, "Chromium cannot resolve
// names" would be an assumption behind the DNS claim in
// TestChromiumProxyCarriesNamesWithoutBrowserDNS.

import (
	"strings"
	"testing"

	pw "github.com/mxschmitt/playwright-go"
)

func TestChromiumHostResolverRulesBlockBrowserDNS(t *testing.T) {
	out := newConnCounter(t)
	_, outPort := out.hostPort(t)
	in := newOriginWithBody(t, "<!doctype html><title>literal-ok</title>")

	b := launchChromium(t, []string{"--host-resolver-rules=" + chromiumResolverRules})
	ctx, err := b.NewContext()
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer ctx.Close()
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	timeout := pw.Float(8000)

	// An address literal still works: the rules remove DNS, not navigation.
	if _, err := page.Goto(in.srv.URL+"/", pw.PageGotoOptions{WaitUntil: pw.WaitUntilStateLoad, Timeout: timeout}); err != nil {
		t.Fatalf("goto to an address literal: %v", err)
	}
	if title, _ := page.Title(); title != "literal-ok" {
		t.Fatalf("literal page title = %q, want literal-ok", title)
	}

	// A name cannot be resolved, so nothing is connected to the listener behind
	// it. This navigation is last: a failed navigation leaves an error page that
	// would race a further one.
	_, err = page.Goto("http://out-of-scope.test:"+itoa(outPort)+"/", pw.PageGotoOptions{WaitUntil: pw.WaitUntilStateLoad, Timeout: timeout})
	if err == nil || !strings.Contains(err.Error(), "ERR_NAME_NOT_RESOLVED") {
		t.Fatalf("goto to an unresolvable name = %v, want ERR_NAME_NOT_RESOLVED", err)
	}
	if n := out.count.Load(); n != 0 {
		t.Fatalf("the browser reached the listener for an unresolvable name (%d connections)", n)
	}
}

func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if i == len(b) {
		return "0"
	}
	return string(b[i:])
}

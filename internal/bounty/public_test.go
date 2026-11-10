package bounty

import "testing"

func TestExtractPublicHuntingUserAgentCyberGhost(t *testing.T) {
	page := []byte(`<div><h3>User agent</h3><p> Please append to your user-agent header the following value: ' <strong>-BugBounty-CyberGhost--31337</strong> '. </p></div>`)
	got, replace := extractPublicHuntingUserAgent(page)
	if got != "-BugBounty-CyberGhost--31337" || replace {
		t.Fatalf("got %q replace=%v", got, replace)
	}
}

func TestExtractPublicHuntingUserAgentReplacement(t *testing.T) {
	page := []byte(`<div><h3>User agent</h3><p>Your User-Agent must be set to <code>Infomaniak-YWH-Bugbounty</code> for all requests.</p></div>`)
	got, replace := extractPublicHuntingUserAgent(page)
	if got != "Infomaniak-YWH-Bugbounty" || !replace {
		t.Fatalf("got %q replace=%v, want Infomaniak-YWH-Bugbounty replace=true", got, replace)
	}
}

func TestExtractPublicHuntingUserAgentIgnoresGenericPolicy(t *testing.T) {
	page := []byte(`<p>Make sure to apply hunting requirements policy (User-Agent, VPN, etc.)</p>`)
	got, replace := extractPublicHuntingUserAgent(page)
	if got != "" || replace {
		t.Fatalf("generic policy produced %q replace=%v", got, replace)
	}
}

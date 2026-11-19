package report

// The two class tables must agree. cvss.go owns the CWE/CVSS baseline a
// finding is scored with; templates.go owns the human context (name, impact,
// remediation) a deliverable renders. A class present in one but not the
// other used to fall back to "CWE: n/a" and a generic remediation, which is
// exactly the material a triager needs. This test makes the coverage and the
// CWE agreement explicit for every class either table knows.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestClassIntelCoversEveryClassifiedClass(t *testing.T) {
	for _, class := range Classes() {
		classification, ok := Classify(class)
		if !ok {
			t.Fatalf("Classes() returned %q but Classify() does not know it", class)
		}
		in := intelFor(class)
		if in.CWE == "n/a" || in.CWE == "" {
			t.Fatalf("%s: intelFor() used the generic fallback (CWE %q)", class, in.CWE)
		}
		if in.CWE != fmt.Sprintf("CWE-%d", classification.CWE.ID) {
			t.Fatalf("%s: intel CWE %q != classification CWE %q", class, in.CWE, classification.CWE.String())
		}
		if in.Name == "" || in.Impact == "" || in.Remediation == "" {
			t.Fatalf("%s: incomplete class intel: %+v", class, in)
		}
		if len(in.References) == 0 {
			t.Fatalf("%s: class intel has no references", class)
		}
	}
}

// Domain classes that are not in the classification table cannot be scored;
// every class domain.AllVulnClasses() defines must be in it, so this test
// fails when a new engine adds a VulnClass without its report baseline.
func TestClassTablesCoverEveryDomainClass(t *testing.T) {
	domainClasses := domain.AllVulnClasses()
	if len(domainClasses) != len(Classes()) {
		t.Fatalf("domain has %d classes, classification table has %d", len(domainClasses), len(Classes()))
	}
	for _, class := range domainClasses {
		if !class.IsValid() {
			t.Errorf("%s: AllVulnClasses returned an invalid class", class)
		}
		if _, ok := Classify(class); !ok {
			t.Errorf("%s: no classification baseline", class)
		}
		in := intelFor(class)
		if in.CWE == "n/a" {
			t.Errorf("%s: no class intel (renders CWE n/a)", class)
		}
	}
}

// The YesWeHack markdown template has its own wording fallbacks; for a known
// class none of them may emit the generic text or the raw class token.
func TestYesWeHackWordingCoversEveryClassifiedClass(t *testing.T) {
	for _, class := range Classes() {
		if got := ywhBugType(class); got == string(class) || strings.TrimSpace(got) == "" {
			t.Errorf("%s: ywhBugType fell back to %q", class, got)
		}
		if got := ywhRemediation(class); strings.Contains(got, "Apply the remediation appropriate") || got == "" {
			t.Errorf("%s: ywhRemediation fell back to the generic text", class)
		}
		if got := riskSentence(class); strings.Contains(got, "The impact follows from the vulnerability class") || got == "" {
			t.Errorf("%s: riskSentence fell back to the generic text", class)
		}
	}
}

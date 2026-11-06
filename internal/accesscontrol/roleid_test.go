package accesscontrol

import "testing"

func TestRoleIDCandidate(t *testing.T) {
	fields := CandidateFields(nil, RoleFieldNames([]byte(`{"roleid":1}`)))
	if len(fields) == 0 || fields[0].Name != "roleid" || fields[0].Kind != ValueNumber || fields[0].Value != "2" {
		t.Fatalf("observed roleid must be a numeric role candidate: %+v", fields)
	}
}

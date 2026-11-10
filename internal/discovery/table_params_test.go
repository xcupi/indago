package discovery

import "testing"

func TestIsTableControlParam(t *testing.T) {
	for _, name := range []string{"draw", "start", "length", "search[value]", "search[regex]", "columns[0][data]", "columns[9][search][value]", "order[0][column]"} {
		if !isTableControlParam(name) {
			t.Fatalf("%q should be a DataTables control parameter", name)
		}
	}
	for _, name := range []string{"q", "email", "columns", "order", "search"} {
		if isTableControlParam(name) {
			t.Fatalf("%q should remain testable", name)
		}
	}
}

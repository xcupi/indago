package detection_test

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// importsOf returns the import paths of a file in the detection package.
func importsOf(t *testing.T, file string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

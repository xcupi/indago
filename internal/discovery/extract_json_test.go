package discovery_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/indago/indago/internal/discovery"
)

func TestExtractJSONBodyParamsPreservesTopLevelRawValues(t *testing.T) {
	body := `{"query":"hello","page":2,"options":{"sort":"newest"},"enabled":true}`
	got := discovery.ExtractJSONBodyParams(body)
	want := []discovery.JSONBodyParam{
		{Name: "enabled", RawValue: `true`},
		{Name: "options", RawValue: `{"sort":"newest"}`},
		{Name: "page", RawValue: `2`},
		{Name: "query", RawValue: `"hello"`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JSON body params = %#v, want %#v", got, want)
	}
}

func TestExtractJSONBodyParamsRejectsUnsupportedOrUnboundedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"array root":     `[{"q":"x"}]`,
		"scalar root":    `"x"`,
		"malformed":      `{"q":`,
		"trailing value": `{"q":"x"} {"r":"y"}`,
		"empty key":      `{"":"x"}`,
		"duplicate key":  `{"q":"first","q":"second"}`,
		"too many keys":  tooManyJSONFields(65),
		"too large":      `{"q":"` + strings.Repeat("x", 64*1024) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := discovery.ExtractJSONBodyParams(body); len(got) != 0 {
				t.Fatalf("unsupported/unbounded body produced params: %#v", got)
			}
		})
	}
}

func tooManyJSONFields(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"k%d":"v"`, i)
	}
	b.WriteByte('}')
	return b.String()
}

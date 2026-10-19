package browser

import "testing"

func TestCDPRedirectTargetRejectsBackslashLocation(t *testing.T) {
	params := map[string]interface{}{
		"responseStatusCode": float64(302),
		"responseHeaders": []interface{}{
			map[string]interface{}{"name": "Location", "value": `\outside`},
		},
		"request": map[string]interface{}{"url": "http://127.0.0.1:8122/api/start"},
	}
	target, redirect, invalid := cdpRedirectTarget(params)
	if !redirect || !invalid {
		t.Fatalf("backslash redirect parsed as target=%q redirect=%v invalid=%v; ambiguous browser URL forms must fail closed", target, redirect, invalid)
	}
}

package scan

import (
	"context"
	"strings"
	"testing"
)

func TestUpsertBlockFindingDescribesSeparatelyGatedFallback(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", "GET")
	param := env.param(ep, "q", "query", "hello")
	ip := env.injection(ep, param)

	finding, err := upsertBlockFinding(context.Background(), env.st, env.scanID, ep, ip.ID, param, 200, 403, "test-case")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finding.Summary, "separately evidence-gated") {
		t.Fatalf("block summary hides the automatic fallback policy: %q", finding.Summary)
	}
	if strings.Contains(finding.Summary, "does not retry or evade") {
		t.Fatalf("block summary contradicts the automatic fallback policy: %q", finding.Summary)
	}
	if decodeFindingDetail(finding.Detail).Throttled {
		t.Fatal("a 403 filter rejection must not be recorded as backpressure")
	}
}

// A 429/503 answer is the target asking for less traffic or being down, not a
// filter judging the payload: the diagnostic has to say the bounded bypass pass
// stays away, and the recorded row has to carry that so the scan controller can
// suppress escalation for the point.
func TestUpsertBlockFindingMarksBackpressureAndSaysSo(t *testing.T) {
	env := newScanEnv(t)
	ep := env.endpoint("https://target.example/search?q=hello", "GET")
	param := env.param(ep, "q", "query", "hello")
	ip := env.injection(ep, param)

	finding, err := upsertBlockFinding(context.Background(), env.st, env.scanID, ep, ip.ID, param, 200, 429, "test-case")
	if err != nil {
		t.Fatal(err)
	}
	if !decodeFindingDetail(finding.Detail).Throttled {
		t.Fatalf("429 must be recorded as backpressure, detail=%s", finding.Detail)
	}
	if !strings.Contains(finding.Summary, "backpressure") || !strings.Contains(finding.Summary, "not escalated") {
		t.Fatalf("block summary must say a throttled point is not escalated: %q", finding.Summary)
	}
}

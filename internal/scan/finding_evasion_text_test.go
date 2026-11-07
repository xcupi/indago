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
}

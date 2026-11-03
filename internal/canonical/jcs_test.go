package canonical

import (
	"testing"
)

func TestCanonicalizeKeyOrder(t *testing.T) {
	fields := map[string]string{
		"time":      "2026-10-31T14:22:07Z",
		"operation": "RunInstances",
		"actor":     "arn:aws:iam::123456789012:role/deploy-agent",
		"status":    "Success",
		"region":    "us-east-1",
		"resource":  "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
	}

	got := Canonicalize(fields)
	// Keys must be sorted alphabetically: actor, operation, region, resource, status, time
	want := `{"actor":"arn:aws:iam::123456789012:role/deploy-agent","operation":"RunInstances","region":"us-east-1","resource":"arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123","status":"Success","time":"2026-10-31T14:22:07Z"}`

	if got != want {
		t.Errorf("Canonicalize() =\n  %s\nwant:\n  %s", got, want)
	}
}

func TestCanonicalizeEmptyResource(t *testing.T) {
	fields := FieldsFromEvent("DescribeInstances", "arn:aws:iam::123:user/alice", "", "2026-10-31T14:22:07Z", "Success", "us-west-2")

	got := Canonicalize(fields)
	want := `{"actor":"arn:aws:iam::123:user/alice","operation":"DescribeInstances","region":"us-west-2","resource":"","status":"Success","time":"2026-10-31T14:22:07Z"}`

	if got != want {
		t.Errorf("Canonicalize() =\n  %s\nwant:\n  %s", got, want)
	}
}

func TestCanonicalizeNoHTMLEscaping(t *testing.T) {
	// Ensure <, >, & are NOT escaped (matching JS JSON.stringify behavior)
	fields := map[string]string{
		"actor":     "role/<admin>&test",
		"operation": "CreateBucket",
		"region":    "us-east-1",
		"resource":  "arn:aws:s3:::my-bucket",
		"status":    "Success",
		"time":      "2026-10-31T00:00:00Z",
	}

	got := Canonicalize(fields)
	// Should contain literal <, >, & not \u003c etc.
	if contains(got, `\u003c`) || contains(got, `\u003e`) || contains(got, `\u0026`) {
		t.Errorf("Canonicalize() escaped HTML chars: %s", got)
	}
	if !contains(got, `<admin>&test`) {
		t.Errorf("Canonicalize() should preserve literal <, >, &: %s", got)
	}
}

func TestHashDeterministic(t *testing.T) {
	fields := FieldsFromEvent("RunInstances", "arn:aws:iam::123456789012:role/deploy-agent", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123", "2026-10-31T14:22:07Z", "Success", "us-east-1")

	h1 := Hash(fields)
	h2 := Hash(fields)

	if h1 != h2 {
		t.Errorf("Hash() not deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("Hash() should be 64 hex chars, got %d", len(h1))
	}
}

func TestHashTruncated(t *testing.T) {
	fields := FieldsFromEvent("RunInstances", "arn:aws:iam::123:role/agent", "i-abc", "2026-10-31T00:00:00Z", "Success", "us-east-1")

	full := Hash(fields)
	trunc := HashTruncated(fields, 16)

	if trunc != full[:16] {
		t.Errorf("HashTruncated(16) = %s, want prefix of %s", trunc, full)
	}
}

func TestVerifyMatch(t *testing.T) {
	fields := FieldsFromEvent("RunInstances", "arn:aws:iam::123:role/agent", "i-abc", "2026-10-31T00:00:00Z", "Success", "us-east-1")
	expected := Hash(fields)

	if err := Verify(fields, expected); err != nil {
		t.Errorf("Verify() should pass: %v", err)
	}
}

func TestVerifyMismatch(t *testing.T) {
	fields := FieldsFromEvent("RunInstances", "arn:aws:iam::123:role/agent", "i-abc", "2026-10-31T00:00:00Z", "Success", "us-east-1")

	if err := Verify(fields, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Error("Verify() should fail on mismatched hash")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

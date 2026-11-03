package summary

import (
	"testing"

	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
)

func event() extract.CanonicalEvent {
	return extract.CanonicalEvent{
		Operation: "RunInstances",
		Actor:     "arn:aws:iam::123456789012:role/deploy-agent",
		Resource:  "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
		Time:      "2026-10-31T14:22:07Z",
		Status:    "Success",
		Region:    "us-east-1",
	}
}

func TestGenerateL0(t *testing.T) {
	got := Generate(event(), 0)
	want := "At 2026-10-31T14:22:07Z, arn:aws:iam::123456789012:role/deploy-agent called RunInstances on arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123 in us-east-1 [Success]"
	if got != want {
		t.Errorf("L0:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestGenerateL1(t *testing.T) {
	// L1 produces same summary as L0 (actor hashing is server-side)
	got := Generate(event(), 1)
	if got != Generate(event(), 0) {
		t.Error("L1 should produce same summary as L0")
	}
}

func TestGenerateL2(t *testing.T) {
	got := Generate(event(), 2)
	want := "RunInstances in us-east-1 [Success]"
	if got != want {
		t.Errorf("L2:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestGenerateL3(t *testing.T) {
	got := Generate(event(), 3)
	if got != "" {
		t.Errorf("L3 should be empty, got %q", got)
	}
}

func TestGenerateEmptyResource(t *testing.T) {
	e := event()
	e.Resource = ""
	got := Generate(e, 0)
	if got == "" {
		t.Error("should produce summary even with empty resource")
	}
	// Should contain "(none)" placeholder
	if !containsStr(got, "(none)") {
		t.Errorf("empty resource should show (none), got: %s", got)
	}
}

func TestHashActor(t *testing.T) {
	h := HashActor("arn:aws:iam::123456789012:role/deploy-agent")
	if len(h) != 16 {
		t.Errorf("HashActor should be 16 chars, got %d", len(h))
	}
	// Deterministic
	if h != HashActor("arn:aws:iam::123456789012:role/deploy-agent") {
		t.Error("HashActor not deterministic")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

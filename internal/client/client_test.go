package client

import (
	"math"
	"testing"
)

func TestFormatFactor(t *testing.T) {
	tests := []struct {
		v    float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{100, "100"},
		{5000, "5000"},
		{4294967295, "4294967295"}, // max uint32 -- MUST NOT use scientific notation
		{0.001, "0.001"},
	}
	for _, tt := range tests {
		got := formatFactor(tt.v)
		if got != tt.want {
			t.Errorf("formatFactor(%v) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestMintFingerprint(t *testing.T) {
	// Cross-language parity vector from test-vectors.json
	fp := mintFingerprint("ENCLAVE_PROD", "AI-INF.1", 1, 1, 0, 1774800000000)
	if fp != "2e16e2fe92dd" {
		t.Errorf("mintFingerprint parity failure: got %s, want 2e16e2fe92dd", fp)
	}
}

func TestMintFingerprintLength(t *testing.T) {
	fp := mintFingerprint("tenant", "INF-OCSF.1", 123456, 1, 0, 1730380800000)
	if len(fp) != 12 {
		t.Errorf("fingerprint should be 12 chars, got %d", len(fp))
	}
}

func TestComputeFactors(t *testing.T) {
	// Known canonical hash: first 8 hex = "a1b2c3d4"
	// 0xa1b2c3d4 = 2712847316
	fa, fb, fc := ComputeFactors("a1b2c3d4e5f60000000000000000000000000000000000000000000000000000", 1, "Success")
	if fa != 2712847316 {
		t.Errorf("factor_a = %v, want 2712847316", fa)
	}
	if fb != 1 {
		t.Errorf("factor_b = %v, want 1", fb)
	}
	if fc != 0 {
		t.Errorf("factor_c = %v, want 0 (success)", fc)
	}
}

func TestComputeFactorsError(t *testing.T) {
	_, _, fc := ComputeFactors("a1b2c3d400000000000000000000000000000000000000000000000000000000", 4, "AccessDenied")
	if fc != 1 {
		t.Errorf("factor_c = %v, want 1 (error)", fc)
	}
}

func TestComputeFactorsMaxUint32(t *testing.T) {
	// "ffffffff" = 4294967295
	fa, _, _ := ComputeFactors("ffffffff00000000000000000000000000000000000000000000000000000000", 1, "Success")
	if fa != 4294967295 {
		t.Errorf("factor_a = %v, want 4294967295", fa)
	}
	// Must be within safe integer range
	if fa > math.Pow(2, 53) {
		t.Errorf("factor_a exceeds 2^53 safe range")
	}
}

func TestSignPayload(t *testing.T) {
	sig := signPayload("test-key", "abc123def456", "agent-1")
	if len(sig) != 64 {
		t.Errorf("signature should be 64 hex chars, got %d", len(sig))
	}
	// Deterministic
	if sig != signPayload("test-key", "abc123def456", "agent-1") {
		t.Error("signPayload not deterministic")
	}
	// Different with different agent
	if sig == signPayload("test-key", "abc123def456", "agent-2") {
		t.Error("signPayload should differ for different agents")
	}
}

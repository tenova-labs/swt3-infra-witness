package extract

import (
	"testing"
)

func TestParseSWT3Telemetry_Single(t *testing.T) {
	data := []byte(`{"model":"gpt-4","tokens_in":500,"tokens_out":200,"latency_ms":1200,"status":"ok","timestamp":"2026-11-14T12:00:00Z","request_id":"req-1"}`)
	events, err := ParseSWT3Telemetry(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Operation != "ai.inference:gpt-4" {
		t.Errorf("operation = %q, want ai.inference:gpt-4", e.Operation)
	}
	if e.Resource != "gpt-4" {
		t.Errorf("resource = %q, want gpt-4", e.Resource)
	}
	if e.Status != "Success" {
		t.Errorf("status = %q, want Success", e.Status)
	}
	if e.Time != "2026-11-14T12:00:00Z" {
		t.Errorf("time = %q, want 2026-11-14T12:00:00Z", e.Time)
	}
	if e.EventID != "req-1" {
		t.Errorf("eventID = %q, want req-1", e.EventID)
	}
}

func TestParseSWT3Telemetry_Array(t *testing.T) {
	data := []byte(`[
		{"model":"gpt-4","tokens_in":100,"tokens_out":50,"latency_ms":500,"status":"ok","timestamp":"2026-11-14T12:00:00Z"},
		{"model":"claude-sonnet-4-20250514","tokens_in":200,"tokens_out":100,"latency_ms":800,"status":"ok","timestamp":"2026-11-14T12:01:00Z"}
	]`)
	events, err := ParseSWT3Telemetry(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Resource != "gpt-4" {
		t.Errorf("events[0].resource = %q, want gpt-4", events[0].Resource)
	}
	if events[1].Resource != "claude-sonnet-4-20250514" {
		t.Errorf("events[1].resource = %q, want claude-sonnet-4-20250514", events[1].Resource)
	}
}

func TestParseSWT3Telemetry_ErrorStatus(t *testing.T) {
	data := []byte(`{"model":"gpt-4","tokens_in":0,"tokens_out":0,"latency_ms":100,"status":"rate_limited","timestamp":"2026-11-14T12:00:00Z"}`)
	events, err := ParseSWT3Telemetry(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].Status != "rate_limited" {
		t.Errorf("status = %q, want rate_limited", events[0].Status)
	}
}

func TestParseSWT3Telemetry_NoModel(t *testing.T) {
	data := []byte(`{"tokens_in":100,"tokens_out":50}`)
	_, err := ParseSWT3Telemetry(data)
	if err == nil {
		t.Fatal("expected error for record without model")
	}
}

func TestParseSWT3Telemetry_WithAgentID(t *testing.T) {
	data := []byte(`{"model":"gpt-4","tokens_in":100,"tokens_out":50,"latency_ms":500,"status":"ok","agent_id":"svc-payments"}`)
	events, err := ParseSWT3Telemetry(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].Actor != "svc-payments" {
		t.Errorf("actor = %q, want svc-payments", events[0].Actor)
	}
}

func TestParseOTelSpans_FlatArray(t *testing.T) {
	data := []byte(`[{
		"traceId": "abc123",
		"spanId": "span456",
		"name": "chat",
		"startTimeUnixNano": 1731585600000000000,
		"endTimeUnixNano":   1731585601200000000,
		"attributes": [
			{"key": "gen_ai.system", "value": {"stringValue": "openai"}},
			{"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4"}},
			{"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": 500}},
			{"key": "gen_ai.usage.completion_tokens", "value": {"intValue": 200}}
		]
	}]`)
	events, err := ParseOTelSpans(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Operation != "ai.inference:openai/gpt-4" {
		t.Errorf("operation = %q, want ai.inference:openai/gpt-4", e.Operation)
	}
	if e.Resource != "gpt-4" {
		t.Errorf("resource = %q, want gpt-4", e.Resource)
	}
	if e.Actor != "openai" {
		t.Errorf("actor = %q, want openai", e.Actor)
	}
	if e.EventID != "span456" {
		t.Errorf("eventID = %q, want span456", e.EventID)
	}
}

func TestParseOTelSpans_OTLPEnvelope(t *testing.T) {
	data := []byte(`{
		"resourceSpans": [{
			"scopeSpans": [{
				"spans": [{
					"traceId": "abc",
					"spanId": "def",
					"name": "chat",
					"startTimeUnixNano": 1731585600000000000,
					"attributes": [
						{"key": "gen_ai.request.model", "value": {"stringValue": "claude-sonnet-4-20250514"}},
						{"key": "gen_ai.system", "value": {"stringValue": "anthropic"}}
					]
				}]
			}]
		}]
	}`)
	events, err := ParseOTelSpans(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Operation != "ai.inference:anthropic/claude-sonnet-4-20250514" {
		t.Errorf("operation = %q", events[0].Operation)
	}
}

func TestParseOTelSpans_ErrorSpan(t *testing.T) {
	data := []byte(`[{
		"traceId": "abc",
		"spanId": "def",
		"name": "chat",
		"startTimeUnixNano": 1731585600000000000,
		"attributes": [
			{"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4"}},
			{"key": "otel.status_code", "value": {"stringValue": "ERROR"}},
			{"key": "otel.status_description", "value": {"stringValue": "rate_limit_exceeded"}}
		]
	}]`)
	events, err := ParseOTelSpans(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if events[0].Status != "rate_limit_exceeded" {
		t.Errorf("status = %q, want rate_limit_exceeded", events[0].Status)
	}
}

func TestParseOTelSpans_NoAISpan(t *testing.T) {
	data := []byte(`[{
		"traceId": "abc",
		"spanId": "def",
		"name": "http.request",
		"attributes": [
			{"key": "http.method", "value": {"stringValue": "GET"}}
		]
	}]`)
	_, err := ParseOTelSpans(data)
	if err == nil {
		t.Fatal("expected error for span without gen_ai attributes")
	}
}

func TestIsSWT3Telemetry(t *testing.T) {
	if !IsSWT3Telemetry([]byte(`{"model":"gpt-4","tokens_in":100}`)) {
		t.Error("should detect SWT3 telemetry")
	}
	if IsSWT3Telemetry([]byte(`{"traceId":"abc","spanId":"def"}`)) {
		t.Error("should not detect OTel as SWT3")
	}
}

func TestIsOTelSpan(t *testing.T) {
	if !IsOTelSpan([]byte(`{"traceId":"abc","spanId":"def"}`)) {
		t.Error("should detect OTel span")
	}
	if !IsOTelSpan([]byte(`{"resourceSpans":[{...}]}`)) {
		t.Error("should detect OTLP envelope")
	}
	if IsOTelSpan([]byte(`{"model":"gpt-4","tokens_in":100}`)) {
		t.Error("should not detect SWT3 as OTel")
	}
}

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ok", "Success"},
		{"success", "Success"},
		{"200", "Success"},
		{"", "Success"},
		{"rate_limited", "rate_limited"},
		{"ERROR", "ERROR"},
	}
	for _, tt := range tests {
		got := normalizeStatus(tt.in)
		if got != tt.want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

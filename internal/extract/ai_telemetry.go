// Package extract: AI telemetry parsers for tail mode.
// Accepts two input schemas:
//   1. SWT3 simple JSON (model, tokens, latency, status)
//   2. OTel span JSON with gen_ai.* semantic convention attributes
//
// Both map into CanonicalEvent for the standard witness pipeline.
// Raw prompts/completions are NEVER extracted (RT-1).
package extract

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SWT3Telemetry is the simple JSON schema apps write to the shared volume.
//
//	{"model":"gpt-4","tokens_in":500,"tokens_out":200,"latency_ms":1200,"status":"ok","timestamp":"2026-11-14T12:00:00Z"}
type SWT3Telemetry struct {
	Model     string `json:"model"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	LatencyMs int    `json:"latency_ms"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	AgentID   string `json:"agent_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// OTelSpan is the minimal subset of an OTel span we need.
type OTelSpan struct {
	TraceID    string                 `json:"traceId"`
	SpanID     string                 `json:"spanId"`
	Name       string                 `json:"name"`
	StartTime  int64                  `json:"startTimeUnixNano"`
	EndTime    int64                  `json:"endTimeUnixNano"`
	Attributes []OTelAttribute        `json:"attributes"`
	AttrMap    map[string]interface{} `json:"-"` // flattened for convenience
}

// OTelAttribute is a key-value pair in OTel span format.
type OTelAttribute struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// ParseSWT3Telemetry parses one or more SWT3 simple telemetry records.
// Accepts a single JSON object or a JSON array.
func ParseSWT3Telemetry(data []byte) ([]CanonicalEvent, error) {
	data = trimBOM(data)

	// Try array first
	var records []SWT3Telemetry
	if err := json.Unmarshal(data, &records); err != nil {
		// Try single object
		var single SWT3Telemetry
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, fmt.Errorf("swt3 telemetry: not a valid JSON object or array: %w", err2)
		}
		records = []SWT3Telemetry{single}
	}

	var events []CanonicalEvent
	for _, r := range records {
		if r.Model == "" {
			continue // skip records without a model
		}
		e := CanonicalEvent{
			Operation:    fmt.Sprintf("ai.inference:%s", r.Model),
			Actor:        r.AgentID,
			Resource:     r.Model,
			Time:         normalizeTimestamp(r.Timestamp),
			Status:       normalizeStatus(r.Status),
			Region:       "", // AI calls are region-agnostic at the app layer
			ActivityType: ActivityOther,
			EventID:      r.RequestID,
		}
		events = append(events, e)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("swt3 telemetry: no valid records with model field")
	}
	return events, nil
}

// ParseOTelSpans parses OTel span JSON and extracts gen_ai.* attributes.
// Accepts the OTLP JSON export format (resourceSpans array) or a flat
// array of span objects.
func ParseOTelSpans(data []byte) ([]CanonicalEvent, error) {
	data = trimBOM(data)

	// Try OTLP envelope first
	var envelope struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []OTelSpan `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && len(envelope.ResourceSpans) > 0 {
		var spans []OTelSpan
		for _, rs := range envelope.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				spans = append(spans, ss.Spans...)
			}
		}
		return spansToEvents(spans)
	}

	// Try flat array of spans
	var spans []OTelSpan
	if err := json.Unmarshal(data, &spans); err != nil {
		// Try single span
		var single OTelSpan
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, fmt.Errorf("otel spans: not valid OTLP or span array: %w", err2)
		}
		spans = []OTelSpan{single}
	}

	return spansToEvents(spans)
}

func spansToEvents(spans []OTelSpan) ([]CanonicalEvent, error) {
	var events []CanonicalEvent

	for _, s := range spans {
		attrs := flattenAttributes(s.Attributes)

		model := stringAttr(attrs, "gen_ai.request.model")
		if model == "" {
			model = stringAttr(attrs, "gen_ai.response.model")
		}
		if model == "" {
			continue // not an AI span
		}

		system := stringAttr(attrs, "gen_ai.system")
		status := "Success"
		if stringAttr(attrs, "otel.status_code") == "ERROR" {
			status = stringAttr(attrs, "otel.status_description")
			if status == "" {
				status = "ERROR"
			}
		}

		ts := ""
		if s.StartTime > 0 {
			ts = time.Unix(0, s.StartTime).UTC().Format(time.RFC3339)
		}

		operation := "ai.inference"
		if system != "" {
			operation = fmt.Sprintf("ai.inference:%s/%s", system, model)
		} else {
			operation = fmt.Sprintf("ai.inference:%s", model)
		}

		e := CanonicalEvent{
			Operation:    operation,
			Actor:        system,
			Resource:     model,
			Time:         ts,
			Status:       status,
			Region:       "",
			ActivityType: ActivityOther,
			EventID:      s.SpanID,
		}
		events = append(events, e)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("otel spans: no spans with gen_ai.request.model attribute")
	}
	return events, nil
}

func flattenAttributes(attrs []OTelAttribute) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		// OTel values are wrapped: {"stringValue":"..."} or {"intValue":...}
		var sv struct {
			StringValue string      `json:"stringValue"`
			IntValue    json.Number `json:"intValue"`
		}
		if json.Unmarshal(a.Value, &sv) == nil {
			if sv.StringValue != "" {
				m[a.Key] = sv.StringValue
			} else if sv.IntValue != "" {
				m[a.Key] = string(sv.IntValue)
			}
			continue
		}
		// Try plain string
		var plain string
		if json.Unmarshal(a.Value, &plain) == nil {
			m[a.Key] = plain
		}
	}
	return m
}

func stringAttr(m map[string]string, key string) string {
	return m[key]
}

func normalizeTimestamp(ts string) string {
	if ts == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	// Already ISO 8601
	if _, err := time.Parse(time.RFC3339, ts); err == nil {
		return ts
	}
	// Try epoch seconds
	return ts
}

func normalizeStatus(s string) string {
	lower := strings.ToLower(s)
	switch lower {
	case "ok", "success", "200", "":
		return "Success"
	default:
		return s
	}
}

func trimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

// IsSWT3Telemetry checks if JSON data looks like SWT3 simple telemetry.
func IsSWT3Telemetry(data []byte) bool {
	// Quick heuristic: contains "model" and "tokens_in"
	return containsKeys(data, "model", "tokens_in")
}

// IsOTelSpan checks if JSON data looks like OTel span data.
func IsOTelSpan(data []byte) bool {
	return containsKeys(data, "traceId", "spanId") || containsKeys(data, "resourceSpans")
}

func containsKeys(data []byte, keys ...string) bool {
	s := string(data)
	for _, k := range keys {
		if !strings.Contains(s, `"`+k+`"`) {
			return false
		}
	}
	return true
}

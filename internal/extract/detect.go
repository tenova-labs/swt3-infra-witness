package extract

import (
	"encoding/json"
	"fmt"
)

// AutoDetect inspects the JSON structure and routes to the correct adapter.
func AutoDetect(data []byte) ([]CanonicalEvent, error) {
	format := DetectFormat(data)
	switch format {
	case "cloudtrail":
		return ParseCloudTrail(data)
	case "azure":
		return ParseAzureActivity(data)
	case "gcp":
		return ParseGCPAudit(data)
	case "ocsf":
		return ParseOCSF(data)
	case "swt3":
		return ParseSWT3Telemetry(data)
	case "otel":
		return ParseOTelSpans(data)
	default:
		return nil, fmt.Errorf("could not auto-detect format. Supported: cloudtrail, azure, gcp, ocsf, swt3, otel. Use --format to specify explicitly")
	}
}

// DetectFormat inspects JSON structure and returns the format name.
func DetectFormat(data []byte) string {
	// Try as object first
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err == nil {
		// AI telemetry formats (tail mode)
		if _, ok := obj["resourceSpans"]; ok {
			return "otel" // OTLP JSON envelope
		}
		if _, ok := obj["traceId"]; ok {
			if _, ok2 := obj["spanId"]; ok2 {
				return "otel" // Single OTel span
			}
		}
		if _, ok := obj["model"]; ok {
			if _, ok2 := obj["tokens_in"]; ok2 {
				return "swt3" // SWT3 simple AI telemetry
			}
		}

		// Check for envelope keys
		if _, ok := obj["Records"]; ok {
			return "cloudtrail" // CloudTrail S3 delivery (uppercase R)
		}
		if _, ok := obj["entries"]; ok {
			return "gcp" // GCP Logging export
		}
		// Azure uses lowercase "records"; peek inside to distinguish from other formats
		if raw, ok := obj["records"]; ok {
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
				inner := DetectFormat(arr[0])
				if inner == "azure" {
					return "azure"
				}
			}
			return "azure" // Default: lowercase "records" is Azure diagnostic export
		}
		// Azure also uses "value" envelope from REST API
		if _, ok := obj["value"]; ok {
			if _, ok2 := obj["nextLink"]; ok2 {
				return "azure" // Azure paginated response
			}
		}

		// Check for provider-specific top-level fields
		if _, ok := obj["eventName"]; ok {
			return "cloudtrail"
		}
		if _, ok := obj["protoPayload"]; ok {
			return "gcp"
		}
		if _, ok := obj["operationName"]; ok {
			if _, ok2 := obj["caller"]; ok2 {
				return "azure"
			}
		}

		// OCSF detection
		if classUID, ok := obj["class_uid"]; ok {
			var uid int
			if json.Unmarshal(classUID, &uid) == nil && uid == 6003 {
				return "ocsf"
			}
		}
		if className, ok := obj["class_name"]; ok {
			var name string
			if json.Unmarshal(className, &name) == nil && name == "api_activity" {
				return "ocsf"
			}
		}
		if _, ok := obj["events"]; ok {
			// Could be OCSF events envelope -- peek inside
			return "ocsf"
		}
	}

	// Try as array -- peek at first element
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return DetectFormat(arr[0])
	}

	return "unknown"
}

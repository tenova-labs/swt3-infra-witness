package extract

import (
	"encoding/json"
	"fmt"
	"strings"
)

// azureActivityRecord maps the fields we need from Azure Activity Log JSON.
// Azure exports via Diagnostic Settings -> Event Hub or Storage Account.
type azureActivityRecord struct {
	OperationName struct {
		Value     string `json:"value"`
		LocalizedValue string `json:"localizedValue"`
	} `json:"operationName"`
	Caller        string `json:"caller"` // UPN or service principal
	ResourceID    string `json:"resourceId"`
	EventTimestamp string `json:"eventTimestamp"` // ISO 8601
	Status        struct {
		Value string `json:"value"` // "Succeeded", "Failed", etc.
	} `json:"status"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
	CorrelationID     string `json:"correlationId"`
	// Nested properties for some event types
	Properties map[string]interface{} `json:"properties"`
}

// azureActivityEnvelope wraps the records array from Azure export.
type azureActivityEnvelope struct {
	Records []azureActivityRecord `json:"records"`
	Value   []azureActivityRecord `json:"value"`
}

// ParseAzureActivity extracts canonical events from Azure Activity Log JSON.
// Accepts single event, {"records": [...]}, or {"value": [...]}.
func ParseAzureActivity(data []byte) ([]CanonicalEvent, error) {
	// Try envelope formats first
	var envelope azureActivityEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil {
		records := envelope.Records
		if len(records) == 0 {
			records = envelope.Value
		}
		if len(records) > 0 {
			return convertAzureRecords(records)
		}
	}

	// Try array
	var records []azureActivityRecord
	if err := json.Unmarshal(data, &records); err == nil && len(records) > 0 {
		return convertAzureRecords(records)
	}

	// Try single event
	var single azureActivityRecord
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("invalid Azure Activity Log JSON: %w", err)
	}
	if single.OperationName.Value == "" {
		return nil, fmt.Errorf("invalid Azure Activity Log event: missing operationName")
	}
	return convertAzureRecords([]azureActivityRecord{single})
}

func convertAzureRecords(records []azureActivityRecord) ([]CanonicalEvent, error) {
	events := make([]CanonicalEvent, 0, len(records))
	for i, r := range records {
		if r.OperationName.Value == "" {
			return nil, fmt.Errorf("record %d: missing operationName", i)
		}

		// Extract operation name (last segment of the provider action)
		operation := r.OperationName.Value
		if idx := strings.LastIndex(operation, "/"); idx >= 0 {
			operation = operation[idx+1:]
		}

		// Status normalization
		status := "Success"
		if r.Status.Value != "" && r.Status.Value != "Succeeded" && r.Status.Value != "Accepted" && r.Status.Value != "OK" {
			status = r.Status.Value
		}

		// Region from resource ID: /subscriptions/.../resourceGroups/.../providers/...
		// Azure doesn't always include region in activity log; use resource group as fallback
		region := r.ResourceGroupName
		if region == "" {
			region = extractAzureRegionFromResourceID(r.ResourceID)
		}

		events = append(events, CanonicalEvent{
			Operation:    r.OperationName.Value,
			Actor:        r.Caller,
			Resource:     r.ResourceID,
			Time:         r.EventTimestamp,
			Status:       status,
			Region:       region,
			ActivityType: classifyActivity(operation),
			EventID:      r.CorrelationID,
		})
	}
	return events, nil
}

func extractAzureRegionFromResourceID(resourceID string) string {
	// Azure resource IDs don't contain region directly.
	// Return empty -- the canonical hash handles empty strings deterministically.
	return ""
}

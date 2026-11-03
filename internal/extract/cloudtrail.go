package extract

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cloudTrailRecord maps the fields we need from CloudTrail JSON.
// Fields we deliberately ignore (requestParameters, responseElements, etc.)
// are not parsed -- they never leave the customer's account.
type cloudTrailRecord struct {
	EventName    string `json:"eventName"`
	UserIdentity struct {
		Type        string `json:"type"`
		ARN         string `json:"arn"`
		PrincipalID string `json:"principalId"`
		AccountID   string `json:"accountId"`
		InvokedBy   string `json:"invokedBy,omitempty"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN  string `json:"ARN"`
		Type string `json:"type"`
	} `json:"resources"`
	EventTime string `json:"eventTime"`
	ErrorCode string `json:"errorCode,omitempty"`
	AWSRegion string `json:"awsRegion"`
	EventID   string `json:"eventID"`
}

// cloudTrailFile is the wrapper for CloudTrail log files delivered to S3.
type cloudTrailFile struct {
	Records []cloudTrailRecord `json:"Records"`
}

// ParseCloudTrail extracts canonical events from CloudTrail JSON.
// Accepts both a single event object and the {"Records": [...]} envelope.
func ParseCloudTrail(data []byte) ([]CanonicalEvent, error) {
	// Try Records array first (S3-delivered log files)
	var file cloudTrailFile
	if err := json.Unmarshal(data, &file); err == nil && len(file.Records) > 0 {
		return convertRecords(file.Records)
	}

	// Try JSON array of events
	var records []cloudTrailRecord
	if err := json.Unmarshal(data, &records); err == nil && len(records) > 0 {
		return convertRecords(records)
	}

	// Try single event
	var single cloudTrailRecord
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("invalid CloudTrail JSON: %w", err)
	}
	if single.EventName == "" {
		return nil, fmt.Errorf("invalid CloudTrail event: missing eventName")
	}
	return convertRecords([]cloudTrailRecord{single})
}

func convertRecords(records []cloudTrailRecord) ([]CanonicalEvent, error) {
	events := make([]CanonicalEvent, 0, len(records))
	for i, r := range records {
		if r.EventName == "" {
			return nil, fmt.Errorf("record %d: missing eventName", i)
		}

		// Extract resource ARN (first entry, or empty)
		resource := ""
		if len(r.Resources) > 0 && r.Resources[0].ARN != "" {
			resource = r.Resources[0].ARN
		}

		// Status: "Success" if no error code
		status := "Success"
		if r.ErrorCode != "" {
			status = r.ErrorCode
		}

		events = append(events, CanonicalEvent{
			Operation:    r.EventName,
			Actor:        r.UserIdentity.ARN,
			Resource:     resource,
			Time:         r.EventTime,
			Status:       status,
			Region:       r.AWSRegion,
			ActivityType: classifyActivity(r.EventName),
			EventID:      r.EventID,
		})
	}
	return events, nil
}

// classifyActivity maps a CloudTrail eventName to an OCSF activity type.
// Uses operation name prefixes as heuristic.
func classifyActivity(eventName string) int {
	lower := strings.ToLower(eventName)

	// Create operations
	for _, prefix := range []string{"create", "put", "run", "allocate", "register", "attach", "enable", "start", "launch", "insert", "add"} {
		if strings.HasPrefix(lower, prefix) {
			return ActivityCreate
		}
	}

	// Read operations
	for _, prefix := range []string{"describe", "get", "list", "lookup", "search", "check", "head", "batch"} {
		if strings.HasPrefix(lower, prefix) {
			return ActivityRead
		}
	}

	// Update operations
	for _, prefix := range []string{"update", "modify", "set", "change", "replace", "tag", "untag"} {
		if strings.HasPrefix(lower, prefix) {
			return ActivityUpdate
		}
	}

	// Delete operations
	for _, prefix := range []string{"delete", "terminate", "remove", "deregister", "detach", "disable", "stop", "release", "revoke"} {
		if strings.HasPrefix(lower, prefix) {
			return ActivityDelete
		}
	}

	return ActivityOther
}

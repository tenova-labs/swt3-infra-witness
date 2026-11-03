package extract

import (
	"encoding/json"
	"fmt"
	"strings"
)

// gcpAuditEntry maps the fields we need from GCP Cloud Audit Log JSON.
// GCP exports via Cloud Logging sink to Pub/Sub, BigQuery, or GCS.
type gcpAuditEntry struct {
	ProtoPayload struct {
		MethodName         string `json:"methodName"`
		AuthenticationInfo struct {
			PrincipalEmail string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
		ServiceName string `json:"serviceName"`
	} `json:"protoPayload"`
	Resource struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Timestamp string `json:"timestamp"` // RFC 3339
	InsertID  string `json:"insertId"`
	Severity  string `json:"severity"`
}

// gcpAuditEnvelope wraps the entries array from GCP Logging export.
type gcpAuditEnvelope struct {
	Entries []gcpAuditEntry `json:"entries"`
}

// ParseGCPAudit extracts canonical events from GCP Cloud Audit Log JSON.
// Accepts single entry, {"entries": [...]}, or bare array.
func ParseGCPAudit(data []byte) ([]CanonicalEvent, error) {
	// Try entries envelope
	var envelope gcpAuditEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && len(envelope.Entries) > 0 {
		return convertGCPEntries(envelope.Entries)
	}

	// Try array
	var entries []gcpAuditEntry
	if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		return convertGCPEntries(entries)
	}

	// Try single entry
	var single gcpAuditEntry
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("invalid GCP Audit Log JSON: %w", err)
	}
	if single.ProtoPayload.MethodName == "" {
		return nil, fmt.Errorf("invalid GCP Audit Log entry: missing protoPayload.methodName")
	}
	return convertGCPEntries([]gcpAuditEntry{single})
}

func convertGCPEntries(entries []gcpAuditEntry) ([]CanonicalEvent, error) {
	events := make([]CanonicalEvent, 0, len(entries))
	for i, e := range entries {
		if e.ProtoPayload.MethodName == "" {
			return nil, fmt.Errorf("entry %d: missing protoPayload.methodName", i)
		}

		// Build resource string from labels
		resource := buildGCPResource(e.Resource.Type, e.Resource.Labels)

		// Status: "Success" if code is 0 or absent
		status := "Success"
		if e.ProtoPayload.Status.Code != 0 {
			status = e.ProtoPayload.Status.Message
			if status == "" {
				status = fmt.Sprintf("ERROR_%d", e.ProtoPayload.Status.Code)
			}
		}

		// Region from labels (zone or location)
		region := e.Resource.Labels["zone"]
		if region == "" {
			region = e.Resource.Labels["location"]
		}
		if region == "" {
			region = e.Resource.Labels["region"]
		}

		// Activity type from the last segment of methodName
		opShort := e.ProtoPayload.MethodName
		if idx := strings.LastIndex(opShort, "."); idx >= 0 {
			opShort = opShort[idx+1:]
		}

		events = append(events, CanonicalEvent{
			Operation:    e.ProtoPayload.MethodName,
			Actor:        e.ProtoPayload.AuthenticationInfo.PrincipalEmail,
			Resource:     resource,
			Time:         e.Timestamp,
			Status:       status,
			Region:       region,
			ActivityType: classifyActivity(opShort),
			EventID:      e.InsertID,
		})
	}
	return events, nil
}

// buildGCPResource constructs a resource identifier from GCP resource labels.
func buildGCPResource(resourceType string, labels map[string]string) string {
	if len(labels) == 0 {
		return resourceType
	}
	project := labels["project_id"]
	// Try common label patterns
	for _, key := range []string{"instance_id", "cluster_name", "bucket_name", "database_id", "topic_name", "function_name"} {
		if v := labels[key]; v != "" {
			if project != "" {
				return fmt.Sprintf("projects/%s/%s/%s", project, resourceType, v)
			}
			return fmt.Sprintf("%s/%s", resourceType, v)
		}
	}
	if project != "" {
		return fmt.Sprintf("projects/%s/%s", project, resourceType)
	}
	return resourceType
}

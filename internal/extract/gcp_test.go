package extract

import (
	"testing"
)

const gcpSingleEntry = `{
  "protoPayload": {
    "methodName": "compute.instances.insert",
    "authenticationInfo": {"principalEmail": "deploy@my-project.iam.gserviceaccount.com"},
    "status": {},
    "serviceName": "compute.googleapis.com"
  },
  "resource": {
    "type": "gce_instance",
    "labels": {"project_id": "my-project", "instance_id": "1234567890", "zone": "us-central1-a"}
  },
  "timestamp": "2026-10-31T14:22:07Z",
  "insertId": "gcp-001",
  "severity": "NOTICE"
}`

const gcpEntriesEnvelope = `{"entries": [
  {
    "protoPayload": {
      "methodName": "storage.buckets.create",
      "authenticationInfo": {"principalEmail": "admin@example.com"},
      "status": {},
      "serviceName": "storage.googleapis.com"
    },
    "resource": {"type": "gcs_bucket", "labels": {"project_id": "my-project", "bucket_name": "my-bucket"}},
    "timestamp": "2026-10-31T10:00:00Z",
    "insertId": "gcp-002"
  },
  {
    "protoPayload": {
      "methodName": "compute.instances.delete",
      "authenticationInfo": {"principalEmail": "admin@example.com"},
      "status": {"code": 403, "message": "PERMISSION_DENIED"},
      "serviceName": "compute.googleapis.com"
    },
    "resource": {"type": "gce_instance", "labels": {"project_id": "my-project", "zone": "europe-west1-b"}},
    "timestamp": "2026-10-31T11:00:00Z",
    "insertId": "gcp-003"
  }
]}`

func TestParseGCPSingleEntry(t *testing.T) {
	events, err := ParseGCPAudit([]byte(gcpSingleEntry))
	if err != nil {
		t.Fatalf("ParseGCPAudit() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	assertEqual(t, "Operation", e.Operation, "compute.instances.insert")
	assertEqual(t, "Actor", e.Actor, "deploy@my-project.iam.gserviceaccount.com")
	assertEqual(t, "Time", e.Time, "2026-10-31T14:22:07Z")
	assertEqual(t, "Status", e.Status, "Success")
	assertEqual(t, "Region", e.Region, "us-central1-a")
	assertEqual(t, "EventID", e.EventID, "gcp-001")
	if e.ActivityType != ActivityCreate {
		t.Errorf("ActivityType = %d, want Create(%d)", e.ActivityType, ActivityCreate)
	}
	// Resource should include project and instance
	if e.Resource == "" {
		t.Error("Resource should not be empty")
	}
}

func TestParseGCPEntriesEnvelope(t *testing.T) {
	events, err := ParseGCPAudit([]byte(gcpEntriesEnvelope))
	if err != nil {
		t.Fatalf("ParseGCPAudit() error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	assertEqual(t, "events[0].Operation", events[0].Operation, "storage.buckets.create")
	assertEqual(t, "events[0].Status", events[0].Status, "Success")
	if events[0].ActivityType != ActivityCreate {
		t.Errorf("events[0].ActivityType = %d, want Create(%d)", events[0].ActivityType, ActivityCreate)
	}

	assertEqual(t, "events[1].Operation", events[1].Operation, "compute.instances.delete")
	assertEqual(t, "events[1].Status", events[1].Status, "PERMISSION_DENIED")
	assertEqual(t, "events[1].Region", events[1].Region, "europe-west1-b")
	if events[1].ActivityType != ActivityDelete {
		t.Errorf("events[1].ActivityType = %d, want Delete(%d)", events[1].ActivityType, ActivityDelete)
	}
}

func TestParseGCPMissingMethodName(t *testing.T) {
	_, err := ParseGCPAudit([]byte(`{"protoPayload": {}, "timestamp": "2026-10-31T00:00:00Z"}`))
	if err == nil {
		t.Error("expected error for missing methodName")
	}
}

func TestParseGCPInvalidJSON(t *testing.T) {
	_, err := ParseGCPAudit([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

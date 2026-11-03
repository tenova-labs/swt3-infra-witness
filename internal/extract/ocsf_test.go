package extract

import (
	"testing"
)

const ocsfSingleEvent = `{
  "class_uid": 6003,
  "class_name": "api_activity",
  "api": {"operation": "RunInstances"},
  "actor": {"user": {"uid": "arn:aws:iam::123:role/agent", "name": "agent"}},
  "cloud": {
    "region": "us-east-1",
    "resource": {"uid": "arn:aws:ec2:us-east-1:123:instance/i-abc"}
  },
  "time": "2026-10-31T14:22:07Z",
  "status": "Success",
  "status_id": 1,
  "activity_id": 1,
  "metadata": {"uid": "ocsf-001"}
}`

const ocsfEventsEnvelope = `{"events": [
  {
    "class_uid": 6003,
    "api": {"operation": "CreateBucket"},
    "actor": {"user": {"name": "admin@example.com"}},
    "cloud": {"region": "eu-west-1", "resource": {"uid": "my-bucket"}},
    "time_dt": 1730380800000,
    "status_id": 1,
    "activity_id": 1,
    "metadata": {"uid": "ocsf-002"}
  },
  {
    "class_uid": 6003,
    "api": {"operation": "DeleteTable"},
    "actor": {"user": {"uid": "service-account-1"}},
    "cloud": {"region": "ap-southeast-1"},
    "dst_endpoint": {"uid": "arn:aws:dynamodb:ap-southeast-1:123:table/users"},
    "time": "2026-10-31T11:00:00Z",
    "status": "AccessDenied",
    "status_id": 2,
    "activity_id": 4,
    "metadata": {"uid": "ocsf-003"}
  }
]}`

func TestParseOCSFSingleEvent(t *testing.T) {
	events, err := ParseOCSF([]byte(ocsfSingleEvent))
	if err != nil {
		t.Fatalf("ParseOCSF() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	assertEqual(t, "Operation", e.Operation, "RunInstances")
	assertEqual(t, "Actor", e.Actor, "arn:aws:iam::123:role/agent")
	assertEqual(t, "Resource", e.Resource, "arn:aws:ec2:us-east-1:123:instance/i-abc")
	assertEqual(t, "Time", e.Time, "2026-10-31T14:22:07Z")
	assertEqual(t, "Status", e.Status, "Success")
	assertEqual(t, "Region", e.Region, "us-east-1")
	assertEqual(t, "EventID", e.EventID, "ocsf-001")
	if e.ActivityType != ActivityCreate {
		t.Errorf("ActivityType = %d, want Create(%d)", e.ActivityType, ActivityCreate)
	}
}

func TestParseOCSFEventsEnvelope(t *testing.T) {
	events, err := ParseOCSF([]byte(ocsfEventsEnvelope))
	if err != nil {
		t.Fatalf("ParseOCSF() error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First: CreateBucket, actor from name (no uid)
	assertEqual(t, "events[0].Operation", events[0].Operation, "CreateBucket")
	assertEqual(t, "events[0].Actor", events[0].Actor, "admin@example.com")
	assertEqual(t, "events[0].Region", events[0].Region, "eu-west-1")
	// time_dt is epoch ms
	if events[0].Time == "" {
		t.Error("events[0].Time should not be empty (from time_dt)")
	}

	// Second: DeleteTable, resource from dst_endpoint fallback
	assertEqual(t, "events[1].Operation", events[1].Operation, "DeleteTable")
	assertEqual(t, "events[1].Resource", events[1].Resource, "arn:aws:dynamodb:ap-southeast-1:123:table/users")
	assertEqual(t, "events[1].Status", events[1].Status, "AccessDenied")
	if events[1].ActivityType != ActivityDelete {
		t.Errorf("events[1].ActivityType = %d, want Delete(%d)", events[1].ActivityType, ActivityDelete)
	}
}

func TestParseOCSFMissingOperation(t *testing.T) {
	_, err := ParseOCSF([]byte(`{"class_uid": 6003, "api": {}, "time": "t"}`))
	if err == nil {
		t.Error("expected error for missing api.operation")
	}
}

func TestParseOCSFInvalidJSON(t *testing.T) {
	_, err := ParseOCSF([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

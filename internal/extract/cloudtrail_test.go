package extract

import (
	"testing"
)

const singleEvent = `{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:iam::123456789012:role/deploy-agent",
    "principalId": "AROA3XFRBF23",
    "accountId": "123456789012"
  },
  "eventTime": "2026-10-31T14:22:07Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "RunInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.42",
  "requestParameters": {"instanceType": "t3.medium"},
  "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0abc123"}]}},
  "resources": [
    {"ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123", "type": "AWS::EC2::Instance"}
  ],
  "eventID": "event-001",
  "eventType": "AwsApiCall"
}`

const recordsEnvelope = `{"Records": [
  {
    "eventName": "CreateBucket",
    "userIdentity": {"arn": "arn:aws:iam::111:user/alice"},
    "eventTime": "2026-10-31T10:00:00Z",
    "awsRegion": "us-west-2",
    "resources": [{"ARN": "arn:aws:s3:::my-bucket"}],
    "eventID": "event-002"
  },
  {
    "eventName": "DeleteBucket",
    "userIdentity": {"arn": "arn:aws:iam::111:user/bob"},
    "eventTime": "2026-10-31T11:00:00Z",
    "awsRegion": "eu-west-1",
    "errorCode": "BucketNotEmpty",
    "resources": [],
    "eventID": "event-003"
  }
]}`

func TestParseSingleEvent(t *testing.T) {
	events, err := ParseCloudTrail([]byte(singleEvent))
	if err != nil {
		t.Fatalf("ParseCloudTrail() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	e := events[0]
	assertEqual(t, "Operation", e.Operation, "RunInstances")
	assertEqual(t, "Actor", e.Actor, "arn:aws:iam::123456789012:role/deploy-agent")
	assertEqual(t, "Resource", e.Resource, "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123")
	assertEqual(t, "Time", e.Time, "2026-10-31T14:22:07Z")
	assertEqual(t, "Status", e.Status, "Success")
	assertEqual(t, "Region", e.Region, "us-east-1")
	assertEqual(t, "EventID", e.EventID, "event-001")

	if e.ActivityType != ActivityCreate {
		t.Errorf("ActivityType = %d, want %d (Create)", e.ActivityType, ActivityCreate)
	}
}

func TestParseRecordsEnvelope(t *testing.T) {
	events, err := ParseCloudTrail([]byte(recordsEnvelope))
	if err != nil {
		t.Fatalf("ParseCloudTrail() error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// First event: CreateBucket, success
	assertEqual(t, "events[0].Operation", events[0].Operation, "CreateBucket")
	assertEqual(t, "events[0].Status", events[0].Status, "Success")
	assertEqual(t, "events[0].Resource", events[0].Resource, "arn:aws:s3:::my-bucket")
	if events[0].ActivityType != ActivityCreate {
		t.Errorf("events[0].ActivityType = %d, want Create(%d)", events[0].ActivityType, ActivityCreate)
	}

	// Second event: DeleteBucket, error
	assertEqual(t, "events[1].Operation", events[1].Operation, "DeleteBucket")
	assertEqual(t, "events[1].Status", events[1].Status, "BucketNotEmpty")
	assertEqual(t, "events[1].Resource", events[1].Resource, "")
	if events[1].ActivityType != ActivityDelete {
		t.Errorf("events[1].ActivityType = %d, want Delete(%d)", events[1].ActivityType, ActivityDelete)
	}
}

func TestParseEmptyResources(t *testing.T) {
	json := `{"eventName": "DescribeInstances", "userIdentity": {"arn": "arn:aws:iam::123:user/test"}, "eventTime": "2026-10-31T00:00:00Z", "awsRegion": "us-east-1", "eventID": "event-004"}`
	events, err := ParseCloudTrail([]byte(json))
	if err != nil {
		t.Fatalf("ParseCloudTrail() error: %v", err)
	}
	if events[0].Resource != "" {
		t.Errorf("Resource should be empty, got %q", events[0].Resource)
	}
	if events[0].ActivityType != ActivityRead {
		t.Errorf("ActivityType = %d, want Read(%d)", events[0].ActivityType, ActivityRead)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := ParseCloudTrail([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseNoEventName(t *testing.T) {
	_, err := ParseCloudTrail([]byte(`{"userIdentity": {"arn": "x"}}`))
	if err == nil {
		t.Error("expected error for missing eventName")
	}
}

func TestClassifyActivity(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"RunInstances", ActivityCreate},
		{"CreateBucket", ActivityCreate},
		{"PutObject", ActivityCreate},
		{"LaunchTemplate", ActivityCreate},
		{"StartInstances", ActivityCreate},
		{"DescribeInstances", ActivityRead},
		{"GetObject", ActivityRead},
		{"ListBuckets", ActivityRead},
		{"UpdateStack", ActivityUpdate},
		{"ModifyInstanceAttribute", ActivityUpdate},
		{"SetBucketPolicy", ActivityUpdate},
		{"TagResource", ActivityUpdate},
		{"DeleteBucket", ActivityDelete},
		{"TerminateInstances", ActivityDelete},
		{"RemovePermission", ActivityDelete},
		{"RevokeSecurityGroupIngress", ActivityDelete},
		{"StopInstances", ActivityDelete},
		{"ConsoleLogin", ActivityOther},
		{"AssumeRole", ActivityOther},
	}
	for _, tt := range tests {
		got := classifyActivity(tt.name)
		if got != tt.want {
			t.Errorf("classifyActivity(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func assertEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

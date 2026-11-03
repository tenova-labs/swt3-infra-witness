package extract

import (
	"testing"
)

func TestDetectCloudTrail(t *testing.T) {
	got := DetectFormat([]byte(singleEvent))
	if got != "cloudtrail" {
		t.Errorf("DetectFormat(cloudtrail single) = %q, want cloudtrail", got)
	}
}

func TestDetectCloudTrailRecords(t *testing.T) {
	got := DetectFormat([]byte(recordsEnvelope))
	if got != "cloudtrail" {
		t.Errorf("DetectFormat(cloudtrail records) = %q, want cloudtrail", got)
	}
}

func TestDetectAzure(t *testing.T) {
	got := DetectFormat([]byte(azureSingleEvent))
	if got != "azure" {
		t.Errorf("DetectFormat(azure) = %q, want azure", got)
	}
}

func TestDetectGCP(t *testing.T) {
	got := DetectFormat([]byte(gcpSingleEntry))
	if got != "gcp" {
		t.Errorf("DetectFormat(gcp) = %q, want gcp", got)
	}
}

func TestDetectOCSF(t *testing.T) {
	got := DetectFormat([]byte(ocsfSingleEvent))
	if got != "ocsf" {
		t.Errorf("DetectFormat(ocsf) = %q, want ocsf", got)
	}
}

func TestDetectAzureRecordsEnvelope(t *testing.T) {
	got := DetectFormat([]byte(azureRecordsEnvelope))
	if got != "azure" {
		t.Errorf("DetectFormat(azure records) = %q, want azure", got)
	}
}

func TestDetectUnknown(t *testing.T) {
	got := DetectFormat([]byte(`{"random": "json"}`))
	if got != "unknown" {
		t.Errorf("DetectFormat(unknown) = %q, want unknown", got)
	}
}

func TestAutoDetectCloudTrail(t *testing.T) {
	events, err := AutoDetect([]byte(singleEvent))
	if err != nil {
		t.Fatalf("AutoDetect() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	assertEqual(t, "Operation", events[0].Operation, "RunInstances")
}

func TestAutoDetectUnknown(t *testing.T) {
	_, err := AutoDetect([]byte(`{"random": "json"}`))
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

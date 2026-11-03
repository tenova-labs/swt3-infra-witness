package extract

import (
	"testing"
)

const azureSingleEvent = `{
  "operationName": {"value": "Microsoft.Compute/virtualMachines/write", "localizedValue": "Create or Update Virtual Machine"},
  "caller": "deploy@example.onmicrosoft.com",
  "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-001",
  "eventTimestamp": "2026-10-31T14:22:07Z",
  "status": {"value": "Succeeded"},
  "resourceGroupName": "rg-prod",
  "subscriptionId": "sub-123",
  "correlationId": "azure-001"
}`

const azureRecordsEnvelope = `{"records": [
  {
    "operationName": {"value": "Microsoft.Storage/storageAccounts/write"},
    "caller": "admin@example.com",
    "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/mystorage",
    "eventTimestamp": "2026-10-31T10:00:00Z",
    "status": {"value": "Succeeded"},
    "resourceGroupName": "rg-prod",
    "correlationId": "azure-002"
  },
  {
    "operationName": {"value": "Microsoft.Network/networkSecurityGroups/delete"},
    "caller": "service-principal-1",
    "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-001",
    "eventTimestamp": "2026-10-31T11:00:00Z",
    "status": {"value": "Failed"},
    "resourceGroupName": "rg-prod",
    "correlationId": "azure-003"
  }
]}`

func TestParseAzureSingleEvent(t *testing.T) {
	events, err := ParseAzureActivity([]byte(azureSingleEvent))
	if err != nil {
		t.Fatalf("ParseAzureActivity() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	assertEqual(t, "Operation", e.Operation, "Microsoft.Compute/virtualMachines/write")
	assertEqual(t, "Actor", e.Actor, "deploy@example.onmicrosoft.com")
	assertEqual(t, "Time", e.Time, "2026-10-31T14:22:07Z")
	assertEqual(t, "Status", e.Status, "Success")
	assertEqual(t, "Region", e.Region, "rg-prod")
	assertEqual(t, "EventID", e.EventID, "azure-001")
	// "write" suffix -> classifyActivity sees it as Other (not prefixed with create/put/etc)
	// But the full operation is used for the canonical hash
}

func TestParseAzureRecordsEnvelope(t *testing.T) {
	events, err := ParseAzureActivity([]byte(azureRecordsEnvelope))
	if err != nil {
		t.Fatalf("ParseAzureActivity() error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	assertEqual(t, "events[0].Status", events[0].Status, "Success")
	assertEqual(t, "events[1].Status", events[1].Status, "Failed")
	if events[1].ActivityType != ActivityDelete {
		t.Errorf("events[1].ActivityType = %d, want Delete(%d)", events[1].ActivityType, ActivityDelete)
	}
}

func TestParseAzureMissingOperationName(t *testing.T) {
	_, err := ParseAzureActivity([]byte(`{"caller": "x", "eventTimestamp": "t"}`))
	if err == nil {
		t.Error("expected error for missing operationName")
	}
}

func TestParseAzureStatusNormalization(t *testing.T) {
	json := `{"operationName": {"value": "test/op"}, "caller": "x", "eventTimestamp": "t", "status": {"value": "Accepted"}, "correlationId": "c1"}`
	events, err := ParseAzureActivity([]byte(json))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	assertEqual(t, "Status", events[0].Status, "Success") // Accepted -> Success
}

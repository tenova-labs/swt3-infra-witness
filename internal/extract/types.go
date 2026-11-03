// Package extract provides format adapters that parse cloud audit log
// formats into a common CanonicalEvent structure.
package extract

// CanonicalEvent holds the 6 normalized fields from any cloud audit log.
// These fields are the pinned canonical set for infrastructure witnessing.
// The set is independent of OCSF schema version evolution.
type CanonicalEvent struct {
	Operation    string `json:"operation"`     // API call name (e.g., RunInstances)
	Actor        string `json:"actor"`         // Identity (IAM ARN, service principal)
	Resource     string `json:"resource"`      // Resource ARN/ID (may be empty for read-only calls)
	Time         string `json:"time"`          // ISO 8601 from provider clock (UTC)
	Status       string `json:"status"`        // "Success" or error code
	Region       string `json:"region"`        // Cloud region
	ActivityType int    `json:"activity_type"` // OCSF activity: 1=Create, 2=Read, 3=Update, 4=Delete, 99=Other
	EventID      string `json:"event_id"`      // Provider-unique event ID (for dedup)
}

// OCSF Activity Type codes
const (
	ActivityCreate = 1
	ActivityRead   = 2
	ActivityUpdate = 3
	ActivityDelete = 4
	ActivityOther  = 99
)

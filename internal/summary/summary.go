// Package summary generates human-readable event descriptions from
// canonical infrastructure events. Summaries survive source audit log
// deletion, enabling auditors to understand what an anchor represents
// without access to the original CloudTrail event.
package summary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
)

// Generate produces a human-readable one-liner for an infrastructure event.
// The clearingLevel controls what fields are included:
//
//	L0: full summary with all fields
//	L1: full summary (actor hashing done server-side in observations)
//	L2: operation + region + status only (no actor, no resource)
//	L3: empty string (hash only, no summary)
func Generate(event extract.CanonicalEvent, clearingLevel int) string {
	switch {
	case clearingLevel >= 3:
		return ""
	case clearingLevel >= 2:
		return fmt.Sprintf("%s in %s [%s]", event.Operation, event.Region, event.Status)
	default:
		resource := event.Resource
		if resource == "" {
			resource = "(none)"
		}
		return fmt.Sprintf("At %s, %s called %s on %s in %s [%s]",
			event.Time, event.Actor, event.Operation, resource, event.Region, event.Status)
	}
}

// HashActor returns the first 16 hex chars of SHA-256(actor).
// Used at clearing level 1+ to replace the actor identity in observations.
func HashActor(actor string) string {
	h := sha256.Sum256([]byte(actor))
	return hex.EncodeToString(h[:])[:16]
}

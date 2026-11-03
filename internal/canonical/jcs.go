// Package canonical implements SWT3 Deterministic Canonical JSON for
// cross-language hash parity. Keys are sorted lexicographically, output
// is compact JSON with no HTML escaping (matching JS JSON.stringify).
//
// This is NOT full RFC 8785 JCS -- it is a simpler scheme sufficient for
// string-only canonical fields. All 6 infrastructure event fields are
// strings, so float serialization parity is not a concern.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize produces a deterministic JSON string from a map of string
// key-value pairs. Keys are sorted lexicographically, output is compact
// with no HTML escaping. The output is identical to JavaScript's
// JSON.stringify(sortKeys(obj)) for objects containing only string values.
func Canonicalize(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(marshalStringNoEscape(k))
		buf.WriteByte(':')
		buf.Write(marshalStringNoEscape(fields[k]))
	}
	buf.WriteByte('}')

	return buf.String()
}

// marshalStringNoEscape JSON-encodes a string without HTML escaping.
// Go's json.Marshal escapes <, >, & which breaks parity with JS JSON.stringify.
func marshalStringNoEscape(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	// Encode appends a newline; trim it and return
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b
}

// Hash computes the SHA-256 hex digest of the canonical JSON representation.
func Hash(fields map[string]string) string {
	canonical := Canonicalize(fields)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// HashTruncated returns the first `length` hex characters of the canonical hash.
func HashTruncated(fields map[string]string, length int) string {
	full := Hash(fields)
	if length > 64 {
		length = 64
	}
	if length < 1 {
		return full
	}
	return full[:length]
}

// FieldsFromEvent builds the canonical field map from individual values.
// This is the pinned 6-field set for infrastructure events.
func FieldsFromEvent(operation, actor, resource, time, status, region string) map[string]string {
	return map[string]string{
		"actor":     actor,
		"operation": operation,
		"region":    region,
		"resource":  resource,
		"status":    status,
		"time":      time,
	}
}

// Verify re-computes the canonical hash and compares against an expected value.
func Verify(fields map[string]string, expectedHash string) error {
	actual := Hash(fields)
	if actual != expectedHash {
		return fmt.Errorf("canonical hash mismatch: expected %s, got %s", expectedHash, actual)
	}
	return nil
}

// Package client provides the HTTP client for sending infrastructure
// evidence to the SWT3 witness endpoint. Includes inlined fingerprint
// and signing functions for zero external dependencies.
package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// Version is the binary version, embedded in every anchor's observations.
const Version = "0.1.0"

// ── Inlined from swt3-ai-go ─────────────────────────────────────────
// Fingerprint formula is LOCKED, cross-language parity verified via
// test-vectors.json. Inlined to maintain zero external dependencies.

const fingerprintLength = 12

func mintFingerprint(tenantID, procedureID string, factorA, factorB, factorC float64, timestampMs int64) string {
	input := fmt.Sprintf("WITNESS:%s:%s:%s:%s:%s:%d",
		tenantID, procedureID,
		formatFactor(factorA), formatFactor(factorB), formatFactor(factorC),
		timestampMs,
	)
	return sha256Hex(input, fingerprintLength)
}

func formatFactor(v float64) string {
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return fmt.Sprintf("%g", v)
	}
	if v == math.Floor(v) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

func sha256Hex(data string, length int) string {
	h := sha256.Sum256([]byte(data))
	full := hex.EncodeToString(h[:])
	if length > 64 {
		length = 64
	}
	return full[:length]
}

func signPayload(signingKey, fingerprint, agentID string) string {
	msg := fingerprint
	if agentID != "" {
		msg = fingerprint + ":" + agentID
	}
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// ── End inlined functions ────────────────────────────────────────────

// ProcedureID is the hardcoded procedure for infrastructure OCSF events.
const ProcedureID = "INF-OCSF.1"

// Config holds the SWT3 endpoint configuration.
type Config struct {
	Endpoint      string
	APIKey        string
	TenantID      string // Resolved from API key by server; sent empty
	ClearingLevel int
	AgentID       string
	SigningKey    string
}

// OCSFPayload is what the binary sends to the OCSF endpoint.
type OCSFPayload struct {
	CanonicalHash        string  `json:"canonical_hash"`
	EventSummary         string  `json:"event_summary"`
	SourceFormat         string  `json:"source_format"`
	OCSFSchemaVersion    string  `json:"ocsf_schema_version"`
	Operation            string  `json:"operation"`
	Actor                string  `json:"actor"`
	Resource             string  `json:"resource"`
	Time                 string  `json:"time"`
	Status               string  `json:"status"`
	Region               string  `json:"region"`
	ActivityType         int     `json:"activity_type"`
	SourceEventTime      string  `json:"source_event_time"`
	ClearingLevel        int     `json:"clearing_level"`
	AgentID              string  `json:"agent_id,omitempty"`
	AnchorFingerprint    string  `json:"anchor_fingerprint"`
	AnchorEpoch          int64   `json:"anchor_epoch"`
	FingerprintTimestamp int64   `json:"fingerprint_timestamp_ms"`
	FactorA              float64 `json:"factor_a"`
	FactorB              float64 `json:"factor_b"`
	FactorC              float64 `json:"factor_c"`
	PayloadSignature     string  `json:"payload_signature,omitempty"`
	BinaryVersion        string  `json:"binary_version"`
}

// OCSFReceipt is the server response after witnessing.
type OCSFReceipt struct {
	OK              bool   `json:"ok"`
	ProcedureID     string `json:"procedure_id"`
	Verdict         string `json:"verdict"`
	SWT3Anchor      string `json:"swt3_anchor"`
	CanonicalHash   string `json:"canonical_hash"`
	VerificationURL string `json:"verification_url"`
	WitnessedAt     string `json:"witnessed_at"`
	Error           string `json:"error,omitempty"`
	Duplicate       bool   `json:"duplicate,omitempty"`
}

// BatchResponse wraps an array of receipts.
type BatchResponse struct {
	OK       bool          `json:"ok"`
	TenantID string        `json:"tenant_id"`
	Count    int           `json:"count"`
	Receipts []OCSFReceipt `json:"receipts"`
	Error    string        `json:"error,omitempty"`
}

// Client sends OCSF payloads to the SWT3 endpoint.
type Client struct {
	cfg    Config
	http   *http.Client
}

// New creates a Client with the given config.
func New(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ComputeFactors derives the 3 SWT3 factors from a canonical hash and event metadata.
//
//	factor_a = first 8 hex chars of canonical_hash parsed as uint32
//	factor_b = OCSF activity type (1-4, 99)
//	factor_c = 0 for success, 1 for error
func ComputeFactors(canonicalHash string, activityType int, status string) (float64, float64, float64) {
	// factor_a: first 8 hex chars -> uint32 -> float64
	var fa float64
	if len(canonicalHash) >= 8 {
		b, err := hex.DecodeString(canonicalHash[:8])
		if err == nil && len(b) == 4 {
			fa = float64(binary.BigEndian.Uint32(b))
		}
	}
	fb := float64(activityType)
	var fc float64
	if status != "Success" {
		fc = 1
	}
	return fa, fb, fc
}

// BuildPayload constructs a fully-formed OCSFPayload ready for transmission.
func (c *Client) BuildPayload(canonicalHash, eventSummary, sourceFormat, sourceEventTime string, operation, actor, resource, eventTime, status, region string, activityType int) OCSFPayload {
	fa, fb, fc := ComputeFactors(canonicalHash, activityType, status)

	now := time.Now()
	tsMs := now.UnixMilli()
	epoch := now.Unix()

	fp := mintFingerprint("", ProcedureID, fa, fb, fc, tsMs)

	p := OCSFPayload{
		CanonicalHash:        canonicalHash,
		EventSummary:         eventSummary,
		SourceFormat:         sourceFormat,
		OCSFSchemaVersion:    "1.7.0",
		Operation:            operation,
		Actor:                actor,
		Resource:             resource,
		Time:                 eventTime,
		Status:               status,
		Region:               region,
		ActivityType:         activityType,
		SourceEventTime:      sourceEventTime,
		ClearingLevel:        c.cfg.ClearingLevel,
		AgentID:              c.cfg.AgentID,
		AnchorFingerprint:    fp,
		AnchorEpoch:          epoch,
		FingerprintTimestamp: tsMs,
		FactorA:              fa,
		FactorB:              fb,
		FactorC:              fc,
		BinaryVersion:        Version,
	}

	if c.cfg.SigningKey != "" {
		p.PayloadSignature = signPayload(c.cfg.SigningKey, fp, c.cfg.AgentID)
	}

	return p
}

// Send posts a batch of OCSF payloads to the witness endpoint.
// Automatically chunks into batches of 500.
func (c *Client) Send(payloads []OCSFPayload) ([]OCSFReceipt, error) {
	if len(payloads) == 0 {
		return nil, nil
	}

	var allReceipts []OCSFReceipt
	for i := 0; i < len(payloads); i += 500 {
		end := i + 500
		if end > len(payloads) {
			end = len(payloads)
		}
		chunk := payloads[i:end]

		receipts, err := c.sendChunk(chunk)
		if err != nil {
			return allReceipts, fmt.Errorf("batch %d-%d: %w", i, end-1, err)
		}
		allReceipts = append(allReceipts, receipts...)
	}
	return allReceipts, nil
}

func (c *Client) sendChunk(payloads []OCSFPayload) ([]OCSFReceipt, error) {
	body := map[string]interface{}{
		"events": payloads,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest("POST", c.cfg.Endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("User-Agent", "swt3-infra-witness/"+Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		var batch BatchResponse
		if err := json.Unmarshal(respBody, &batch); err != nil {
			return nil, fmt.Errorf("unmarshal response: %w", err)
		}
		return batch.Receipts, nil
	}

	// Truncate non-JSON responses (e.g., HTML 404 pages) for clean terminal output
	errMsg := string(respBody)
	if len(errMsg) > 200 || (len(errMsg) > 0 && errMsg[0] == '<') {
		// Try to extract JSON error
		var errJSON struct{ Error string `json:"error"` }
		if json.Unmarshal(respBody, &errJSON) == nil && errJSON.Error != "" {
			errMsg = errJSON.Error
		} else {
			errMsg = errMsg[:min(200, len(errMsg))] + "..."
		}
	}
	return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, errMsg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

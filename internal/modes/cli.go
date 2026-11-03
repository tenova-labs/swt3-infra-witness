// Package modes implements the execution modes for swt3-infra-witness.
package modes

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tenova-labs/swt3-infra-witness/internal/canonical"
	"github.com/tenova-labs/swt3-infra-witness/internal/client"
	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
	"github.com/tenova-labs/swt3-infra-witness/internal/summary"
)

// ANSI color codes
const (
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	dim    = "\033[90m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

// CursorFile is the default path for the CLI cursor.
const CursorFile = ".swt3-infra-cursor.json"

type cursor struct {
	LastEventID string `json:"last_event_id"`
	LastTime    string `json:"last_time"`
	Count       int64  `json:"count"`
}

// RunCLI reads a CloudTrail JSON file, processes events, and sends to SWT3.
func RunCLI(cfg client.Config, format, inputPath string, noCursor, dryRun bool) error {
	// Read input (file or stdin)
	var data []byte
	var err error
	if inputPath == "-" || inputPath == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	// Parse events
	var events []extract.CanonicalEvent
	switch format {
	case "cloudtrail":
		events, err = extract.ParseCloudTrail(data)
	case "azure":
		events, err = extract.ParseAzureActivity(data)
	case "gcp":
		events, err = extract.ParseGCPAudit(data)
	case "ocsf":
		events, err = extract.ParseOCSF(data)
	case "auto":
		events, err = extract.AutoDetect(data)
	default:
		return fmt.Errorf("unsupported format: %s (supported: cloudtrail, azure, gcp, ocsf, auto)", format)
	}
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	if len(events) == 0 {
		fmt.Fprintf(os.Stderr, "%sNo events found in input.%s\n", yellow, reset)
		return nil
	}

	// Load cursor for dedup
	var cur cursor
	if !noCursor {
		cur = loadCursor()
	}

	// Build payloads
	c := client.New(cfg)
	var payloads []client.OCSFPayload
	var lastEvent extract.CanonicalEvent

	seen := make(map[string]bool)
	skipped := 0

	for _, e := range events {
		// Dedup: skip if already processed (cursor or LRU)
		if !noCursor && cur.LastEventID != "" && e.EventID != "" && e.EventID == cur.LastEventID {
			skipped++
			continue
		}
		if e.EventID != "" {
			if seen[e.EventID] {
				skipped++
				continue
			}
			seen[e.EventID] = true
		}

		fields := canonical.FieldsFromEvent(e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region)
		hash := canonical.Hash(fields)
		sum := summary.Generate(e, cfg.ClearingLevel)

		p := c.BuildPayload(hash, sum, "cloudtrail", e.Time, e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region, e.ActivityType)
		payloads = append(payloads, p)
		lastEvent = e
	}

	if len(payloads) == 0 {
		fmt.Fprintf(os.Stderr, "All %d events already processed (cursor).\n", skipped)
		return nil
	}

	// Dry run: print parsed events without sending
	if dryRun {
		fmt.Fprintf(os.Stderr, "\n%s--dry-run:%s parsed %d events, hashing verified\n\n", bold, reset, len(payloads))
		for i, p := range payloads {
			actLabel := activityLabel(p.ActivityType)
			statusColor := green
			if p.FactorC != 0 {
				statusColor = red
			}
			fmt.Fprintf(os.Stdout, "  %s%d%s  %s%-20s%s  %s%s%s  %s%s%s\n",
				dim, i+1, reset,
				bold, p.Operation, reset,
				statusColor, p.Status, reset,
				dim, actLabel, reset,
			)
			fmt.Fprintf(os.Stdout, "     hash: %s%s%s\n", dim, p.CanonicalHash[:24]+"...", reset)
			fmt.Fprintf(os.Stdout, "     fp:   %s%s%s\n", dim, p.AnchorFingerprint, reset)
			if p.EventSummary != "" {
				fmt.Fprintf(os.Stdout, "     %s%s%s\n", dim, p.EventSummary, reset)
			}
			fmt.Println()
		}
		fmt.Fprintf(os.Stderr, "%s%d events ready to witness.%s Remove --dry-run to send.\n", green, len(payloads), reset)
		return nil
	}

	// Send
	fmt.Fprintf(os.Stderr, "Sending %d events to %s%s%s...\n", len(payloads), dim, cfg.Endpoint, reset)
	receipts, err := c.Send(payloads)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}

	// Print results
	passed := 0
	dupes := 0
	errors := 0
	for _, r := range receipts {
		if r.Duplicate {
			dupes++
			fmt.Fprintf(os.Stdout, "  %s~%s  %s(duplicate)%s\n", yellow, reset, dim, reset)
			continue
		}
		if r.OK {
			passed++
			fmt.Fprintf(os.Stdout, "  %s+%s  %s  %s%s%s  %s\n",
				green, reset, r.ProcedureID, green, r.Verdict, reset, dim+r.SWT3Anchor+reset)
		} else {
			errors++
			fmt.Fprintf(os.Stderr, "  %sx%s  %s\n", red, reset, r.Error)
		}
	}

	fmt.Fprintf(os.Stderr, "\n%s%d witnessed%s", green, passed, reset)
	if dupes > 0 {
		fmt.Fprintf(os.Stderr, ", %s%d duplicates%s", yellow, dupes, reset)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, ", %d skipped (cursor)", skipped)
	}
	if errors > 0 {
		fmt.Fprintf(os.Stderr, ", %s%d errors%s", red, errors, reset)
	}
	fmt.Fprintln(os.Stderr)

	if passed > 0 {
		for _, r := range receipts {
			if r.OK && !r.Duplicate && r.VerificationURL != "" {
				fmt.Fprintf(os.Stderr, "Verify: %s%s%s\n", dim, r.VerificationURL, reset)
				break
			}
		}
	}

	// Save cursor
	if !noCursor && lastEvent.EventID != "" {
		saveCursor(cursor{
			LastEventID: lastEvent.EventID,
			LastTime:    lastEvent.Time,
			Count:       cur.Count + int64(passed),
		})
	}

	return nil
}

func activityLabel(t int) string {
	switch t {
	case 1:
		return "CREATE"
	case 2:
		return "READ"
	case 3:
		return "UPDATE"
	case 4:
		return "DELETE"
	default:
		return "OTHER"
	}
}

func loadCursor() cursor {
	data, err := os.ReadFile(CursorFile)
	if err != nil {
		return cursor{}
	}
	var c cursor
	json.Unmarshal(data, &c)
	return c
}

func saveCursor(c cursor) {
	data, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(CursorFile, data, 0644)
}

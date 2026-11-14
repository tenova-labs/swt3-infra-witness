// Package modes: tail mode watches a directory for JSONL files containing
// AI telemetry and witnesses them through the SWT3 protocol.
//
// This is the passive sidecar mode: apps voluntarily write telemetry to a
// shared volume, the sidecar observes and witnesses. No traffic interception.
package modes

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tenova-labs/swt3-infra-witness/internal/canonical"
	"github.com/tenova-labs/swt3-infra-witness/internal/client"
	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
	"github.com/tenova-labs/swt3-infra-witness/internal/summary"
)

// Tail-mode metrics (Prometheus-compatible, zero dependencies).
var (
	tailFilesWatched  int64
	tailBytesRead     int64
	tailEventsTotal   int64
	tailErrorsTotal   int64
	tailBatchesSent   int64
	tailLastWitnessed int64
	tailLastLatencyMs int64
	tailStartTime     = time.Now()
)

// fileCursor tracks the byte offset for each watched file.
type fileCursor struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode,omitempty"` // detect rotation
}

// RunTail watches watchDir for JSONL files and witnesses AI telemetry events.
func RunTail(cfg client.Config, format, watchDir, cursorDir string, pollInterval time.Duration, metricsPort int, noCursor, dryRun bool) error {
	// Validate watch directory exists
	info, err := os.Stat(watchDir)
	if err != nil {
		return fmt.Errorf("watch directory %q: %w", watchDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("watch directory %q is not a directory", watchDir)
	}

	// Create cursor directory
	if !noCursor && cursorDir != "" {
		if err := os.MkdirAll(cursorDir, 0755); err != nil {
			return fmt.Errorf("create cursor dir %q: %w", cursorDir, err)
		}
	}

	c := client.New(cfg)
	cursors := make(map[string]fileCursor)

	// Load existing cursors
	if !noCursor && cursorDir != "" {
		cursors = loadTailCursors(cursorDir)
	}

	// Start metrics/health server
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                    true,
			"version":              client.Version,
			"mode":                 "tail",
			"watch_dir":            watchDir,
			"uptime_seconds":       int(time.Since(tailStartTime).Seconds()),
			"files_watched":        atomic.LoadInt64(&tailFilesWatched),
			"events_processed":     atomic.LoadInt64(&tailEventsTotal),
			"errors":               atomic.LoadInt64(&tailErrorsTotal),
			"last_witnessed_epoch": atomic.LoadInt64(&tailLastWitnessed),
		})
	})
	metricsMux.HandleFunc("/metrics", tailMetricsHandler(format, watchDir))

	if metricsPort > 0 {
		metricsAddr := fmt.Sprintf(":%d", metricsPort)
		go func() {
			if err := http.ListenAndServe(metricsAddr, metricsMux); err != nil {
				fmt.Fprintf(os.Stderr, "metrics server error: %v\n", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "swt3-infra-witness tail mode\n")
		fmt.Fprintf(os.Stderr, "  watching:  %s\n", watchDir)
		fmt.Fprintf(os.Stderr, "  poll:      %s\n", pollInterval)
		fmt.Fprintf(os.Stderr, "  metrics:   :%d/metrics\n", metricsPort)
		fmt.Fprintf(os.Stderr, "  health:    :%d/healthz\n", metricsPort)
	} else {
		fmt.Fprintf(os.Stderr, "swt3-infra-witness tail mode\n")
		fmt.Fprintf(os.Stderr, "  watching:  %s\n", watchDir)
		fmt.Fprintf(os.Stderr, "  poll:      %s\n", pollInterval)
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "  %s--dry-run: events will be parsed but not sent%s\n", bold, reset)
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\nShutting down gracefully...\n")
			if !noCursor && cursorDir != "" {
				saveTailCursors(cursorDir, cursors)
			}
			return nil

		case <-ticker.C:
			processed, errs := tailTick(c, cfg, format, watchDir, cursorDir, cursors, noCursor, dryRun)
			if processed > 0 {
				atomic.AddInt64(&tailEventsTotal, int64(processed))
				atomic.AddInt64(&tailBatchesSent, 1)
				atomic.StoreInt64(&tailLastWitnessed, time.Now().Unix())
			}
			if errs > 0 {
				atomic.AddInt64(&tailErrorsTotal, int64(errs))
			}
		}
	}
}

// tailTick scans the watch directory for new data and processes it.
func tailTick(c *client.Client, cfg client.Config, format, watchDir, cursorDir string, cursors map[string]fileCursor, noCursor, dryRun bool) (processed int, errors int) {
	entries, err := os.ReadDir(watchDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read dir %s: %v\n", watchDir, err)
		return 0, 1
	}

	var watchedCount int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".json") {
			continue
		}
		watchedCount++

		filePath := filepath.Join(watchDir, name)
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		cur := cursors[name]

		// Detect file rotation (inode changed or file shrunk)
		var inode uint64
		if sys, ok := info.Sys().(*syscall.Stat_t); ok {
			inode = sys.Ino
		}
		if cur.Inode != 0 && inode != 0 && cur.Inode != inode {
			// File was rotated -- restart from beginning
			cur = fileCursor{Inode: inode}
		}
		if info.Size() < cur.Offset {
			// File was truncated -- restart from beginning
			cur = fileCursor{Offset: 0, Inode: inode}
		}

		// No new data
		if info.Size() <= cur.Offset {
			continue
		}

		n, e := processFile(c, cfg, format, filePath, &cur, dryRun)
		cur.Inode = inode
		cursors[name] = cur
		processed += n
		errors += e
	}
	atomic.StoreInt64(&tailFilesWatched, watchedCount)

	// Persist cursors
	if !noCursor && cursorDir != "" && processed > 0 {
		saveTailCursors(cursorDir, cursors)
	}

	return processed, errors
}

// processFile reads new lines from a JSONL file starting at the cursor offset.
func processFile(c *client.Client, cfg client.Config, format, filePath string, cur *fileCursor, dryRun bool) (processed int, errors int) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", filePath, err)
		return 0, 1
	}
	defer f.Close()

	// Seek to cursor position
	if cur.Offset > 0 {
		if _, err := f.Seek(cur.Offset, 0); err != nil {
			fmt.Fprintf(os.Stderr, "seek %s: %v\n", filePath, err)
			return 0, 1
		}
	}

	var payloads []client.OCSFPayload
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024) // up to 1MB lines
	bytesRead := int64(0)

	for scanner.Scan() {
		line := scanner.Bytes()
		bytesRead += int64(len(line)) + 1 // +1 for newline

		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || trimmed[0] == '#' {
			continue // skip empty lines and comments
		}

		events, err := parseTelemetryLine(format, []byte(trimmed))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %sparse error%s in %s: %v\n", yellow, reset, filepath.Base(filePath), err)
			errors++
			continue
		}

		for _, e := range events {
			fields := canonical.FieldsFromEvent(e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region)
			hash := canonical.Hash(fields)
			sum := summary.Generate(e, cfg.ClearingLevel)
			p := c.BuildPayload(hash, sum, "ai-telemetry", e.Time, e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region, e.ActivityType)
			payloads = append(payloads, p)
		}
	}

	// Update cursor with bytes read (only complete lines)
	cur.Offset += bytesRead
	atomic.AddInt64(&tailBytesRead, bytesRead)

	if len(payloads) == 0 {
		return 0, errors
	}

	if dryRun {
		for _, p := range payloads {
			fmt.Fprintf(os.Stdout, "  %s+%s  %s  fp:%s%s%s\n",
				green, reset, p.Operation, dim, p.AnchorFingerprint, reset)
		}
		return len(payloads), errors
	}

	// Send batch
	batchStart := time.Now()
	receipts, err := c.Send(payloads)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %ssend error%s: %v\n", red, reset, err)
		return 0, errors + len(payloads)
	}
	atomic.StoreInt64(&tailLastLatencyMs, time.Since(batchStart).Milliseconds())

	witnessed := 0
	for _, r := range receipts {
		if r.OK && !r.Duplicate {
			witnessed++
		}
	}
	if witnessed > 0 {
		fmt.Fprintf(os.Stderr, "  %s%d witnessed%s from %s\n",
			green, witnessed, reset, filepath.Base(filePath))
	}

	return len(receipts), errors
}

// parseTelemetryLine routes a single JSON line to the appropriate parser.
func parseTelemetryLine(format string, data []byte) ([]extract.CanonicalEvent, error) {
	switch format {
	case "swt3":
		return extract.ParseSWT3Telemetry(data)
	case "otel":
		return extract.ParseOTelSpans(data)
	case "auto", "":
		// Auto-detect per line
		if extract.IsSWT3Telemetry(data) {
			return extract.ParseSWT3Telemetry(data)
		}
		if extract.IsOTelSpan(data) {
			return extract.ParseOTelSpans(data)
		}
		// Try SWT3 first as default for simple JSON
		events, err := extract.ParseSWT3Telemetry(data)
		if err == nil {
			return events, nil
		}
		return nil, fmt.Errorf("unrecognized telemetry format")
	default:
		return nil, fmt.Errorf("unsupported format for tail mode: %s (use swt3, otel, or auto)", format)
	}
}

// Prometheus metrics handler for tail mode.
func tailMetricsHandler(format, watchDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		uptimeSeconds := time.Since(tailStartTime).Seconds()

		fmt.Fprintf(w, "# HELP swt3_tail_files_watched Number of JSONL files currently being watched.\n")
		fmt.Fprintf(w, "# TYPE swt3_tail_files_watched gauge\n")
		fmt.Fprintf(w, "swt3_tail_files_watched %d\n", atomic.LoadInt64(&tailFilesWatched))

		fmt.Fprintf(w, "# HELP swt3_tail_bytes_read_total Total bytes read from watched files.\n")
		fmt.Fprintf(w, "# TYPE swt3_tail_bytes_read_total counter\n")
		fmt.Fprintf(w, "swt3_tail_bytes_read_total %d\n", atomic.LoadInt64(&tailBytesRead))

		fmt.Fprintf(w, "# HELP swt3_events_processed_total Total AI telemetry events processed.\n")
		fmt.Fprintf(w, "# TYPE swt3_events_processed_total counter\n")
		fmt.Fprintf(w, "swt3_events_processed_total %d\n", atomic.LoadInt64(&tailEventsTotal))

		fmt.Fprintf(w, "# HELP swt3_events_errors_total Total event processing errors.\n")
		fmt.Fprintf(w, "# TYPE swt3_events_errors_total counter\n")
		fmt.Fprintf(w, "swt3_events_errors_total %d\n", atomic.LoadInt64(&tailErrorsTotal))

		fmt.Fprintf(w, "# HELP swt3_batches_sent_total Total witness batches sent.\n")
		fmt.Fprintf(w, "# TYPE swt3_batches_sent_total counter\n")
		fmt.Fprintf(w, "swt3_batches_sent_total %d\n", atomic.LoadInt64(&tailBatchesSent))

		fmt.Fprintf(w, "# HELP swt3_last_witnessed_timestamp Unix timestamp of last successful witness.\n")
		fmt.Fprintf(w, "# TYPE swt3_last_witnessed_timestamp gauge\n")
		fmt.Fprintf(w, "swt3_last_witnessed_timestamp %d\n", atomic.LoadInt64(&tailLastWitnessed))

		fmt.Fprintf(w, "# HELP swt3_last_batch_latency_ms Latency of the last witness batch in milliseconds.\n")
		fmt.Fprintf(w, "# TYPE swt3_last_batch_latency_ms gauge\n")
		fmt.Fprintf(w, "swt3_last_batch_latency_ms %d\n", atomic.LoadInt64(&tailLastLatencyMs))

		fmt.Fprintf(w, "# HELP swt3_uptime_seconds Seconds since tail mode started.\n")
		fmt.Fprintf(w, "# TYPE swt3_uptime_seconds gauge\n")
		fmt.Fprintf(w, "swt3_uptime_seconds %.0f\n", uptimeSeconds)

		fmt.Fprintf(w, "# HELP swt3_info Static build information.\n")
		fmt.Fprintf(w, "# TYPE swt3_info gauge\n")
		fmt.Fprintf(w, "swt3_info{version=%q,mode=\"tail\",format=%q,watch_dir=%q} 1\n",
			client.Version, format, watchDir)
	}
}

// Cursor persistence
func loadTailCursors(cursorDir string) map[string]fileCursor {
	cursors := make(map[string]fileCursor)
	data, err := os.ReadFile(filepath.Join(cursorDir, "cursors.json"))
	if err != nil {
		return cursors
	}
	json.Unmarshal(data, &cursors)
	return cursors
}

func saveTailCursors(cursorDir string, cursors map[string]fileCursor) {
	data, _ := json.MarshalIndent(cursors, "", "  ")
	os.WriteFile(filepath.Join(cursorDir, "cursors.json"), data, 0644)
}

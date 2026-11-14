package modes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/tenova-labs/swt3-infra-witness/internal/canonical"
	"github.com/tenova-labs/swt3-infra-witness/internal/client"
	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
	"github.com/tenova-labs/swt3-infra-witness/internal/summary"
)

// Prometheus-compatible metrics (text exposition format, zero dependencies).
var (
	metricsEventsProcessed int64
	metricsEventsErrors    int64
	metricsBatchesSent     int64
	metricsDedupsSkipped   int64
	metricsLastWitnessedAt int64
	metricsLastLatencyMs   int64
	metricsStartTime       = time.Now()
)

// RunServer starts an HTTP server that receives CloudTrail events via webhook.
// If metricsPort > 0, /metrics is served on a separate port (red team #2).
func RunServer(cfg client.Config, format string, port int, metricsPort int) error {
	c := client.New(cfg)

	mux := http.NewServeMux()
	metricsMux := mux // default: same mux
	if metricsPort > 0 {
		metricsMux = http.NewServeMux() // separate mux for metrics
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		processed := atomic.LoadInt64(&metricsEventsProcessed)
		errors := atomic.LoadInt64(&metricsEventsErrors)
		lastWitness := atomic.LoadInt64(&metricsLastWitnessedAt)
		uptime := time.Since(metricsStartTime).Seconds()

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":                    true,
			"version":              client.Version,
			"mode":                 "server",
			"uptime_seconds":       int(uptime),
			"events_processed":     processed,
			"events_errors":        errors,
			"last_witnessed_epoch": lastWitness,
		})
	})

	metricsMux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		uptimeSeconds := time.Since(metricsStartTime).Seconds()

		fmt.Fprintf(w, "# HELP swt3_events_processed_total Total cloud audit events processed.\n")
		fmt.Fprintf(w, "# TYPE swt3_events_processed_total counter\n")
		fmt.Fprintf(w, "swt3_events_processed_total %d\n", atomic.LoadInt64(&metricsEventsProcessed))

		fmt.Fprintf(w, "# HELP swt3_events_errors_total Total event processing errors.\n")
		fmt.Fprintf(w, "# TYPE swt3_events_errors_total counter\n")
		fmt.Fprintf(w, "swt3_events_errors_total %d\n", atomic.LoadInt64(&metricsEventsErrors))

		fmt.Fprintf(w, "# HELP swt3_batches_sent_total Total witness batches sent to SWT3 endpoint.\n")
		fmt.Fprintf(w, "# TYPE swt3_batches_sent_total counter\n")
		fmt.Fprintf(w, "swt3_batches_sent_total %d\n", atomic.LoadInt64(&metricsBatchesSent))

		fmt.Fprintf(w, "# HELP swt3_dedup_skipped_total Total events skipped by deduplication.\n")
		fmt.Fprintf(w, "# TYPE swt3_dedup_skipped_total counter\n")
		fmt.Fprintf(w, "swt3_dedup_skipped_total %d\n", atomic.LoadInt64(&metricsDedupsSkipped))

		fmt.Fprintf(w, "# HELP swt3_last_witnessed_timestamp Unix timestamp of last successful witness.\n")
		fmt.Fprintf(w, "# TYPE swt3_last_witnessed_timestamp gauge\n")
		fmt.Fprintf(w, "swt3_last_witnessed_timestamp %d\n", atomic.LoadInt64(&metricsLastWitnessedAt))

		fmt.Fprintf(w, "# HELP swt3_last_batch_latency_ms Latency of the last witness batch in milliseconds.\n")
		fmt.Fprintf(w, "# TYPE swt3_last_batch_latency_ms gauge\n")
		fmt.Fprintf(w, "swt3_last_batch_latency_ms %d\n", atomic.LoadInt64(&metricsLastLatencyMs))

		fmt.Fprintf(w, "# HELP swt3_uptime_seconds Seconds since server start.\n")
		fmt.Fprintf(w, "# TYPE swt3_uptime_seconds gauge\n")
		fmt.Fprintf(w, "swt3_uptime_seconds %.0f\n", uptimeSeconds)

		fmt.Fprintf(w, "# HELP swt3_info Static build information.\n")
		fmt.Fprintf(w, "# TYPE swt3_info gauge\n")
		fmt.Fprintf(w, "swt3_info{version=%q,format=%q} 1\n", client.Version, format)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		batchStart := time.Now()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			atomic.AddInt64(&metricsEventsErrors, 1)
			http.Error(w, fmt.Sprintf(`{"error":"read body: %s"}`, err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var events []extract.CanonicalEvent
		switch format {
		case "cloudtrail":
			events, err = extract.ParseCloudTrail(body)
		case "azure":
			events, err = extract.ParseAzureActivity(body)
		case "gcp":
			events, err = extract.ParseGCPAudit(body)
		case "ocsf":
			events, err = extract.ParseOCSF(body)
		case "auto":
			events, err = extract.AutoDetect(body)
		default:
			atomic.AddInt64(&metricsEventsErrors, 1)
			http.Error(w, fmt.Sprintf(`{"error":"unsupported format: %s"}`, format), http.StatusBadRequest)
			return
		}
		if err != nil {
			atomic.AddInt64(&metricsEventsErrors, 1)
			http.Error(w, fmt.Sprintf(`{"error":"parse: %s"}`, err), http.StatusBadRequest)
			return
		}

		var payloads []client.OCSFPayload
		for _, e := range events {
			fields := canonical.FieldsFromEvent(e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region)
			hash := canonical.Hash(fields)
			sum := summary.Generate(e, cfg.ClearingLevel)
			p := c.BuildPayload(hash, sum, "cloudtrail", e.Time, e.Operation, e.Actor, e.Resource, e.Time, e.Status, e.Region, e.ActivityType)
			payloads = append(payloads, p)
		}

		receipts, err := c.Send(payloads)
		if err != nil {
			atomic.AddInt64(&metricsEventsErrors, int64(len(payloads)))
			http.Error(w, fmt.Sprintf(`{"error":"send: %s"}`, err), http.StatusBadGateway)
			return
		}

		// Update metrics
		atomic.AddInt64(&metricsEventsProcessed, int64(len(events)))
		atomic.AddInt64(&metricsBatchesSent, 1)
		atomic.StoreInt64(&metricsLastWitnessedAt, time.Now().Unix())
		atomic.StoreInt64(&metricsLastLatencyMs, time.Since(batchStart).Milliseconds())

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":       true,
			"count":    len(receipts),
			"receipts": receipts,
		})
	})

	addr := fmt.Sprintf(":%d", port)
	fmt.Fprintf(os.Stderr, "swt3-infra-witness server listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "  POST /          - receive cloud audit events\n")
	fmt.Fprintf(os.Stderr, "  GET  /healthz   - health check\n")

	// Red team #2: If metrics-port is set, serve /metrics on a separate port
	// so the webhook can be exposed via load balancer without leaking metrics.
	if metricsPort > 0 {
		metricsAddr := fmt.Sprintf(":%d", metricsPort)
		fmt.Fprintf(os.Stderr, "  GET  /metrics   - Prometheus metrics (port %d)\n", metricsPort)
		go func() {
			if err := http.ListenAndServe(metricsAddr, metricsMux); err != nil {
				fmt.Fprintf(os.Stderr, "metrics server error: %v\n", err)
			}
		}()
	} else {
		fmt.Fprintf(os.Stderr, "  GET  /metrics   - Prometheus metrics\n")
	}

	return http.ListenAndServe(addr, mux)
}

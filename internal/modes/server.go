package modes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tenova-labs/swt3-infra-witness/internal/canonical"
	"github.com/tenova-labs/swt3-infra-witness/internal/client"
	"github.com/tenova-labs/swt3-infra-witness/internal/extract"
	"github.com/tenova-labs/swt3-infra-witness/internal/summary"
)

// RunServer starts an HTTP server that receives CloudTrail events via webhook.
func RunServer(cfg client.Config, format string, port int) error {
	c := client.New(cfg)

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"version": client.Version,
			"mode":    "server",
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
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
			http.Error(w, fmt.Sprintf(`{"error":"unsupported format: %s"}`, format), http.StatusBadRequest)
			return
		}
		if err != nil {
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
			http.Error(w, fmt.Sprintf(`{"error":"send: %s"}`, err), http.StatusBadGateway)
			return
		}

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
	fmt.Fprintf(os.Stderr, "  POST /          - receive CloudTrail events\n")
	fmt.Fprintf(os.Stderr, "  GET  /healthz   - health check\n")
	return http.ListenAndServe(addr, mux)
}

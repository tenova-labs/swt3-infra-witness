// mock-receiver is a minimal HTTP server that mimics the SWT3 witness OCSF
// endpoint. All returned anchors carry the SWT3-MOCK- prefix.
//
// FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
//
// Usage:
//
//	go run ./cmd/mock-receiver/
//	go run ./cmd/mock-receiver/ --port 9999
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const mockPrefix = "SWT3-MOCK-"

var requestCount int64

type receipt struct {
	OK          bool   `json:"ok"`
	ProcedureID string `json:"procedure_id"`
	Verdict     string `json:"verdict"`
	SWT3Anchor  string `json:"swt3_anchor"`
	WitnessedAt string `json:"witnessed_at"`
	Mock        bool   `json:"mock"`
}

func main() {
	port := "9999"
	for i, arg := range os.Args[1:] {
		if arg == "--port" && i+1 < len(os.Args)-1 {
			port = os.Args[i+2]
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true, "mock": true, "version": "8.1.0",
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		n := atomic.AddInt64(&requestCount, 1)
		if n%100 == 0 {
			fmt.Fprintf(os.Stderr, "\n  *** THIS IS A MOCK SERVER. DO NOT USE IN PRODUCTION. (%d requests) ***\n\n", n)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"read body"}`, 400)
			return
		}
		defer r.Body.Close()

		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, 400)
			return
		}

		events, _ := data["events"].([]interface{})
		if events == nil {
			events = []interface{}{data}
		}

		now := time.Now().UTC()
		receipts := make([]receipt, 0, len(events))
		for _, ev := range events {
			em, _ := ev.(map[string]interface{})
			fp, _ := em["anchor_fingerprint"].(string)
			proc, _ := em["procedure_id"].(string)
			if proc == "" {
				proc = "INF-OCSF.1"
			}
			if fp == "" {
				fp = "000000000000"
			}
			receipts = append(receipts, receipt{
				OK:          true,
				ProcedureID: proc,
				Verdict:     "PASS",
				SWT3Anchor:  fmt.Sprintf("%s%s-PASS-%d-%s", mockPrefix, proc, now.Unix(), fp),
				WitnessedAt: now.Format(time.RFC3339),
				Mock:        true,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-SWT3-Mock", "true")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":       true,
			"count":    len(receipts),
			"receipts": receipts,
		})

		fmt.Fprintf(os.Stderr, "  [mock] %s %s -> %d events witnessed\n", r.Method, r.URL.Path, len(receipts))
	})

	fmt.Fprintf(os.Stderr, "\n  SWT3 Mock Receiver v8.1.0\n")
	fmt.Fprintf(os.Stderr, "  FOR TESTING ONLY. DO NOT USE IN PRODUCTION.\n")
	fmt.Fprintf(os.Stderr, "  All anchors carry %s prefix.\n\n", mockPrefix)
	fmt.Fprintf(os.Stderr, "  Listening on :%s\n\n", port)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

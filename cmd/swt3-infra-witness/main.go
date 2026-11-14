// swt3-infra-witness is a zero-dependency Go binary that reads cloud audit
// logs, extracts canonical fields, computes deterministic hashes, and sends
// the evidence to the SWT3 witness endpoint. Raw audit data never leaves the
// customer's environment.
//
// Usage:
//
//	swt3-infra-witness --mode cli --format cloudtrail --input events.json
//	swt3-infra-witness --mode server --port 8080
//
// Environment:
//
//	SWT3_API_KEY        (required) API key for the SWT3 endpoint
//	SWT3_ENDPOINT       (optional) Override endpoint URL
//	SWT3_CLEARING_LEVEL (optional) 0-3, default 1
//	SWT3_AGENT_ID       (optional) Binary instance identity
//	SWT3_SIGNING_KEY    (optional) HMAC-SHA256 signing key
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tenova-labs/swt3-infra-witness/internal/client"
	"github.com/tenova-labs/swt3-infra-witness/internal/modes"
)

const helpText = `swt3-infra-witness %s -- Infrastructure evidence for the SWT3 unified tree

  Reads cloud audit logs, extracts 6 canonical fields, computes deterministic
  hashes, and witnesses the evidence via the SWT3 protocol. Raw audit data
  never leaves your environment. Zero external dependencies.

USAGE:
  swt3-infra-witness --mode cli --format cloudtrail --input events.json
  swt3-infra-witness --mode cli --format cloudtrail --input events.json --dry-run
  swt3-infra-witness --mode server --port 8080
  swt3-infra-witness --mode tail --watch-dir /shared/swt3
  cat events.json | swt3-infra-witness --mode cli

MODES:
  cli       Read file or stdin, process, send, exit (default)
  server    HTTP webhook receiver (POST / and GET /healthz)
  tail      Watch directory for JSONL telemetry files (sidecar mode)
  pull      S3 bucket polling (Phase 2)
  lambda    AWS Lambda handler (Phase 2)

FLAGS:
  --mode           Execution mode: cli, server, tail (default: cli)
  --format         Input format: cloudtrail, azure, gcp, ocsf, swt3, otel, auto (default: auto)
  --input          Input file path, - for stdin (default: -)
  --port           HTTP port for server mode (default: 8080)
  --metrics-port   Separate port for /metrics endpoint (default: same as --port)
  --watch-dir      Directory to watch for JSONL files in tail mode (default: /var/log/swt3)
  --poll-interval  Seconds between directory scans in tail mode (default: 2)
  --cursor-dir     Directory for tail mode cursor files (default: .swt3-tail-cursors)
  --dry-run        Parse and hash events without sending to SWT3
  --no-cursor      Disable cursor file for CLI/tail dedup
  --version        Print version and exit

ENVIRONMENT:
  SWT3_API_KEY         (required) Your SWT3 API key (axm_*)
  SWT3_ENDPOINT        Witness endpoint URL
  SWT3_CLEARING_LEVEL  0-3 (default: 1)
  SWT3_AGENT_ID        Binary instance identity
  SWT3_SIGNING_KEY     HMAC-SHA256 signing key

QUICKSTART:
  # Cloud audit logs
  export SWT3_API_KEY=axm_live_xxx
  swt3-infra-witness --mode cli --format cloudtrail --input cloudtrail-events.json

  # AI telemetry sidecar (Kubernetes shared volume)
  swt3-infra-witness --mode tail --watch-dir /shared/swt3 --metrics-port 9091

DOCS:  https://sovereign.tenova.io/docs
`

func main() {
	mode := flag.String("mode", "cli", "")
	format := flag.String("format", "auto", "")
	input := flag.String("input", "-", "")
	port := flag.Int("port", 8080, "")
	metricsPort := flag.Int("metrics-port", 0, "")
	watchDir := flag.String("watch-dir", "/var/log/swt3", "")
	pollInterval := flag.Int("poll-interval", 2, "")
	cursorDir := flag.String("cursor-dir", ".swt3-tail-cursors", "")
	noCursor := flag.Bool("no-cursor", false, "")
	dryRun := flag.Bool("dry-run", false, "")
	version := flag.Bool("version", false, "")
	help := flag.Bool("help", false, "")
	flag.Usage = func() { fmt.Fprintf(os.Stderr, helpText, client.Version) }
	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stdout, helpText, client.Version)
		os.Exit(0)
	}
	if *version {
		fmt.Printf("swt3-infra-witness %s\n", client.Version)
		os.Exit(0)
	}

	cfg := client.Config{
		Endpoint:      envOr("SWT3_ENDPOINT", "https://sovereign.tenova.io/api/v1/witness/ocsf"),
		APIKey:        os.Getenv("SWT3_API_KEY"),
		ClearingLevel: envInt("SWT3_CLEARING_LEVEL", 1),
		AgentID:       envOr("SWT3_AGENT_ID", "swt3-infra-witness"),
		SigningKey:    os.Getenv("SWT3_SIGNING_KEY"),
	}

	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "error: SWT3_API_KEY environment variable is required")
		fmt.Fprintln(os.Stderr, "  Get your API key at https://sovereign.tenova.io/settings")
		os.Exit(1)
	}

	// Red team #5: Warn on non-production API keys
	// Production keys start with axm_open_, axm_live_, or axm_test_
	isNonProd := strings.HasPrefix(cfg.APIKey, "swt3_dev_") ||
		strings.HasPrefix(cfg.APIKey, "axm_dev_") ||
		strings.HasPrefix(cfg.APIKey, "axm_mock_") ||
		strings.Contains(cfg.APIKey, "REPLACE") ||
		strings.Contains(cfg.APIKey, "YOUR_KEY")
	if isNonProd {
		fmt.Fprintln(os.Stderr, "WARNING: Non-production API key detected. Anchors will NOT be persisted to the ledger.")
		fmt.Fprintln(os.Stderr, "  Get a real key at https://sovereign.tenova.io/signup")
	}

	var err error
	switch *mode {
	case "cli":
		err = modes.RunCLI(cfg, *format, *input, *noCursor, *dryRun)
	case "server":
		err = modes.RunServer(cfg, *format, *port, *metricsPort)
	case "tail":
		err = modes.RunTail(cfg, *format, *watchDir, *cursorDir,
			time.Duration(*pollInterval)*time.Second, *metricsPort, *noCursor, *dryRun)
	case "pull":
		fmt.Fprintln(os.Stderr, "Pull mode requires the aws build tag (Phase 2).")
		fmt.Fprintln(os.Stderr, "Use --mode cli or --mode server for Phase 1.")
		os.Exit(1)
	case "lambda":
		fmt.Fprintln(os.Stderr, "Lambda mode requires the aws build tag (Phase 2).")
		fmt.Fprintln(os.Stderr, "Use --mode cli or --mode server for Phase 1.")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s (supported: cli, server, tail)\n", *mode)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

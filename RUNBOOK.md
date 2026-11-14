# SWT3 Infrastructure Witness -- SRE Runbook

On-call reference for diagnosing and resolving common failure modes.

## Quick Diagnostics

```bash
# Is the witness running?
curl -s http://localhost:8080/healthz | jq .

# How many events processed?
curl -s http://localhost:8080/metrics | grep swt3_events_processed_total

# Any errors?
curl -s http://localhost:8080/metrics | grep swt3_events_errors_total

# Last witness timestamp (0 = never witnessed)
curl -s http://localhost:8080/metrics | grep swt3_last_witnessed_timestamp
```

---

## Failure: Lambda Function Timing Out

**Symptom**: CloudWatch logs show `Task timed out after X seconds`

**Causes**:
1. CloudTrail log file too large (> 50MB compressed)
2. Secrets Manager call slow on cold start
3. SWT3 endpoint unreachable from Lambda VPC

**Resolution**:
```bash
# Check message size in SQS
aws sqs get-queue-attributes --queue-url $QUEUE_URL \
  --attribute-names ApproximateNumberOfMessages

# Increase Lambda timeout (default 60s)
# In Terraform: lambda_timeout = 120

# Check if Lambda has internet access (required for SWT3 endpoint)
# Lambda in VPC needs NAT Gateway or VPC endpoint
```

**Escalation**: If messages consistently fail, they move to the DLQ after 3 retries. Check DLQ depth:
```bash
aws sqs get-queue-attributes --queue-url $DLQ_URL \
  --attribute-names ApproximateNumberOfMessages
```

---

## Failure: Anchors Not Appearing in Portal

**Symptom**: `swt3 status` shows no recent anchors, but infra-witness logs show events processed

**Causes**:
1. Non-production API key (swt3_dev_, axm_dev_, REPLACE_ME)
2. Wrong endpoint URL
3. API key expired or revoked
4. Network egress blocked (firewall, security group, NACL)

**Resolution**:
```bash
# Check API key prefix -- must be axm_open_* or axm_live_*
echo $SWT3_API_KEY | cut -c1-10

# Test endpoint connectivity
curl -s -o /dev/null -w "%{http_code}" https://sovereign.tenova.io/api/v1/health

# Check for non-production key warning in logs
# The binary prints "WARNING: Non-production API key detected" on startup

# Verify the endpoint env var
echo $SWT3_ENDPOINT
# Expected: https://sovereign.tenova.io/api/v1/witness/ocsf
```

---

## Failure: verify-chain Shows Gaps

**Symptom**: `swt3 verify-chain` reports missing entries or broken chain

**Causes**:
1. WAL file rotated (entries older than 5MB threshold are archived)
2. Disk full -- WAL writes failed silently
3. Process crashed between enqueue and flush
4. Clock skew between hosts (non-monotonic timestamps)

**Resolution**:
```bash
# Check WAL directory
ls -la /tmp/swt3-wal/

# Check disk space
df -h /tmp

# Check for timestamp regressions
swt3 verify-chain --json | jq '.timestamp_regressions'

# Check if entries are local-only vs server-signed
swt3 verify-chain --json | jq '{local: .local_only_count, server: .server_signed_count}'
```

**Note**: Local-only anchors prove contiguity (no gaps) but NOT authenticity (could be fabricated). Only server-signed anchors are auditor-verifiable.

---

## Failure: Secrets Manager Permission Denied

**Symptom**: Lambda logs show `AccessDeniedException` for `secretsmanager:GetSecretValue`

**Causes**:
1. IAM role missing the secrets policy
2. Secret ARN changed (rotated, different region)
3. KMS key policy doesn't grant Lambda role decrypt permission

**Resolution**:
```bash
# Verify the secret exists
aws secretsmanager describe-secret --secret-id swt3/api-key

# Verify the Lambda role has the policy
aws iam list-attached-role-policies --role-name swt3-witness-lambda

# Test access from the role
aws secretsmanager get-secret-value --secret-id swt3/api-key
```

---

## Failure: Mock Key in Production

**Symptom**: Events processed but nothing in the portal. Logs show "Non-production API key detected"

**Causes**:
1. docker-compose.dev.yml copied to production without changing the API key
2. .env file has placeholder value (swt3_dev_REPLACE_ME)
3. CI/CD pipeline missing the SWT3_API_KEY secret variable

**Resolution**:
```bash
# Check the key
echo $SWT3_API_KEY | head -c 15
# If it shows swt3_dev_, axm_dev_, or contains REPLACE: it's not a real key

# Get a real key
# https://sovereign.tenova.io/signup (free tier)
# Or check your team's Secrets Manager / Key Vault

# The binary will warn on startup -- check logs for:
# "WARNING: Non-production API key detected"
```

---

## Failure: DLQ Messages Accumulating

**Symptom**: CloudWatch alarm on DLQ depth, or manual check shows messages

**Causes**:
1. Malformed CloudTrail log files (corrupted S3 objects)
2. Oversized events exceeding Lambda memory
3. Persistent SWT3 endpoint errors (5xx)

**Resolution**:
```bash
# Check DLQ depth
aws sqs get-queue-attributes --queue-url $DLQ_URL \
  --attribute-names ApproximateNumberOfMessages

# Peek at a failed message
aws sqs receive-message --queue-url $DLQ_URL --max-number-of-messages 1

# Common fix: increase Lambda memory (default 128MB)
# In Terraform: lambda_memory = 256

# If SWT3 endpoint was temporarily down, redrive the DLQ:
# Move messages back to the main queue for reprocessing
```

---

## Failure: Metrics Endpoint Unreachable

**Symptom**: Prometheus scrape failures, Grafana dashboard empty

**Causes**:
1. Metrics on same port as webhook, but network policy blocks Prometheus
2. --metrics-port flag not set, metrics port not in scrape config
3. Pod/container restarted, new IP not in service discovery

**Resolution**:
```bash
# Check if metrics are on the main port
curl -s http://localhost:8080/metrics | head -5

# If using separate metrics port
curl -s http://localhost:9090/metrics | head -5

# For Kubernetes: check the service/endpoint
kubectl get endpoints -n swt3-system

# Verify Prometheus scrape config targets the right port
```

---

## Failure: EKS DaemonSet Not Scheduling

**Symptom**: `kubectl get ds -n swt3-system` shows 0 ready

**Causes**:
1. Node taint not tolerated (GPU nodes often have `nvidia.com/gpu:NoSchedule`)
2. RuntimeClassName not available on nodes
3. Insufficient resources (CPU/memory requests)

**Resolution**:
```bash
# Check DaemonSet status
kubectl describe ds -n swt3-system swt3-witness

# Check events for scheduling failures
kubectl get events -n swt3-system --sort-by='.lastTimestamp'

# Add GPU toleration in Terraform:
# tolerations = [{ key = "nvidia.com/gpu", operator = "Exists", effect = "NoSchedule" }]
```

---

## Failure: Tail Mode Not Processing Events

**Symptom**: Sidecar running but `swt3_tail_files_watched == 0` or `swt3_events_processed_total` not incrementing

**Causes**:
1. Shared volume not mounted (emptyDir missing from pod spec)
2. App writing to wrong directory (not `/shared/swt3/`)
3. App writing non-JSONL files (tail mode only reads `*.json` and `*.jsonl`)
4. Volume mounted read-only on the app side (cannot write)
5. Cursor ahead of file (file was truncated but cursor not reset)

**Resolution**:
```bash
# Check the sidecar healthz
kubectl exec deploy/my-app -c swt3-witness-sidecar -- wget -qO- http://localhost:9091/healthz

# Verify the watch directory has files
kubectl exec deploy/my-app -c swt3-witness-sidecar -- ls -la /shared/swt3/

# Check if the app is writing (run from the app container)
kubectl exec deploy/my-app -c my-app -- ls -la /shared/swt3/

# Check metrics for file count
kubectl exec deploy/my-app -c swt3-witness-sidecar -- wget -qO- http://localhost:9091/metrics | grep swt3_tail_files_watched

# If cursor is stale, delete cursor file (will re-process existing data -- server deduplicates)
kubectl exec deploy/my-app -c swt3-witness-sidecar -- rm -f /shared/swt3/.swt3-tail-cursors/cursors.json
```

**Common fix**: The app container must mount the volume as read-write. The sidecar mounts it as read-only. Check both volume mounts in the pod spec.

---

## Failure: Tail Mode High Error Rate

**Symptom**: `swt3_events_errors_total` increasing, "parse error" messages in logs

**Causes**:
1. App writing invalid JSON (missing commas, unquoted strings)
2. App writing non-telemetry JSON (no `model` field for SWT3 format, no `gen_ai.*` attributes for OTel format)
3. Binary data mixed with JSONL in the same file
4. Format flag mismatch (`--format otel` but app writes SWT3 simple JSON)

**Resolution**:
```bash
# Check sidecar logs for parse errors
kubectl logs deploy/my-app -c swt3-witness-sidecar | grep "parse error"

# Validate a telemetry line manually
echo '{"model":"gpt-4","tokens_in":100,"tokens_out":50,"latency_ms":500,"status":"ok"}' | python3 -m json.tool

# Use --format auto (default) to accept both SWT3 and OTel formats
# Only use --format swt3 or --format otel if you know the app only writes one format
```

---

## Health Check Reference

| Endpoint | Port | Auth | What It Checks |
|----------|------|------|----------------|
| GET /healthz | 8080 (server) or --metrics-port (tail) | None | Binary alive, uptime, event count, error count, files watched (tail) |
| GET /metrics | 8080 or --metrics-port | None | Prometheus counters, gauges, build info, tail-specific metrics |
| swt3 doctor | CLI | Config file | YAML valid, env vars set, profile valid, mock endpoint detection |
| swt3 verify-chain | CLI | None | WAL + handoff integrity, timestamps, Merkle roots |
| swt3 status | CLI | API key | Portal connectivity, recent anchor count |

---

## Escalation Path

1. **Self-service**: This runbook + `swt3 doctor --ci` + `swt3 verify-chain --json`
2. **Documentation**: https://sovereign.tenova.io/docs
3. **Engineering**: engineering@tenovaai.com

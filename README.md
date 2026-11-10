# swt3-infra-witness

**Infrastructure evidence for the SWT3 unified tree.**

AI agents are deploying cloud infrastructure autonomously. Pulumi Neo, StackGen Aiden, Claude Code, Terraform Cloud -- they all make API calls that change your environment. CloudTrail logs what happened. SWT3 already witnesses what your AI models decided. This binary connects the two: the same Merkle root that covers your AI inference now covers your infrastructure changes.

One tree. Both evidence streams. No competitor has this.

---

## v8.1.0 -- Hierarchical Milestone Merkle Trees

v8.0.0 put infrastructure evidence alongside AI inference evidence in a flat daily Merkle root. v8.1.0 gives that tree hierarchical structure. Infrastructure changes don't happen in isolation -- they happen in phases. A cloud migration has stages: provision networking, deploy compute, configure security, validate connectivity. An AI-driven deployment pipeline has ordered steps: scale cluster, deploy model, run canary, promote to production. Flat Merkle roots cannot express "the security group must be configured before the instance launches." Hierarchical milestone trees can.

**Why this matters for infrastructure witnessing:** When an AI agent orchestrates a multi-step deployment via Terraform or Pulumi, CloudTrail captures each API call independently. This binary already extracts canonical fields and witnesses each event. With hierarchical milestone trees, those infrastructure anchors now land inside ordered phases. The Phase 1 milestone "VPC created" and the Phase 1 milestone "security group configured" must both pass before the Phase 2 gate opens for "instance launched." A single three-tier Merkle proof says "networking was provisioned and secured before compute was deployed" -- not because a pipeline tool says so, but because the cryptographic structure enforces it. The proof spans from a single CloudTrail event leaf through its milestone, through its phase, to the structure root.

## How it works

```
CloudTrail JSON --> swt3-infra-witness --> 6 canonical fields --> SHA-256 --> SWT3 API
                                                                              |
                                                     Same ledger + Merkle tree as AI inference
```

The binary reads your CloudTrail events (raw JSON stays in your account), extracts 6 fields (operation, actor, resource, time, status, region), computes a deterministic canonical hash, generates a human-readable summary, and sends only the hash + summary to SWT3. Your audit data never leaves your environment.

Infrastructure anchors land in the same witness ledger and daily cryptographic commitment as your AI witness anchors. A single membership proof can now verify that a specific AI inference and a specific infrastructure change coexisted in the same cryptographic commitment.

## Quickstart

```bash
# 1. Build (zero dependencies, ~9MB static binary)
git clone https://github.com/tenova-labs/swt3-infra-witness
cd swt3-infra-witness
CGO_ENABLED=0 go build -o swt3-infra-witness ./cmd/swt3-infra-witness/

# 2. Verify parsing works (no API key needed, auto-detects format)
./swt3-infra-witness --dry-run --input sample-events/cloudtrail-sample.json
./swt3-infra-witness --dry-run --input sample-events/azure-activity-sample.json
./swt3-infra-witness --dry-run --input sample-events/gcp-audit-sample.json

# 3. Witness for real (auto-detects CloudTrail, Azure, GCP, or OCSF)
export SWT3_API_KEY=axm_live_xxx
./swt3-infra-witness --input your-audit-events.json
```

That's it. Three commands from zero to witnessed infrastructure evidence in your unified tree.

## Dry run

Verify the full pipeline (parse, extract, hash, summarize) without an API key or live endpoint:

```bash
./swt3-infra-witness --dry-run --input events.json
```

```
--dry-run: parsed 3 events, hashing verified

  1  RunInstances          Success  CREATE
     hash: 052b1b32ca03c99cb51d7e55...
     fp:   63bc4d83d6b9
     At 2026-10-31T14:22:07Z, arn:aws:iam::123:role/deploy called RunInstances on i-0abc123 in us-east-1 [Success]

  2  CreateSecurityGroup   Success  CREATE
     hash: 31fbcba6e665f971d22e667e...
     fp:   bb1bc4b4c21c

  3  DescribeInstances     Success  READ
     hash: a45516d962e486f0be6b100f...
     fp:   57615f9fd34e

3 events ready to witness. Remove --dry-run to send.
```

## Modes

| Mode | Use case | Command |
|------|----------|---------|
| **cli** | One-shot processing (CI/CD, cron, ad hoc) | `swt3-infra-witness --input events.json` |
| **server** | Webhook receiver (SIEM, EventBridge) | `swt3-infra-witness --mode server --port 8080` |
| **pull** | S3 bucket polling (Phase 2) | Coming |
| **lambda** | AWS Lambda handler (Phase 2) | Coming |

### CLI mode

Reads a CloudTrail JSON file (single event or `{"Records": [...]}` envelope), processes all events, sends to SWT3, exits. Maintains a cursor file (`.swt3-infra-cursor.json`) for dedup across runs.

```bash
# File input
swt3-infra-witness --input cloudtrail-events.json

# Stdin pipe (works with aws cli, jq, etc.)
aws cloudtrail lookup-events --output json | swt3-infra-witness --format cloudtrail

# Disable cursor (reprocess everything)
swt3-infra-witness --input events.json --no-cursor
```

### Server mode

Long-running HTTP server. POST CloudTrail JSON to `/`, get receipts back. Health check at `GET /healthz`.

```bash
swt3-infra-witness --mode server --port 8080
```

```bash
# Send events via curl
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d @cloudtrail-events.json
```

## Configuration

All configuration via environment variables (12-factor):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SWT3_API_KEY` | Yes | - | Your SWT3 API key (`axm_*`) |
| `SWT3_ENDPOINT` | No | `https://sovereign.tenova.io/api/v1/witness/ocsf` | Witness endpoint URL |
| `SWT3_CLEARING_LEVEL` | No | `1` | Evidence clearing level (0-3) |
| `SWT3_AGENT_ID` | No | `swt3-infra-witness` | Binary instance identity |
| `SWT3_SIGNING_KEY` | No | - | HMAC-SHA256 signing key |

## Canonical fields

Every cloud audit event is reduced to exactly 6 fields before hashing:

| Field | CloudTrail source | Example |
|-------|-------------------|---------|
| `operation` | `eventName` | `RunInstances` |
| `actor` | `userIdentity.arn` | `arn:aws:iam::123456789012:role/deploy-agent` |
| `resource` | `resources[0].ARN` | `arn:aws:ec2:us-east-1:123:instance/i-abc` |
| `time` | `eventTime` | `2026-10-31T14:22:07Z` |
| `status` | `errorCode` or `"Success"` | `Success` |
| `region` | `awsRegion` | `us-east-1` |

These 6 fields are sorted alphabetically, serialized to compact JSON (no HTML escaping), and hashed with SHA-256. The field set is pinned -- it does not change with OCSF schema evolution. The hash is identical regardless of which SIEM normalized the event.

## Clearing levels

The same 4-tier clearing system used for AI inference applies to infrastructure evidence:

| Level | What's retained | What's cleared |
|-------|----------------|----------------|
| **0** (Analytics) | Full summary, all fields | Nothing |
| **1** (Standard) | Full summary, actor hashed in observations | Raw actor identity |
| **2** (Sensitive) | Operation + status only | Actor, resource |
| **3** (Classified) | Canonical hash only | Everything human-readable |

## The unified tree

This is the entire point. Your daily Merkle root now covers:

- AI inference evidence (from the SWT3 SDK -- model decisions, guardrails, drift)
- Infrastructure evidence (from this binary -- CloudTrail API calls)

A single membership proof can verify that anchor X (an AI inference) and anchor Y (a CloudTrail event) were included in the same daily commitment. No other system on the market can produce this proof.

```
Daily Merkle Root
  |-- AI-INF.1 (model inference witnessed by SDK)
  |-- AI-GRD.1 (guardrail evaluation witnessed by SDK)
  |-- INF-OCSF.1 (RunInstances witnessed by this binary)  <-- NEW
  |-- INF-OCSF.1 (CreateSecurityGroup witnessed by this binary)  <-- NEW
  |-- Single root covers BOTH domains
```

## Anchor format

Infrastructure anchors follow the SWT3 anchor specification:

```
SWT3-E-VULTR-AUD-INF-OCSF.1-PASS-1730380800-63bc4d83d6b9
```

| Segment | Value | Meaning |
|---------|-------|---------|
| Protocol | `SWT3` | SWT3 protocol |
| Tier | `E` | Enclave deployment |
| Provider | `VULTR` | Infrastructure provider (where SWT3 runs) |
| UCT | `AUD` | Audit & Accountability domain |
| Procedure | `INF-OCSF.1` | Infrastructure OCSF Evidence |
| Verdict | `PASS` | Evidence recorded (always PASS) |
| Epoch | `1730380800` | Unix timestamp |
| Fingerprint | `63bc4d83d6b9` | 12-char SHA-256 truncation |

## Framework crosswalks

INF-OCSF.1 maps to:

| Framework | Control |
|-----------|---------|
| NIST 800-53 | AU-2, AU-3, AU-6, AU-12 |
| EU AI Act | Art. 12(1) |
| FedRAMP HIGH/MOD | AU-2, AU-3, AU-6, AU-12 |
| CMMC Level 2 | AU.L2-3.3.1 |
| NIST 800-171 | 3.3.1 |
| SOC 2 | CC7.2 |
| NIST AI RMF | GOVERN 1.7 |

## What this does NOT cover

Honest scope:

- Kubernetes mutations (`kubectl apply`) -- only if EKS audit logs forward to CloudTrail
- Direct SSH or database access -- not a cloud API call
- On-premises deployments -- no cloud audit log available
- CloudTrail data events (S3 object puts, Lambda invocations) -- require separate enablement
- DNS changes via non-cloud registrars
- IaC state manipulation (`terraform import`, `terraform state rm`)

## Multi-cloud roadmap

Phase 1 ships the CloudTrail adapter because every AWS customer has CloudTrail enabled by default. The binary's architecture is pluggable -- adding a cloud is a format adapter (~100 lines), not a rewrite. The canonical hash is cloud-agnostic: same 6 fields, same SHA-256, same anchor format regardless of which cloud produced the audit event.

| Cloud | Adapter | Status |
|-------|---------|--------|
| AWS CloudTrail | `cloudtrail` | Live |
| Azure Activity Log | `azure` | Live |
| GCP Cloud Audit Logs | `gcp` | Live |
| Any SIEM (OCSF-normalized) | `ocsf` | Live |

If your cloud isn't listed, the server mode (`--mode server`) accepts any JSON that maps to the 6 canonical fields. You can write a lightweight transform in your pipeline and POST to the binary.

## Architecture

```
Your AWS Account                          SWT3 Witness System
+----------------------------------+      +-------------------------+
|                                  |      |                         |
|  CloudTrail --> S3 --> JSON      |      |  POST /api/v1/witness/  |
|                  |               |      |       ocsf              |
|     swt3-infra-witness           |      |         |               |
|       |                          |      |   Fingerprint re-derive |
|   Parse CloudTrail JSON          |      |   Canonical hash verify |
|   Extract 6 canonical fields     |      |   Idempotency check     |
|   SHA-256 canonical hash         |      |   Mint SWT3 anchor      |
|   Generate event summary         |  --> |   Write to ledger       |
|   Compute fingerprint            |      |   Merkle tree inclusion |
|       |                          |      |   Webhook dispatch      |
|   Send hash + summary ONLY       |      |         |               |
|   (raw data stays here)          |      |   Same Merkle root as   |
|                                  |      |   AI inference anchors  |
+----------------------------------+      +-------------------------+
```

## Docker

```bash
docker build -t swt3-infra-witness .
docker run -e SWT3_API_KEY=axm_live_xxx swt3-infra-witness --mode server
```

Image: ~7MB (distroless base + static Go binary).

## Zero dependencies

The binary uses only Go standard library. No external modules. `go.mod` has zero `require` statements. The fingerprint formula is inlined from the SWT3 Go SDK -- it is locked and verified against cross-language test vectors (Python, TypeScript, Rust, C#, Ruby, Swift, Go all produce identical hashes).

## License

Apache-2.0. Patent pending.

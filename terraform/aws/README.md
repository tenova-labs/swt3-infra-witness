# SWT3 Infrastructure Witness -- AWS Terraform Module

**Status: Phase 2 -- Do not deploy yet.**

This directory will contain the Terraform/OpenTofu module for automated
CloudTrail evidence collection via AWS Lambda.

For Phase 1, use the CLI or server mode:

```bash
# CLI mode (one-shot, CI/CD pipelines)
export SWT3_API_KEY=axm_live_xxx
swt3-infra-witness --mode cli --format cloudtrail --input ./cloudtrail-events.json

# Server mode (webhook receiver)
swt3-infra-witness --mode server --port 8080
```

## Phase 2 Module (Coming)

```hcl
module "swt3_witness" {
  source            = "tenova-labs/infra-witness/aws"
  version           = "1.0.0"
  swt3_api_key      = var.swt3_api_key
  cloudtrail_bucket = aws_cloudtrail.main.s3_bucket_name
}
```

Provisions: Lambda (container image) + SQS queue + S3 event notification + IAM role (least privilege).

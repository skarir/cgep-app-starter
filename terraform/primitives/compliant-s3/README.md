# compliant-s3

This module enforces SC-28, AU-3, AU-6, CM-6, and AC-3 on a single AWS S3 bucket by enabling AES-256 server-side encryption at rest, versioning, full public-access blocking, required compliance tags on every resource, and server access logging to a dedicated log bucket.

## Controls

| Control       | Implementation |
|---------------|----------------|
| SC-28         | `aws_s3_bucket_server_side_encryption_configuration` — AES256 SSE on both primary and log buckets |
| AC-3          | `aws_s3_bucket_public_access_block` — all four flags `true` on both buckets |
| CM-6          | `provider.default_tags` — Project, Environment, ManagedBy, ComplianceScope applied to every resource |
| AU-3 / AU-6   | `aws_s3_bucket_logging` — access logs streamed to a dedicated log bucket |

## Usage

```hcl
module "compliant_s3" {
  source       = "./terraform/primitives/compliant-s3"
  project_name = "cgep-lab"
  environment  = "dev"
}
```

## Inputs

| Name           | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `project_name` | string | yes      | Short identifier; part of bucket names and the Project tag |
| `environment`  | string | yes      | One of `dev`, `staging`, `prod` |
| `bucket_suffix`| string | no       | Override the random suffix; must be globally unique |

## Outputs

| Name                  | Description |
|-----------------------|-------------|
| `bucket_name`         | Primary bucket name |
| `bucket_arn`          | Primary bucket ARN |
| `log_bucket_arn`      | Log bucket ARN |
| `encryption_algorithm`| SSE algorithm in use (SC-28 attestation) |

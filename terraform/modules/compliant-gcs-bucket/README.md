# compliant-gcs-bucket

Terraform module that enforces **SC-12, SC-13, SC-28, AU-11, CM-6, and AC-3** on a single GCS bucket. Security controls are hardcoded inside the module body — consumers set only business inputs (project, environment, retention duration).

## Controls

| Control | NIST Family | Implementation |
|---|---|---|
| **SC-12** | System & Comms Protection | `google_kms_key_ring` + `google_kms_crypto_key` — customer-managed key, not Google-managed |
| **SC-13** | System & Comms Protection | `google_storage_bucket.encryption.default_kms_key_name` — CMEK enforced on all objects |
| **SC-28** | System & Comms Protection | CMEK means no plaintext storage path exists; satisfies protection of information at rest |
| **AC-3** | Access Control | `uniform_bucket_level_access = true` + `public_access_prevention = "enforced"` |
| **CM-6** | Configuration Management | `locals.required_labels` merged via `merge()` — consumers cannot suppress the four tags |
| **AU-11** | Audit & Accountability | `versioning.enabled = true` + `retention_policy.retention_period` (configurable, prod ≥ 365 d) |

## Usage

```hcl
module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "my-gcp-project"
  project_label      = "cgep-lab"
  environment        = "dev"
  retention_days     = 30
  bucket_name_suffix = "dev-data-001"
}

output "attestation" { value = module.data_bucket.compliance_attestation }
```

## Inputs

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `gcp_project` | string | yes | — | GCP project ID |
| `project_label` | string | yes | — | Short identifier (3-21 chars, lowercase) |
| `environment` | string | yes | — | One of `dev`, `staging`, `prod` |
| `retention_days` | number | yes | — | Retention in days (prod requires ≥ 365) |
| `bucket_name_suffix` | string | yes | — | Globally-unique suffix |
| `location` | string | no | `us-central1` | GCS bucket location |
| `kms_location` | string | no | `us-central1` | KMS keyring location (single-region only) |
| `labels` | map(string) | no | `{}` | Extra labels; compliance labels always override |

## Outputs

| Name | Description |
|---|---|
| `bucket_url` | `gs://` URL |
| `bucket_self_link` | Self-link for GCP resource references |
| `kms_key_id` | CMEK resource ID |
| `compliance_attestation` | Map of all enforced control values |

## Key design decisions

- **Two location variables** — GCS accepts multi-region names (`US`, `EU`); KMS does not. Splitting prevents a confusing `KMS_RESOURCE_NOT_FOUND_IN_LOCATION` error.
- **`merge(var.labels, local.required_labels)`** — required labels are the second argument so they always win, even if a consumer passes the same key.
- **`depends_on` on the bucket** — ensures the KMS IAM binding is in place before bucket creation; avoids a race where the first object write fails with a permission error.

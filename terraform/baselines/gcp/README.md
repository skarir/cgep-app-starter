# gcp-security-baseline

Terraform module that deploys GCP's identity-first security baseline for the CGE-P capstone. Three controls, all preventative or audit-generating, all off by default in a new GCP project.

## Controls

| File | Control | NIST 800-53 | What it enforces |
|---|---|---|---|
| `org_policy.tf` | `storage.uniformBucketLevelAccess` | CM-6 | Buckets must use IAM-only access; per-object ACLs are rejected at the API |
| `org_policy.tf` | `iam.disableServiceAccountKeyCreation` | AC-2 | Long-lived JSON key creation is REJECTED — use WIF instead |
| `org_policy.tf` | `compute.requireOsLogin` | AC-3 | SSH to Compute Engine tied to IAM principals, not metadata keys |
| `wif.tf` | Workload Identity Federation | AC-2 | GitHub Actions authenticates via OIDC → short-lived token, no key on disk |
| `audit_logs.tf` | Data Access audit logs | AU-2, AU-12 | Storage, KMS, IAM DATA_READ/WRITE/ADMIN_READ logged (off by default in GCP) |

## Key lesson: Data Access logs are OFF by default

This is the #1 GCP audit finding. A new GCP project logs admin activity (resource creation/deletion) but **not** data plane operations (object reads, KMS decrypts, IAM lookups). This module turns them on for the three services that matter most for a PHI workload.

## Usage

```bash
cd terraform/baselines/gcp
terraform init
terraform apply -auto-approve
```

## WIF — no service account JSON keys

After apply, GitHub Actions can authenticate to GCP using:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: ${{ steps.tf.outputs.wif_provider }}
      service_account: cgep-grc-gate-sa@cgep-lab-sunil-2026.iam.gserviceaccount.com
```

The `attribute_condition` in `wif.tf` restricts this provider to `skarir/cgep-app-starter` only. Any other repo's token is rejected.

## Verify Org Policy enforcement

```bash
# Confirm policies are in effect
gcloud org-policies list --project=cgep-lab-sunil-2026

# Attempt a forbidden action — should fail with FAILED_PRECONDITION
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account=cgep-grc-gate-sa@cgep-lab-sunil-2026.iam.gserviceaccount.com \
  --project=cgep-lab-sunil-2026
```

## Cleanup

```bash
terraform destroy -auto-approve
```

Note: WIF pools enter a 30-day soft-delete state and cannot be re-created with the same ID until expired.

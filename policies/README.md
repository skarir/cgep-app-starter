# Compliance Policies (Rego / OPA)

GCP-focused OPA policies for the CGE-P capstone. Each policy maps to a NIST 800-53 control, fires a deny message that names both the resource address and the control ID, and ships with a `_test.rego` file covering at least one passing and one failing fixture.

## Running the suite

```bash
# All tests (must be PASS: N/N)
opa test -v policies/ policies/tests/

# Evaluate against a real plan
opa eval -d policies -i terraform/lab-3-3/plan.json data.compliance.sc28.deny --format=pretty
opa eval -d policies -i terraform/lab-3-3/plan.json data.compliance.ac3.deny  --format=pretty
opa eval -d policies -i terraform/lab-3-3/plan.json data.compliance.cm6.deny  --format=pretty
```

## Policy inventory

### GCP policies (`google_*` resource types)

| File | Package | Control | Cloud | Severity | What it checks |
|---|---|---|---|---|---|
| `sc28_encryption.rego` | `compliance.sc28` | **SC-28** | GCP | High | Every `google_storage_bucket` must have an `encryption { default_kms_key_name }` block pointing to a CMEK. |
| `ac3_no_public.rego` | `compliance.ac3` | **AC-3** | GCP | Critical | Buckets must have `uniform_bucket_level_access=true` + `public_access_prevention="enforced"`. Firewalls must not expose ports 22 or 3389 to `0.0.0.0/0`. |
| `cm6_required_tags.rego` | `compliance.cm6` | **CM-6** | GCP | Medium | Every labelable GCP resource must carry the four required labels: `project`, `environment`, `managed_by`, `compliance_scope`. |

### AWS policies (`aws_*` resource types)

| File | Package | Control | Cloud | Severity | What it checks |
|---|---|---|---|---|---|
| `sc28_encryption_aws.rego` | `compliance.sc28_aws` | **SC-28** | AWS | High | Every `aws_s3_bucket` must have a matching `aws_s3_bucket_server_side_encryption_configuration`. Matched by reference (not value) because bucket names are unknown at plan time. |
| `ac3_no_public_aws.rego` | `compliance.ac3_aws` | **AC-3** | AWS | Critical | Every `aws_s3_bucket` must have a matching `aws_s3_bucket_public_access_block` with all four flags set to `true`. |
| `cm6_required_tags_aws.rego` | `compliance.cm6_aws` | **CM-6** | AWS | Medium | Every taggable AWS resource must carry the four required tags: `Project`, `Environment`, `ManagedBy`, `ComplianceScope`. Reads `tags_all` (provider `default_tags` merged) first, falls back to `tags`. |

## Remediation guidance

### SC-28 — Missing CMEK
```hcl
resource "google_storage_bucket" "example" {
  encryption { default_kms_key_name = google_kms_crypto_key.key.id }
}
```

### AC-3 — Public bucket
```hcl
resource "google_storage_bucket" "example" {
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
```

### AC-3 — Open management port
Narrow the firewall `source_ranges` to a known CIDR or remove the rule entirely.

### CM-6 — Missing labels
```hcl
labels = {
  project          = "your-project"
  environment      = "dev"          # or staging / prod
  managed_by       = "terraform"
  compliance_scope = "cge-p-lab"
}
```

## How this feeds the capstone

- **Lab 4.x** — these policies run as a Conftest gate in GitHub Actions: every PR that touches `terraform/` must pass `conftest test --policy policies/` before Terraform apply is permitted.
- **Lab 6** — the OSCAL Component Definition cites `policies/sc28_encryption.rego` etc. as the implementation of SC-28/AC-3/CM-6, and links to `evidence/lab-3-3/opa-test-results.json` as the test evidence.

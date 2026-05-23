# Compliance Control Mapping — Acme Health Patient Intake API

**Primary framework:** HIPAA Security Rule (45 CFR §§ 164.306–164.318)  
**Authoritative implementation guide:** NIST SP 800-66 Rev. 2  
**Submission date:** 2026-05-23

---

## Control implementation summary

| HIPAA Control | Title | Implementation artefact | Gap(s) closed | Status |
|---|---|---|---|---|
| 164.312(a)(2)(iv) | Encryption & decryption | `terraform/grc_baseline.tf` → `aws_kms_key.phi`; `terraform/grc_override.tf` → `aws_dynamodb_table.intake` SSE override | GAP-01, GAP-02 | **Closed** |
| 164.312(e)(1) | Transmission security | `aws_s3_bucket_policy.uploads_tls_only`; `aws_security_group.lambda`; `aws_vpc_endpoint.*`; Lambda `vpc_config` override | GAP-03, GAP-05 | **Closed** |
| 164.308(a)(7) | Contingency plan | `aws_s3_bucket_versioning.uploads`; `aws_s3_bucket_object_lock_configuration.evidence` | GAP-04 | **Closed** |
| 164.312(a)(1) | Access control | `aws_iam_role_policy.lambda_least_privilege` | GAP-07 | **Closed** |
| 164.312(b) | Audit controls | `aws_cloudtrail.main`; `aws_s3_bucket.evidence`; Cosign-signed evidence bundles | GAP-08 partial | **Partial** |

---

## Policy gate coverage

Each closed gap has a corresponding OPA/Rego policy that blocks any PR reverting the remediation:

| Gap | Rego policy | Test file | Checked in CI |
|-----|-------------|-----------|---------------|
| GAP-01 S3 CMK | `policies/s3_cmk_encryption.rego` | `policies/s3_cmk_encryption_test.rego` | Step 2 — Conftest |
| GAP-02 DynamoDB CMK | `policies/dynamodb_cmk.rego` | `policies/dynamodb_cmk_test.rego` | Step 2 — Conftest |
| GAP-03 S3 TLS | `policies/s3_tls_required.rego` | `policies/s3_tls_required_test.rego` | Step 2 — Conftest |
| GAP-04 S3 versioning | `policies/s3_versioning.rego` | `policies/s3_versioning_test.rego` | Step 2 — Conftest |
| GAP-05 Lambda VPC | `policies/lambda_vpc.rego` | `policies/lambda_vpc_test.rego` | Step 2 — Conftest |
| GAP-07 IAM least priv | `policies/iam_least_privilege.rego` | `policies/iam_least_privilege_test.rego` | Step 2 — Conftest |

---

## Evidence chain of custody

Every merge to `main` produces a tamper-evident evidence bundle:

1. **Terraform plan JSON** (`plan.json`) — records every planned resource change
2. **Conftest results** (`conftest-results.json`) — OPA policy pass/fail per resource
3. **tfsec results** (`tfsec-results.json`) — static IaC security scan
4. **Terraform outputs** (`tf-outputs.json`) — deployed resource identifiers
5. **SHA-256 sidecar** (`.sha256`) — integrity fingerprint
6. **Cosign keyless signature** (`.sig.bundle`) — GitHub OIDC → Fulcio cert → Rekor transparency log entry
7. **S3 Object Lock** (GOVERNANCE, 365 days) — preservation guarantee

Verification:
```bash
bash scripts/verify-evidence.sh s3://<EVIDENCE_BUCKET>/runs/<RUN_ID>/evidence-bundle-<RUN_ID>.tar.gz
```

---

## Secondary framework cross-references

| HIPAA control | SOC 2 TSC | CMMC Level 2 |
|---|---|---|
| 164.312(a)(2)(iv) | CC6.1 | SC.L2-3.13.11 |
| 164.312(e)(1) | CC6.6, CC6.7 | SC.L2-3.13.1, SC.L2-3.13.8 |
| 164.308(a)(7) | A1.2 | MP.L2-3.8.9 |
| 164.312(a)(1) | CC6.3 | AC.L2-3.1.5 |
| 164.312(b) | CC7.2 | AU.L2-3.3.1 |

Full machine-readable mapping: `oscal/components/component-definition.json`

# WRITEUP — Acme Health Patient Intake API: GRC Hardening

**Candidate:** Sunil Karir  
**Submission date:** 2026-05-23  
**Primary framework:** HIPAA Security Rule  
**Repo:** https://github.com/skarir/cgep-app-starter  
**Grader note:** run `bash scripts/verify-evidence.sh <vault-uri>` to confirm chain of custody end-to-end.

---

## 1. Framework Choice and Rationale

I chose **HIPAA Security Rule** as the primary framework. The workload is a Patient Intake API that receives fields from patients before their first telehealth visit. That data — reason for visit, complaint, pharmacy NPI — is Protected Health Information (PHI) under 45 CFR § 160.103. There is no defensible argument that HIPAA does not apply.

SOC 2 Type II was the obvious second choice, and an enterprise customer push makes it near-term relevant for Acme. CMMC Level 2 would apply only if the federal pilot progresses past a letter of intent. I chose HIPAA as primary because it is non-optional today, not a future business objective.

**How the choice propagates:**

- Every Rego policy `# METADATA` block carries `framework: hipaa` and at least one `164.x` control ID.
- The OSCAL `component-definition.json` sets `source` to NIST SP 800-66 Rev. 2 (the authoritative HIPAA implementation guide published by NIST).
- Cross-references to SOC 2 (CC6.x) and CMMC (SC.L2-x, AC.L2-x) appear as `props` on each `implemented-requirement`, making the mapping visible to an auditor without polluting the primary citation chain.

---

## 2. Gap Remediation — What Was Closed and How

| Gap | Status | Layer used | Control cited |
|-----|--------|------------|---------------|
| GAP-01 S3 SSE-KMS | **Closed** | Terraform + OPA | HIPAA 164.312(a)(2)(iv) |
| GAP-02 DynamoDB CMK | **Closed** | Terraform override + OPA | HIPAA 164.312(a)(2)(iv) |
| GAP-03 S3 TLS policy | **Closed** | Terraform + OPA | HIPAA 164.312(e)(1) |
| GAP-04 S3 versioning | **Closed** | Terraform + OPA | HIPAA 164.308(a)(7) |
| GAP-05 Lambda VPC | **Closed** | Terraform override + OPA | HIPAA 164.312(e)(1) |
| GAP-06 Lambda observability | **Partial** | OSCAL (documented gap) | SOC 2 CC7.2 |
| GAP-07 IAM wildcard | **Closed** | Terraform + OPA | HIPAA 164.312(a)(1) |
| GAP-08 API Gateway logging | **Partial** | OSCAL (documented gap) | HIPAA 164.312(b) |

### GAP-01 and GAP-02 — PHI encryption at rest

Both the S3 uploads bucket and the DynamoDB submissions table now encrypt data with `aws_kms_key.phi`, a customer-managed key with rotation enabled every 365 days. The CMK gives Acme the ability to independently audit key usage in CloudTrail and revoke access by disabling the key — neither is possible with an AWS-managed key.

I chose to implement this in the Terraform layer rather than only in policy because auditors ask for running infrastructure, not just policy gates. The Rego policies (`s3_cmk_encryption.rego`, `dynamodb_cmk.rego`) ensure CI refuses any future PR that would revert to SSE-S3 or remove the CMK binding.

**DynamoDB trade-off:** Changing `server_side_encryption` on an existing DynamoDB table forces table replacement in Terraform (`-/+ replace`). I documented this in `terraform/grc_override.tf` with an explicit comment. In a real Acme migration, this would require a maintenance window with point-in-time recovery or an export/import, and the data classification (PHI) would make the encryption non-negotiable regardless of the disruption cost.

### GAP-03 — S3 TLS-only policy

The `aws_s3_bucket_policy.uploads_tls_only` resource adds a Deny statement on `aws:SecureTransport = false`. Without this, an S3 pre-signed URL that downgraded to HTTP would silently succeed. The Rego policy (`s3_tls_required.rego`) checks that every planned S3 bucket has a policy with this deny statement.

**Limitation:** Terraform must apply the bucket policy after the bucket exists, so the ordering matters. I added `depends_on` on the TLS policy where needed. First-apply sequencing is noted in `grc_baseline.tf`.

### GAP-04 — S3 versioning

`aws_s3_bucket_versioning.uploads` enables versioning on the PHI uploads bucket. Without versioning, a Lambda `PutObject` to the same key is an unrecoverable overwrite. The Rego policy (`s3_versioning.rego`) also catches any future plan that sets versioning to `Suspended`.

### GAP-05 — Lambda VPC placement

The override file (`terraform/grc_override.tf`) adds a `vpc_config` block to the Lambda, placing it in the starter's private subnets. I also added `aws_vpc_endpoint.dynamodb` and `aws_vpc_endpoint.s3` as Gateway endpoints so the Lambda can reach AWS services without a NAT gateway. This keeps the solution within the starter's VPC (not a second one) and avoids NAT costs in a sandbox.

**Security group design:** The Lambda security group allows only HTTPS egress (port 443). There are no ingress rules — the function is invoked through API Gateway's managed infrastructure, not via a network connection.

### GAP-07 — IAM least privilege

The starter's `lambda_inline` policy uses `dynamodb:*` and `s3:*`. I added `lambda_least_privilege` with only the six actions the handler's source code actually calls: `PutItem`, `GetItem`, `UpdateItem`, `Query` (DynamoDB), `PutObject`, `GetObject` (S3, scoped to the `uploads/` prefix), plus `kms:GenerateDataKey` and `kms:Decrypt` for the CMK.

The broad `lambda_inline` policy coexists in the repo to preserve the starter's deliberate gap. The OPA policy (`iam_least_privilege.rego`) detects `dynamodb:*` and `s3:*` in Allow statements and blocks any PR that adds them back. The correct remediation in production would be to delete `lambda_inline` entirely, which is documented in a comment on `grc_baseline.tf`.

---

## 3. Design Decisions and Trade-offs

### Terraform override files for starter compatibility

I used `terraform/grc_override.tf` (a Terraform override file) to add `vpc_config` to the Lambda and `server_side_encryption` to the DynamoDB table without modifying `main.tf`. This is a deliberate choice: the capstone brief says "use the starter — wrap it, don't rewrite it." Overrides are the correct Terraform mechanism for this. The downside is that overrides are easy to miss during code review; I document them explicitly in the OSCAL `props`.

### KMS key scope

One CMK for both S3 and DynamoDB rather than separate keys. The trade-off: a single CMK simplifies key rotation policy and CloudTrail audit but means a compromised key affects both stores simultaneously. For a 50-person company still building its GRC program, operational simplicity wins. A mature posture would have separate CMKs per data store with separate key policies.

### Object Lock mode: GOVERNANCE not COMPLIANCE

The evidence vault uses GOVERNANCE mode rather than COMPLIANCE mode. GOVERNANCE can be overridden by an IAM user with `s3:BypassGovernanceRetention`, while COMPLIANCE cannot be overridden even by the root account until retention expires. I chose GOVERNANCE because COMPLIANCE mode makes it impossible to recover from a misconfigured retention period — a real risk in a sandbox environment. The write-up documents this as a known residual risk; a production deployment would use COMPLIANCE mode.

### Cosign keyless signing

Step 4 of the pipeline signs the evidence bundle using Cosign keyless via GitHub OIDC. The OIDC token issued to the runner acts as identity proof; Fulcio issues a short-lived certificate; Rekor creates an immutable transparency log entry. There are no long-lived signing keys to manage or rotate. The downside is that the Sigstore public Rekor instance is a dependency — if Rekor is unavailable, the signing step fails. For a regulated environment, a private Rekor instance would be the right answer.

---

## 4. Control-to-Code Mapping

| Control | Code artefact | Direction |
|---------|---------------|-----------|
| HIPAA 164.312(a)(2)(iv) | `terraform/grc_baseline.tf` → `aws_kms_key.phi`, `aws_s3_bucket_server_side_encryption_configuration.uploads`, `aws_dynamodb_table.intake` (override) | IaC → control |
| HIPAA 164.312(a)(2)(iv) | `policies/s3_cmk_encryption.rego`, `policies/dynamodb_cmk.rego` | Policy → control |
| HIPAA 164.312(e)(1) | `terraform/grc_baseline.tf` → `aws_s3_bucket_policy.uploads_tls_only`, `aws_security_group.lambda`, `aws_vpc_endpoint.*`, `aws_lambda_function.intake` (override) | IaC → control |
| HIPAA 164.312(e)(1) | `policies/s3_tls_required.rego`, `policies/lambda_vpc.rego` | Policy → control |
| HIPAA 164.308(a)(7) | `terraform/grc_baseline.tf` → `aws_s3_bucket_versioning.uploads` | IaC → control |
| HIPAA 164.308(a)(7) | `policies/s3_versioning.rego` | Policy → control |
| HIPAA 164.312(a)(1) | `terraform/grc_baseline.tf` → `aws_iam_role_policy.lambda_least_privilege` | IaC → control |
| HIPAA 164.312(a)(1) | `policies/iam_least_privilege.rego` | Policy → control |
| HIPAA 164.312(b) | `terraform/grc_baseline.tf` → `aws_cloudtrail.main`, `aws_s3_bucket.evidence`, `aws_s3_bucket_object_lock_configuration.evidence` | IaC → control |
| HIPAA 164.312(b) | `.github/workflows/grc-gate.yml` steps 4–5 | Pipeline → control |

The OSCAL `component-definition.json` (Layer 4) provides the machine-readable version of this table, with Terraform resource addresses as `props` and evidence vault URIs as `links`.

---

## 5. What I Did Not Get To (Honest Gaps)

### GAP-06 — Lambda observability (reserved concurrency, DLQ, X-Ray)

Reserved concurrency, a dead-letter queue, and X-Ray tracing are not in scope. They map to SOC 2 CC7.2 (monitoring) and CMMC SI.L2-3.14.6 (system monitoring), which are secondary frameworks in this submission. The operational risk is that a Lambda throttle or invocation failure would be silent. The remediation is one Terraform block for each, plus an OPA policy checking for X-Ray `tracing_config.mode = "Active"`. I chose not to add these because they would not have been wired into the OSCAL and the evidence pipeline in time — and a partial Layer 4 is worse than an honest gap statement.

### GAP-08 — API Gateway access logging

`aws_apigatewayv2_stage.default` has no `access_log_settings`. This means API Gateway request logs are not captured, violating HIPAA 164.312(b) at the API layer. The remediation requires a CloudWatch log group, an IAM role for API Gateway to write to it, and the `access_log_settings` block with a structured log format. I note it in the OSCAL component (`gap-partially-closed` prop) and acknowledge it here. The CloudTrail trail captures management-plane events (stage creation, route changes) but not data-plane request logs.

### Remote Terraform state backend

The current configuration uses local state. For a production capstone, state should be in S3 + DynamoDB (locking) with the state bucket under the same KMS CMK. I left the backend local because the grader applies from their own environment; adding a remote backend would require pre-provisioning the state bucket out-of-band.

### API Gateway WAF

GAP-08 mentions WAF. AWS WAF in front of an HTTP API requires an `aws_wafv2_web_acl_association`. WAF is not in scope for this capstone but would be the next priority for a HIPAA-aligned API.

---

## 6. Evidence Verification Instructions

```bash
# 1. Confirm the pipeline ran and produced a signed bundle
aws s3 ls s3://<EVIDENCE_BUCKET>/runs/<RUN_ID>/

# 2. Full chain-of-custody check (integrity + authenticity + preservation)
bash scripts/verify-evidence.sh \
  s3://<EVIDENCE_BUCKET>/runs/<RUN_ID>/evidence-bundle-<RUN_ID>.tar.gz

# Expected output:
# PASS integrity: SHA-256 matches (...)
# PASS authenticity: Cosign signature verified via Sigstore
# PASS preservation: Object Lock mode=GOVERNANCE retain-until=...

# 3. Run OPA unit tests locally
opa test ./policies -v

# 4. Validate OSCAL document (requires compliance-trestle)
pip install compliance-trestle
trestle validate -f oscal/components/component-definition.json
```

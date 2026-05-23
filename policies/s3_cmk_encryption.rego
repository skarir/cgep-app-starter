# METADATA
# title: S3 buckets must use customer-managed KMS key (CMK)
# description: >
#   PHI buckets must encrypt objects with an aws:kms algorithm using a
#   customer-managed key. AWS-managed SSE-S3 does not give Acme custody
#   over the data key, violating HIPAA 164.312(a)(2)(iv).
# related_resources:
#   - ref: https://www.hhs.gov/hipaa/for-professionals/security/index.html
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-01
#   severity: high
#   remediation: >
#     Add aws_s3_bucket_server_side_encryption_configuration with
#     sse_algorithm = "aws:kms" referencing your CMK.
package compliance.hipaa.s3_cmk_encryption

import rego.v1

# Deny any planned SSE configuration that does NOT use aws:kms
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  some rule in after.rule
  some enc in rule.apply_server_side_encryption_by_default
  enc.sse_algorithm != "aws:kms"

  msg := sprintf(
    "[HIPAA-164.312(a)(2)(iv)] [HIGH] %s: sse_algorithm is %q — must be \"aws:kms\" with a customer CMK. Remediation: set sse_algorithm = \"aws:kms\" and reference your KMS key ARN.",
    [change.address, enc.sse_algorithm]
  )
}

# Deny an S3 bucket tagged DataClass=phi that has no SSE resource in the plan
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket"
  change.change.actions[_] in {"create", "update"}
  change.change.after.tags.DataClass == "phi"

  bucket_name := change.change.after.bucket
  not _has_kms_sse_for_bucket(change.address)

  msg := sprintf(
    "[HIPAA-164.312(a)(2)(iv)] [HIGH] %s (bucket=%q): PHI bucket has no aws_s3_bucket_server_side_encryption_configuration using aws:kms in this plan. Add one before applying.",
    [change.address, bucket_name]
  )
}

_has_kms_sse_for_bucket(bucket_addr) if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_server_side_encryption_configuration"
  change.change.actions[_] in {"create", "update"}

  some rule in change.change.after.rule
  some enc in rule.apply_server_side_encryption_by_default
  enc.sse_algorithm == "aws:kms"
}

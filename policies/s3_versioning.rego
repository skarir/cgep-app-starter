# METADATA
# title: S3 PHI buckets must have versioning enabled
# description: >
#   Without versioning, an overwrite or delete of a PHI object is
#   unrecoverable. HIPAA 164.308(a)(7) requires a contingency plan
#   including data backup; S3 versioning is the technical control.
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   gap: GAP-04
#   severity: medium
#   remediation: >
#     Add an aws_s3_bucket_versioning resource for each PHI bucket
#     and set status = "Enabled".
package compliance.hipaa.s3_versioning

import rego.v1

# Collect versioning resources and the bucket names they cover
_versioned_buckets contains bucket if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_versioning"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  some vc in after.versioning_configuration
  vc.status == "Enabled"

  bucket := after.bucket
}

# Deny an S3 bucket that lacks a versioning resource in the same plan
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after
  bucket := after.bucket

  not bucket in _versioned_buckets

  msg := sprintf(
    "[HIPAA-164.308(a)(7)] [MEDIUM] %s (bucket=%q): no aws_s3_bucket_versioning with status=Enabled found in plan. PHI overwrites are unrecoverable without versioning.",
    [change.address, bucket]
  )
}

# Deny a versioning resource that is explicitly set to Disabled or Suspended
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_versioning"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  some vc in after.versioning_configuration
  vc.status != "Enabled"

  msg := sprintf(
    "[HIPAA-164.308(a)(7)] [MEDIUM] %s: versioning status is %q — must be \"Enabled\" for PHI buckets.",
    [change.address, vc.status]
  )
}

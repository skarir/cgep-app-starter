# METADATA
# title: S3 buckets must deny non-TLS requests
# description: >
#   Every S3 bucket must have a bucket policy with an explicit Deny on
#   requests where aws:SecureTransport is false. Without this, clients
#   can PUT or GET objects over plaintext HTTP, exposing PHI in transit.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-03
#   severity: high
#   remediation: >
#     Add an aws_s3_bucket_policy resource with a Statement Deny on
#     Condition Bool aws:SecureTransport = false.
package compliance.hipaa.s3_tls_required

import rego.v1

# Collect bucket addresses for S3 buckets being created/updated
_planned_buckets[addr] := name if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket"
  change.change.actions[_] in {"create", "update"}
  addr := change.address
  name := change.change.after.bucket
}

# Collect bucket policy resources that enforce TLS
_tls_enforcing_policies contains policy_bucket if {
  some change in input.resource_changes
  change.type == "aws_s3_bucket_policy"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  policy_doc := json.unmarshal(after.policy)
  some stmt in policy_doc.Statement
  stmt.Effect == "Deny"

  some condition_key in [k | k := stmt.Condition.Bool[_]; true]
  lower(condition_key) == lower("aws:SecureTransport")

  policy_bucket := after.bucket
}

# Deny if a planned bucket has no TLS-enforcing policy
deny contains msg if {
  some addr, name in _planned_buckets
  not _bucket_has_tls_policy(name)

  msg := sprintf(
    "[HIPAA-164.312(e)(1)] [HIGH] %s (bucket=%q): no aws_s3_bucket_policy enforcing aws:SecureTransport deny found in plan. Add a Deny statement for aws:SecureTransport=false.",
    [addr, name]
  )
}

_bucket_has_tls_policy(name) if {
  name in _tls_enforcing_policies
}

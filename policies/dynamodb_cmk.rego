# METADATA
# title: DynamoDB tables must use customer-managed KMS encryption
# description: >
#   DynamoDB tables holding PHI must encrypt data at rest with a
#   customer-managed KMS key. The AWS-owned default key does not give
#   Acme custody of the key material, violating HIPAA 164.312(a)(2)(iv).
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-02
#   severity: high
#   remediation: >
#     Add a server_side_encryption block to aws_dynamodb_table with
#     enabled = true and a kms_key_arn pointing at your CMK.
#     Note: changing encryption forces table replacement — plan for a
#     maintenance window on existing tables.
package compliance.hipaa.dynamodb_cmk

import rego.v1

# Deny a DynamoDB table with no CMK SSE block or SSE disabled
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_dynamodb_table"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  not _has_cmk_sse(after)

  msg := sprintf(
    "[HIPAA-164.312(a)(2)(iv)] [HIGH] %s: aws_dynamodb_table has no server_side_encryption block with enabled=true and a customer kms_key_arn. Add one referencing your CMK.",
    [change.address]
  )
}

_has_cmk_sse(after) if {
  some sse in after.server_side_encryption
  sse.enabled == true
  sse.kms_key_arn != null
  sse.kms_key_arn != ""
}

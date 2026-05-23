package compliance.hipaa.dynamodb_cmk_test

import rego.v1
import data.compliance.hipaa.dynamodb_cmk

# ---- passing fixture: table with CMK SSE enabled ---------------------
test_pass_table_has_cmk_sse if {
  plan := {"resource_changes": [{
    "address": "aws_dynamodb_table.intake",
    "type": "aws_dynamodb_table",
    "change": {
      "actions": ["create"],
      "after": {
        "name": "acme-health-intake-submissions-abc1",
        "billing_mode": "PAY_PER_REQUEST",
        "hash_key": "submission_id",
        "server_side_encryption": [{
          "enabled": true,
          "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc"
        }]
      }
    }
  }]}

  count(dynamodb_cmk.deny) == 0 with input as plan
}

# ---- failing fixture: table with no SSE block at all -----------------
test_fail_table_no_sse_block if {
  plan := {"resource_changes": [{
    "address": "aws_dynamodb_table.intake",
    "type": "aws_dynamodb_table",
    "change": {
      "actions": ["create"],
      "after": {
        "name": "acme-health-intake-submissions-abc1",
        "billing_mode": "PAY_PER_REQUEST",
        "hash_key": "submission_id"
      }
    }
  }]}

  msgs := dynamodb_cmk.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.312(a)(2)(iv)")
  contains(m, "server_side_encryption")
}

# ---- failing fixture: table with SSE enabled but no kms_key_arn ------
test_fail_table_sse_no_cmk if {
  plan := {"resource_changes": [{
    "address": "aws_dynamodb_table.intake",
    "type": "aws_dynamodb_table",
    "change": {
      "actions": ["create"],
      "after": {
        "name": "acme-health-intake-submissions-abc1",
        "billing_mode": "PAY_PER_REQUEST",
        "hash_key": "submission_id",
        "server_side_encryption": [{
          "enabled": true,
          "kms_key_arn": null
        }]
      }
    }
  }]}

  msgs := dynamodb_cmk.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "kms_key_arn")
}

package compliance.hipaa.s3_versioning_test

import rego.v1
import data.compliance.hipaa.s3_versioning

# ---- passing fixture: bucket + versioning enabled ---------------------
test_pass_versioning_enabled if {
  plan := {"resource_changes": [
    {
      "address": "aws_s3_bucket.uploads",
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["create"],
        "after": {"bucket": "acme-uploads-abc1", "tags": {}}
      }
    },
    {
      "address": "aws_s3_bucket_versioning.uploads",
      "type": "aws_s3_bucket_versioning",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "acme-uploads-abc1",
          "versioning_configuration": [{"status": "Enabled"}]
        }
      }
    }
  ]}

  count(s3_versioning.deny) == 0 with input as plan
}

# ---- failing fixture: bucket with no versioning resource --------------
test_fail_no_versioning_resource if {
  plan := {"resource_changes": [{
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "change": {
      "actions": ["create"],
      "after": {"bucket": "acme-uploads-abc1", "tags": {}}
    }
  }]}

  msgs := s3_versioning.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.308(a)(7)")
  contains(m, "Enabled")
}

# ---- failing fixture: versioning resource set to Suspended ------------
test_fail_versioning_suspended if {
  plan := {"resource_changes": [
    {
      "address": "aws_s3_bucket.uploads",
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["create"],
        "after": {"bucket": "acme-uploads-abc1", "tags": {}}
      }
    },
    {
      "address": "aws_s3_bucket_versioning.uploads",
      "type": "aws_s3_bucket_versioning",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "acme-uploads-abc1",
          "versioning_configuration": [{"status": "Suspended"}]
        }
      }
    }
  ]}

  msgs := s3_versioning.deny with input as plan
  count(msgs) >= 1
  some m in msgs
  contains(m, "Suspended")
}

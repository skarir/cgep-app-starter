package compliance.hipaa.s3_cmk_encryption_test

import rego.v1
import data.compliance.hipaa.s3_cmk_encryption

# ---- passing fixture: SSE config uses aws:kms -------------------------
test_pass_sse_uses_kms if {
  plan := {"resource_changes": [{
    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "change": {
      "actions": ["create"],
      "after": {
        "bucket": "acme-uploads-abc1",
        "rule": [{
          "apply_server_side_encryption_by_default": [{
            "sse_algorithm": "aws:kms",
            "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc"
          }],
          "bucket_key_enabled": true
        }]
      }
    }
  }]}

  count(s3_cmk_encryption.deny) == 0 with input as plan
}

# ---- failing fixture: SSE config uses AES256 (SSE-S3) ----------------
test_fail_sse_uses_sse_s3 if {
  plan := {"resource_changes": [{
    "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
    "type": "aws_s3_bucket_server_side_encryption_configuration",
    "change": {
      "actions": ["create"],
      "after": {
        "bucket": "acme-uploads-abc1",
        "rule": [{
          "apply_server_side_encryption_by_default": [{
            "sse_algorithm": "AES256",
            "kms_master_key_id": null
          }],
          "bucket_key_enabled": false
        }]
      }
    }
  }]}

  msgs := s3_cmk_encryption.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.312(a)(2)(iv)")
  contains(m, "AES256")
}

# ---- failing fixture: PHI-tagged bucket with no SSE resource ----------
test_fail_phi_bucket_no_sse if {
  plan := {"resource_changes": [{
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "change": {
      "actions": ["create"],
      "after": {
        "bucket": "acme-uploads-abc1",
        "tags": {"DataClass": "phi", "ManagedBy": "terraform"}
      }
    }
  }]}

  msgs := s3_cmk_encryption.deny with input as plan
  count(msgs) >= 1
  some m in msgs
  contains(m, "PHI bucket has no")
}

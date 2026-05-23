package compliance.hipaa.s3_tls_required_test

import rego.v1
import data.compliance.hipaa.s3_tls_required

# ---- passing fixture: bucket + matching TLS policy --------------------
test_pass_bucket_has_tls_policy if {
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
      "address": "aws_s3_bucket_policy.uploads_tls_only",
      "type": "aws_s3_bucket_policy",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "acme-uploads-abc1",
          "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonTLS\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::acme-uploads-abc1\",\"arn:aws:s3:::acme-uploads-abc1/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
        }
      }
    }
  ]}

  count(s3_tls_required.deny) == 0 with input as plan
}

# ---- failing fixture: bucket with no bucket policy at all -------------
test_fail_bucket_no_policy if {
  plan := {"resource_changes": [{
    "address": "aws_s3_bucket.uploads",
    "type": "aws_s3_bucket",
    "change": {
      "actions": ["create"],
      "after": {"bucket": "acme-uploads-abc1", "tags": {}}
    }
  }]}

  msgs := s3_tls_required.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.312(e)(1)")
  contains(m, "aws:SecureTransport")
}

# ---- failing fixture: bucket policy exists but has no TLS deny --------
test_fail_bucket_policy_no_tls_deny if {
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
      "address": "aws_s3_bucket_policy.uploads_public",
      "type": "aws_s3_bucket_policy",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "acme-uploads-abc1",
          "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::acme-uploads-abc1/*\"}]}"
        }
      }
    }
  ]}

  msgs := s3_tls_required.deny with input as plan
  count(msgs) >= 1
  some m in msgs
  contains(m, "aws:SecureTransport")
}

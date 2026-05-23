package compliance.hipaa.iam_least_privilege_test

import rego.v1
import data.compliance.hipaa.iam_least_privilege

_make_inline_policy(actions) := {"resource_changes": [{
  "address": "aws_iam_role_policy.lambda_inline",
  "type": "aws_iam_role_policy",
  "change": {
    "actions": ["create"],
    "after": {
      "name": "intake-data-access",
      "role": "acme-health-intake-lambda-abc1",
      "policy": json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]})
    }
  }
}]}

# ---- passing fixture: specific actions only --------------------------
test_pass_specific_actions if {
  plan := _make_inline_policy(["dynamodb:PutItem", "dynamodb:GetItem", "s3:PutObject"])
  count(iam_least_privilege.deny) == 0 with input as plan
}

# ---- failing fixture: dynamodb:* wildcard ----------------------------
test_fail_dynamodb_wildcard if {
  plan := _make_inline_policy(["dynamodb:*", "s3:PutObject"])
  msgs := iam_least_privilege.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.312(a)(1)")
  contains(m, "dynamodb:*")
}

# ---- failing fixture: s3:* wildcard ----------------------------------
test_fail_s3_wildcard if {
  plan := _make_inline_policy(["dynamodb:PutItem", "s3:*"])
  msgs := iam_least_privilege.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "s3:*")
}

# ---- failing fixture: multiple wildcards -----------------------------
test_fail_multiple_wildcards if {
  plan := _make_inline_policy(["dynamodb:*", "s3:*"])
  msgs := iam_least_privilege.deny with input as plan
  count(msgs) == 2
}

# ---- passing fixture: string action (not array) ----------------------
test_pass_string_action_specific if {
  plan := {"resource_changes": [{
    "address": "aws_iam_role_policy.lambda_inline",
    "type": "aws_iam_role_policy",
    "change": {
      "actions": ["create"],
      "after": {
        "name": "intake-data-access",
        "role": "some-role",
        "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:PutItem\",\"Resource\":\"*\"}]}"
      }
    }
  }]}

  count(iam_least_privilege.deny) == 0 with input as plan
}

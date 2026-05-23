package compliance.hipaa.lambda_vpc_test

import rego.v1
import data.compliance.hipaa.lambda_vpc

# ---- passing fixture: Lambda with VPC config -------------------------
test_pass_lambda_has_vpc_config if {
  plan := {"resource_changes": [{
    "address": "aws_lambda_function.intake",
    "type": "aws_lambda_function",
    "change": {
      "actions": ["create"],
      "after": {
        "function_name": "acme-health-intake-handler-abc1",
        "runtime": "python3.12",
        "vpc_config": [{
          "subnet_ids": ["subnet-aaa111", "subnet-bbb222"],
          "security_group_ids": ["sg-ccc333"]
        }]
      }
    }
  }]}

  count(lambda_vpc.deny) == 0 with input as plan
}

# ---- failing fixture: Lambda with no vpc_config ----------------------
test_fail_lambda_no_vpc_config if {
  plan := {"resource_changes": [{
    "address": "aws_lambda_function.intake",
    "type": "aws_lambda_function",
    "change": {
      "actions": ["create"],
      "after": {
        "function_name": "acme-health-intake-handler-abc1",
        "runtime": "python3.12"
      }
    }
  }]}

  msgs := lambda_vpc.deny with input as plan
  count(msgs) == 1
  some m in msgs
  contains(m, "HIPAA-164.312(e)(1)")
  contains(m, "vpc_config")
}

# ---- failing fixture: Lambda with vpc_config but empty subnet list ---
test_fail_lambda_vpc_config_no_subnets if {
  plan := {"resource_changes": [{
    "address": "aws_lambda_function.intake",
    "type": "aws_lambda_function",
    "change": {
      "actions": ["create"],
      "after": {
        "function_name": "acme-health-intake-handler-abc1",
        "runtime": "python3.12",
        "vpc_config": [{
          "subnet_ids": [],
          "security_group_ids": []
        }]
      }
    }
  }]}

  msgs := lambda_vpc.deny with input as plan
  count(msgs) >= 1
  some m in msgs
  contains(m, "subnet_ids")
}

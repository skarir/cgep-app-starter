# METADATA
# title: Lambda functions must be deployed inside a VPC
# description: >
#   Lambda functions processing PHI must run inside the VPC to benefit
#   from network segmentation and prevent direct internet egress.
#   Running outside a VPC violates the boundary protection requirement
#   in HIPAA 164.312(e)(1) and exposes the function to the public internet.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-05
#   severity: high
#   remediation: >
#     Add a vpc_config block to aws_lambda_function referencing private
#     subnet IDs and a hardened security group.
package compliance.hipaa.lambda_vpc

import rego.v1

# Deny a Lambda function with no vpc_config block
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_lambda_function"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  not _has_vpc_config(after)

  msg := sprintf(
    "[HIPAA-164.312(e)(1)] [HIGH] %s: aws_lambda_function has no vpc_config block. Lambda processing PHI must run inside a VPC. Add vpc_config with private subnet IDs and a security group.",
    [change.address]
  )
}

# Deny a Lambda function with an empty vpc_config (no subnets)
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_lambda_function"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  some vpc in after.vpc_config
  count(vpc.subnet_ids) == 0

  msg := sprintf(
    "[HIPAA-164.312(e)(1)] [HIGH] %s: vpc_config has no subnet_ids. Specify at least one private subnet.",
    [change.address]
  )
}

_has_vpc_config(after) if {
  some vpc in after.vpc_config
  count(vpc.subnet_ids) > 0
}

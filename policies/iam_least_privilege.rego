# METADATA
# title: IAM inline policies must not use wildcard actions
# description: >
#   IAM roles must follow least privilege. Wildcard actions such as
#   dynamodb:* or s3:* grant far more than a function needs and violate
#   the principle of minimal access. HIPAA 164.312(a)(1) requires access
#   controls that restrict access to authorised individuals only.
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   gap: GAP-07
#   severity: high
#   remediation: >
#     Replace wildcard Action values (e.g. "dynamodb:*", "s3:*") with
#     the specific actions the function actually needs (e.g.
#     dynamodb:PutItem, s3:PutObject).
package compliance.hipaa.iam_least_privilege

import rego.v1

_wildcard_pattern := `^[a-zA-Z0-9]+:\*$`

# Deny any inline policy statement with a wildcard action
deny contains msg if {
  some change in input.resource_changes
  change.type == "aws_iam_role_policy"
  change.change.actions[_] in {"create", "update"}
  after := change.change.after

  policy_doc := json.unmarshal(after.policy)
  some stmt in policy_doc.Statement
  stmt.Effect == "Allow"

  some action in _actions_list(stmt.Action)
  regex.match(_wildcard_pattern, action)

  msg := sprintf(
    "[HIPAA-164.312(a)(1)] [HIGH] %s: IAM inline policy contains wildcard action %q in an Allow statement. Replace with specific actions needed by the function.",
    [change.address, action]
  )
}

# Normalise Action to a list regardless of whether it's a string or array
_actions_list(action) := [action] if is_string(action)
_actions_list(action) := action if is_array(action)

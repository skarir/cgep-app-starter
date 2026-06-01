# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# description: "Every taggable AWS resource must carry the four required tags: Project, Environment, ManagedBy, ComplianceScope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required tags (Project, Environment, ManagedBy, ComplianceScope) directly or via provider default_tags."
package compliance.cm6_aws

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

labelable_type(t) if t == "aws_s3_bucket"
labelable_type(t) if t == "aws_dynamodb_table"
labelable_type(t) if t == "aws_lambda_function"
labelable_type(t) if t == "aws_kms_key"
labelable_type(t) if t == "aws_cloudtrail"

deny contains msg if {
	some resource in all_resources
	labelable_type(resource.type)
	missing := required - tag_keys(resource)
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add the missing tags or use provider default_tags.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

# provider default_tags merges into tags_all; prefer that when present.
tag_keys(resource) := {k | resource.values.tags_all[k]} if resource.values.tags_all

tag_keys(resource) := {k | resource.values.tags[k]} if {
	not resource.values.tags_all
	resource.values.tags
}

tag_keys(resource) := set() if {
	not resource.values.tags_all
	not resource.values.tags
}

sort_array(s) := sort([x | some x in s])

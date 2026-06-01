# METADATA
# title: CM-6 - Configuration Settings (required compliance labels)
# description: "Every taggable resource must carry the four required labels: project, environment, managed_by, compliance_scope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required labels (project, environment, managed_by, compliance_scope) to the resource."
package compliance.cm6

import rego.v1

required := {"project", "environment", "managed_by", "compliance_scope"}

labelable_type(t) if t == "google_storage_bucket"
labelable_type(t) if t == "google_compute_instance"
labelable_type(t) if t == "google_compute_disk"

deny contains msg if {
	some resource in all_resources
	labelable_type(resource.type)
	missing := required - provided_labels(resource)
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required labels %v. Remediation: add the missing labels to the resource.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if {
	some r in input.planned_values.root_module.resources
}

all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

provided_labels(resource) := {k | resource.values.labels[k]} if {
	resource.values.labels
}

provided_labels(resource) := set() if {
	not resource.values.labels
}

sort_array(s) := sorted if {
	sorted := sort([x | some x in s])
}

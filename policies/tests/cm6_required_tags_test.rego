package compliance.cm6_test

import rego.v1
import data.compliance.cm6

# ── Fixtures ───────────────────────────────────────────────────────────────

complete_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type":    "google_storage_bucket",
	"values": {"labels": {
		"project":          "lab33",
		"environment":      "dev",
		"managed_by":       "terraform",
		"compliance_scope": "cge-p-lab",
	}},
}]}}}

partial_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.partial",
	"type":    "google_storage_bucket",
	"values": {"labels": {"project": "lab33"}},
}]}}}

no_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.naked",
	"type":    "google_storage_bucket",
	"values":  {},
}]}}}

# Non-labelable resource type — should never be flagged.
non_labelable := {"planned_values": {"root_module": {"resources": [{
	"address": "google_compute_network.demo",
	"type":    "google_compute_network",
	"values":  {},
}]}}}

# ── Tests ──────────────────────────────────────────────────────────────────

test_complete_labels_passes if {
	count(cm6.deny) == 0 with input as complete_labels
}

test_partial_labels_fails if {
	some msg in cm6.deny with input as partial_labels
	contains(msg, "CM-6")
	contains(msg, "google_storage_bucket.partial")
}

test_no_labels_fails if {
	some msg in cm6.deny with input as no_labels
	contains(msg, "CM-6")
	contains(msg, "google_storage_bucket.naked")
}

test_non_labelable_passes if {
	count(cm6.deny) == 0 with input as non_labelable
}

package compliance.sc28_test

import rego.v1
import data.compliance.sc28

# ── Fixtures ───────────────────────────────────────────────────────────────

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type":    "google_storage_bucket",
	"values": {
		"name":       "good",
		"encryption": [{"default_kms_key_name": "projects/x/locations/us-central1/keyRings/r/cryptoKeys/k"}],
	},
}]}}}

# Encryption block is present but holds an empty key — should still deny.
empty_key_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.empty_key",
	"type":    "google_storage_bucket",
	"values": {
		"name":       "empty_key",
		"encryption": [{"default_kms_key_name": ""}],
	},
}]}}}

# No encryption block at all.
noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type":    "google_storage_bucket",
	"values":  {"name": "bad", "encryption": []},
}]}}}

# Bucket inside a child module — recurse path.
module_wrapped_input := {"planned_values": {"root_module": {
	"resources": [],
	"child_modules": [{"resources": [{
		"address": "module.data_bucket.google_storage_bucket.bucket",
		"type":    "google_storage_bucket",
		"values":  {"name": "wrapped", "encryption": []},
	}]}],
}}}

# ── Tests ──────────────────────────────────────────────────────────────────

test_compliant_passes if {
	count(sc28.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in sc28.deny with input as noncompliant_input
	contains(msg, "SC-28")
	contains(msg, "google_storage_bucket.bad")
}

test_empty_key_fails if {
	some msg in sc28.deny with input as empty_key_input
	contains(msg, "SC-28")
	contains(msg, "google_storage_bucket.empty_key")
}

test_module_wrapped_bucket_fails if {
	some msg in sc28.deny with input as module_wrapped_input
	contains(msg, "SC-28")
	contains(msg, "module.data_bucket.google_storage_bucket.bucket")
}

# modules/compliant-gcs-bucket/outputs.tf

output "bucket_url" {
  value       = google_storage_bucket.bucket.url
  description = "gs:// URL of the compliant bucket."
}

output "bucket_self_link" {
  value       = google_storage_bucket.bucket.self_link
  description = "Self-link of the compliant bucket (used by other GCP resources that reference it)."
}

output "kms_key_id" {
  value       = google_kms_crypto_key.key.id
  description = "Resource ID of the CMEK protecting this bucket (SC-12/SC-13 attestation)."
}

output "compliance_attestation" {
  description = "Machine-readable attestation of every control this module enforces. Consumed by Lab 3 Rego policies and Lab 6 OSCAL evidence links."
  value = {
    encryption_algorithm     = "google-managed-cmek-aes256"
    versioning_enabled       = google_storage_bucket.bucket.versioning[0].enabled
    public_access_prevention = google_storage_bucket.bucket.public_access_prevention
    uniform_access_enforced  = google_storage_bucket.bucket.uniform_bucket_level_access
    retention_period_days    = var.retention_days
    kms_rotation_period      = google_kms_crypto_key.key.rotation_period
    required_labels_present = alltrue([
      for k in keys(local.required_labels) :
      contains(keys(google_storage_bucket.bucket.labels), k)
    ])
  }
}

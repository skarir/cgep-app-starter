# modules/compliant-gcs-bucket/main.tf
# Lab 2.4 — Terraform Modules for Compliance (GCP)
#
# Controls hardcoded inside this module (consumers CANNOT override):
#   SC-12  — Customer-managed KMS keyring + crypto key (we own the key)
#   SC-13  — AES-256 CMEK encryption enforced on bucket
#   SC-28  — Encryption at rest via CMEK (no plaintext storage path)
#   AC-3   — uniform_bucket_level_access + public_access_prevention = enforced
#   CM-6   — Four required compliance labels merged on every resource
#   AU-11  — Retention policy with configurable days; versioning enabled

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

locals {
  # CM-6: Required compliance labels — consumers can add but cannot remove these.
  required_labels = {
    project          = var.project_label
    environment      = var.environment
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }

  effective_labels = merge(var.labels, local.required_labels)
  bucket_name      = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}"
  keyring_id       = "${var.bucket_name_suffix}-ring"
  key_id           = "${var.bucket_name_suffix}-key"
}

# Resolve the GCS service account for this project so we can grant KMS access.
data "google_storage_project_service_account" "gcs" {
  project = var.gcp_project
}

# ---------------------------------------------------------------------------
# SC-12: Cryptographic key establishment — we own the key, not Google.
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "ring" {
  name     = local.keyring_id
  location = var.kms_location
  project  = var.gcp_project
}

# SC-13 / SC-28: CMEK with mandatory 90-day (7,776,000 s) rotation.
resource "google_kms_crypto_key" "key" {
  name            = local.key_id
  key_ring        = google_kms_key_ring.ring.id
  rotation_period = "7776000s"   # 90 days

  lifecycle {
    prevent_destroy = false   # flip to true in production
  }
}

# Grant the GCS service account encrypt/decrypt rights on the key.
resource "google_kms_crypto_key_iam_member" "gcs_encrypter" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

# ---------------------------------------------------------------------------
# AC-3 + SC-28 + CM-6 + AU-11 — all enforced in one bucket declaration.
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "bucket" {
  name     = local.bucket_name
  project  = var.gcp_project
  location = var.location

  # AC-3: No object-level ACLs — IAM is the only access path.
  uniform_bucket_level_access = true

  # AC-3: No anonymous or public access under any circumstance.
  public_access_prevention = "enforced"

  # AU-11: Object versioning preserves every version for audit history.
  versioning { enabled = true }

  # SC-13 / SC-28: CMEK — all objects encrypted with our key, not Google's default.
  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  # AU-11: Retention policy — objects cannot be deleted before retention_days expires.
  retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = false   # flip to true to make immutable (one-way operation)
  }

  # CM-6: Required labels merged with any consumer-supplied extras.
  labels = local.effective_labels

  # Bucket creation must wait for the IAM binding so the first write succeeds.
  depends_on = [google_kms_crypto_key_iam_member.gcs_encrypter]
}

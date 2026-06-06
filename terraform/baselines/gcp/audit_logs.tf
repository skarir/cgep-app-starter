# terraform/baselines/gcp/audit_logs.tf
# Controls: AU-2 (auditable events), AU-12 (audit record generation)
#
# GCP Data Access audit logs are OFF BY DEFAULT for all services.
# This is the most frequently cited GCP audit finding because engineers
# assume logging is on — it is not.
#
# Three log types per service:
#   DATA_READ  — read operations (gsutil cat, KMS decrypt)
#   DATA_WRITE — write operations (gsutil cp, KMS create key version)
#   ADMIN_READ — metadata reads (list buckets, describe key)

# Cloud Storage — every object read/write becomes an audit record.
resource "google_project_iam_audit_config" "storage" {
  project = var.gcp_project
  service = "storage.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

# Cloud KMS — every encrypt/decrypt/sign is a billable KMS operation;
# auditing them gives you non-repudiation evidence (AU-10).
resource "google_project_iam_audit_config" "kms" {
  project = var.gcp_project
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

# IAM — who granted what role to whom; critical for AC-2 evidence.
resource "google_project_iam_audit_config" "iam" {
  project = var.gcp_project
  service = "iam.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
  audit_log_config { log_type = "ADMIN_READ" }
}

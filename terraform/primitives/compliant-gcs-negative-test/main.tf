# primitives/compliant-gcs-negative-test/main.tf
# Lab 2.4 — Negative test: proves the prod retention validation fires at plan time.
#
# Run: terraform plan  (it must FAIL with the retention_days validation error)
# Do NOT apply this config — it is intentionally invalid.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = "cgep-lab-sunil-2026"
  region  = "us-central1"
}

module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = "cgep-lab-sunil-2026"
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 30 # INTENTIONAL VIOLATION: prod requires >= 365
  bucket_name_suffix = "should-never-exist"
}

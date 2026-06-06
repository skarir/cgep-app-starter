# terraform/baselines/gcp/main.tf
# Lab 5.4 — GCP Security Services Baseline
#
# Three identity-first controls:
#   Org Policy (CM-6, AC-2, AC-3) — reject misconfigurations at the API call
#   Workload Identity Federation (AC-2) — short-lived OIDC tokens, no JSON keys
#   Data Access audit logs (AU-2, AU-12) — off by default in GCP; turned on here

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project               = var.gcp_project
  region                = "us-central1"
  # Required for orgpolicy.googleapis.com with user ADC credentials
  user_project_override = true
  billing_project       = var.gcp_project
}

data "google_project" "current" {
  project_id = var.gcp_project
}

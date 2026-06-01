# terraform/lab-3-3/main.tf
# Lab 3.3 — Policy test bed: compliant + non-compliant GCP resources.
# This file is PLAN-ONLY. Run terraform plan → show -json to get plan.json.
# Do NOT apply — the non-compliant resources are intentional violations.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

variable "gcp_project" {
  type        = string
  description = "GCP project ID for plan generation. Resources are never applied."
  default     = "cgep-lab-sunil-2026"
}

# KMS resources referenced by the compliant bucket.
resource "google_kms_key_ring" "ring" {
  name     = "lab33-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name     = "lab33-key"
  key_ring = google_kms_key_ring.ring.id
}

# ── COMPLIANT: passes all three policies ─────────────────────────────────

resource "google_storage_bucket" "good" {
  name                        = "${var.gcp_project}-lab33-good"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption { default_kms_key_name = google_kms_crypto_key.key.id }

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

# ── NON-COMPLIANT: each trips exactly one policy ──────────────────────────

# Trips SC-28 — no encryption block.
resource "google_storage_bucket" "bad_no_cmek" {
  name                        = "${var.gcp_project}-lab33-no-cmek"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

# Trips AC-3 — public access not locked down.
resource "google_storage_bucket" "bad_public" {
  name                        = "${var.gcp_project}-lab33-public"
  location                    = "us-central1"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"

  encryption { default_kms_key_name = google_kms_crypto_key.key.id }

  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

# Trips CM-6 — no labels at all.
resource "google_storage_bucket" "bad_no_labels" {
  name                        = "${var.gcp_project}-lab33-no-labels"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption { default_kms_key_name = google_kms_crypto_key.key.id }
}

# Network for the firewall rule.
resource "google_compute_network" "demo" {
  name                    = "lab33-demo"
  auto_create_subnetworks = false
}

# Trips AC-3 — SSH open to the world.
resource "google_compute_firewall" "open_ssh" {
  name          = "lab33-open-ssh"
  network       = google_compute_network.demo.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# terraform/baselines/gcp/wif.tf
# Controls: AC-2 (account management — replaces long-lived keys with short-lived OIDC tokens)
#
# Workload Identity Federation lets GitHub Actions authenticate to GCP without
# storing a service account JSON key anywhere. The pattern:
#   1. GitHub Actions runner mints a JWT signed by GitHub's OIDC endpoint
#   2. GCP exchanges it for a short-lived access token (max 1 hour)
#   3. Token is never written to disk; expires automatically
#
# The attribute_condition is CRITICAL — without it, ANY public GitHub repo
# can impersonate this service account.

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.gcp_project
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "WIF pool for GitHub Actions — replaces service account JSON keys (AC-2)"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.gcp_project
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub OIDC provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
  }

  # Scope this provider to exactly one repository.
  # Any other repo's OIDC token will be rejected.
  attribute_condition = "assertion.repository == \"${var.github_repo}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Read-only service account assumed by the GitHub Actions workflow via WIF.
resource "google_service_account" "gha" {
  project      = var.gcp_project
  account_id   = "cgep-grc-gate-sa"
  display_name = "CGE-P GRC gate (read-only via WIF)"
  description  = "Assumed by GitHub Actions via WIF — no JSON keys ever created"
}

# Viewer on the project (enough for terraform plan + evidence collection).
resource "google_project_iam_member" "gha_viewer" {
  project = var.gcp_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.gha.email}"
}

# Allow the WIF pool/provider to impersonate this service account,
# but ONLY when the request comes from the specific repository.
resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.gha.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}",
  ]
}

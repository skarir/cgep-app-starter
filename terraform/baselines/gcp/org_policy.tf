# terraform/baselines/gcp/org_policy.tf
# Controls: CM-6 (configuration settings), AC-2 (account management), AC-3 (access enforcement)
#
# Org Policy enforces at the API call — REJECTED before the resource exists.
# This is the strongest preventative layer: Rego policies are detective,
# Org Policy is preventative.

# CM-6: All GCS buckets must use uniform bucket-level access (no per-object ACLs).
# Prevents legacy ACL-based access that bypasses IAM.
resource "google_org_policy_policy" "uniform_bucket_access" {
  name   = "projects/${var.gcp_project}/policies/storage.uniformBucketLevelAccess"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# AC-2: Disable creation of long-lived service account JSON keys in this project.
# Service account JSON keys are the #1 GCP credential leak vector.
# GitHub Actions uses WIF (see wif.tf) instead.
resource "google_org_policy_policy" "disable_sa_keys" {
  name   = "projects/${var.gcp_project}/policies/iam.disableServiceAccountKeyCreation"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

# AC-3: Require OS Login on Compute Engine instances.
# OS Login ties SSH access to IAM principals — no persistent SSH keys in metadata.
resource "google_org_policy_policy" "require_oslogin" {
  name   = "projects/${var.gcp_project}/policies/compute.requireOsLogin"
  parent = "projects/${var.gcp_project}"

  spec {
    rules { enforce = "TRUE" }
  }
}

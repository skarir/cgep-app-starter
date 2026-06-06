# terraform/baselines/gcp/outputs.tf

output "wif_provider" {
  value       = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id}"
  description = "Full WIF provider resource name — paste into google-github-actions/auth@v2 workflow."
}

output "gha_service_account" {
  value       = google_service_account.gha.email
  description = "Service account email assumed by GitHub Actions via WIF."
}

output "wif_pool_name" {
  value       = google_iam_workload_identity_pool.github.name
  description = "WIF pool resource name."
}

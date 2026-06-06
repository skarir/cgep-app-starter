# terraform/baselines/gcp/variables.tf

variable "gcp_project" {
  type        = string
  description = "GCP project ID where the baseline controls are enforced."
  default     = "cgep-lab-sunil-2026"
}

variable "github_repo" {
  type        = string
  description = "GitHub OWNER/REPO that is allowed to use WIF (no other repo can impersonate)."
  default     = "skarir/cgep-app-starter"
}

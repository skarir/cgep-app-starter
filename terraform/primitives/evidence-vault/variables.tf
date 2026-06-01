# terraform/primitives/evidence-vault/variables.tf

variable "project_name" {
  type        = string
  description = "Short project identifier. Becomes part of the vault bucket name and the Project tag."
  default     = "cgep-lab"
}

variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work (bypassable); COMPLIANCE for real evidence (immutable until expiry)."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention in days applied to every object uploaded to the vault. Use 1 for lab work."
  default     = 1
}

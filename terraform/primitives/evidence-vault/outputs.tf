# terraform/primitives/evidence-vault/outputs.tf

output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "S3 bucket name of the evidence vault. Pass to capture-evidence.sh --vault."
}

output "vault_arn" {
  value       = aws_s3_bucket.vault.arn
  description = "ARN of the evidence vault bucket."
}

output "lock_mode" {
  value       = var.lock_mode
  description = "Object Lock retention mode in effect (GOVERNANCE or COMPLIANCE)."
}

output "retention_days" {
  value       = var.retention_days
  description = "Default retention period applied to every uploaded object."
}

# terraform/baselines/aws/outputs.tf

output "cloudtrail_name" {
  value       = aws_cloudtrail.mgmt.name
  description = "CloudTrail trail name (AU-2/AU-12/AU-10 attestation)."
}

output "cloudtrail_arn" {
  value       = aws_cloudtrail.mgmt.arn
  description = "CloudTrail trail ARN."
}

output "cloudtrail_log_bucket" {
  value       = aws_s3_bucket.trail.id
  description = "S3 bucket receiving CloudTrail management events."
}

output "security_hub_arn" {
  value       = aws_securityhub_account.this.id
  description = "Security Hub account ARN (RA-5/SI-4 attestation)."
}

output "nist_800_53_subscription_arn" {
  value       = aws_securityhub_standards_subscription.nist_800_53.id
  description = "ARN of the NIST 800-53 Rev 5 standards subscription."
}

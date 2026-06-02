# terraform/baselines/aws/security_hub.tf
# Controls: RA-5 (vulnerability monitoring), SI-4 (information system monitoring)

# Enable Security Hub in this account/region.
# If already enabled from a previous run: terraform import aws_securityhub_account.this <ACCOUNT_ID>
resource "aws_securityhub_account" "this" {}

# NIST 800-53 Rev 5 — the framework this capstone is measured against.
# Runs ~300 automated checks. Billed at ~$0.001 per check per month.
resource "aws_securityhub_standards_subscription" "nist_800_53" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# AWS Foundational Security Best Practices — second lens; maps to CIS and ISO 27001.
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

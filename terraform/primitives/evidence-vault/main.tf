# terraform/primitives/evidence-vault/main.tf
# Lab 2.5 — IaC as Compliance Evidence (AWS)
#
# Builds an S3 Object Lock vault that refuses deletion by design.
# Controls enforced:
#   SC-28  — AES-256 server-side encryption on every stored object
#   AU-9   — Object Lock retention prevents tampering with audit records
#   AC-3   — Public access blocked; bucket deletion denied except to account root
#   CM-6   — Required compliance tags via provider default_tags

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = "us-east-1"

  # CM-6: Compliance tags applied automatically to every taggable resource.
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = "evidence"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "suffix" { byte_length = 4 }

locals {
  vault_name = "${var.project_name}-grc-evidence-vault-${random_id.suffix.hex}"
}

# AU-9: Object Lock must be declared at bucket creation — cannot be retrofitted.
resource "aws_s3_bucket" "vault" {
  bucket              = local.vault_name
  object_lock_enabled = true
}

# Object Lock requires versioning to be enabled.
resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

# AU-9: Default retention applied to every uploaded object.
# GOVERNANCE = lab-safe (bypassable with privilege).
# COMPLIANCE = production (immutable until expiry, even root cannot delete).
resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = var.lock_mode
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

# SC-28: AES-256 encryption at rest on all evidence objects.
resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# AC-3: No public access vectors.
resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AC-3: Deny bucket deletion from anyone except the account root.
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_policy" "vault" {
  bucket = aws_s3_bucket.vault.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyBucketDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:DeleteBucket"
      Resource  = aws_s3_bucket.vault.arn
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

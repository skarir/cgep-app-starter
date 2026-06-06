# terraform/primitives/oidc/main.tf
# Lab 4.3 — GitHub Actions OIDC trust for AWS
#
# Creates:
#   - aws_iam_openid_connect_provider  (GitHub's OIDC issuer)
#   - aws_iam_role                     (cgep-grc-gate, scoped to one repo)
#   - ReadOnlyAccess attachment        (enough for terraform plan)

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

variable "github_org" {
  type        = string
  description = "GitHub organisation or user name (e.g. skarir)"
}

variable "github_repo" {
  type        = string
  description = "Repository name without the org prefix (e.g. cgep-app-starter)"
}

# GitHub's OIDC provider — there can only be one per AWS account.
# If it already exists, import it before applying:
#   terraform import aws_iam_openid_connect_provider.github \
#     arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # GitHub's current OIDC thumbprint (rotated Feb 2023)
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# IAM role assumed by the workflow via OIDC — scoped to exactly one repo.
# StringLike on sub allows any ref (branch, tag, PR) within that repo.
resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })

  tags = {
    Project         = "cgep-lab"
    ManagedBy       = "terraform"
    ComplianceScope = "cge-p-lab"
  }
}

# ReadOnlyAccess is sufficient for terraform plan (no apply in the gate).
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

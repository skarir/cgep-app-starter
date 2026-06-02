# terraform/baselines/aws/main.tf
# Lab 5.2 — AWS Security Services Baseline
#
# Deploys the three services that form the AWS-native compliance backbone:
#   CloudTrail  — AU-2, AU-12, AU-10
#   Security Hub — RA-5, SI-4 (NIST 800-53 Rev 5 + FSBP)
#   AWS Config  — CM-2, CM-6, CM-8 (may be SCP-blocked in org accounts)

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project         = "cgep-lab"
      Environment     = "baseline"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

resource "random_id" "suffix" { byte_length = 4 }

data "aws_caller_identity" "current" {}

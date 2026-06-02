# terraform/baselines/aws/config.tf
# Controls: CM-2 (baseline configuration), CM-6 (configuration settings),
#            CM-8 (information system component inventory)
#
# IMPORTANT: This file is DISABLED by default (enable_config = false).
# Org-managed accounts often have an SCP that blocks config:PutConfigurationRecorder.
# If deployment fails with AccessDeniedException from an SCP, keep this disabled —
# the Security Hub finding "AWS Config should be enabled" (Config.1) is itself
# evidence that the gap is known and documented.
#
# To enable: set variable enable_config = true in terraform.tfvars.

# ── S3 bucket for Config snapshots ───────────────────────────────────────────

resource "aws_s3_bucket" "config" {
  count         = var.enable_config ? 1 : 0
  bucket        = "cgep-lab-config-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = var.enable_config ? 1 : 0
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── IAM role for Config ───────────────────────────────────────────────────────

resource "aws_iam_role" "config" {
  count = var.enable_config ? 1 : 0
  name  = "cgep-lab-config-recorder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ── Config recorder + delivery channel ────────────────────────────────────────

resource "aws_config_configuration_recorder" "this" {
  count    = var.enable_config ? 1 : 0
  name     = "cgep-lab-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_config ? 1 : 0
  name           = "cgep-lab-channel"
  s3_bucket_name = aws_s3_bucket.config[0].id
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

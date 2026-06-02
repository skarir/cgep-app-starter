# terraform/baselines/aws/cloudtrail.tf
# Controls: AU-2 (auditable events), AU-12 (audit record generation),
#            AU-10 (non-repudiation via log-file validation)

# ── S3 bucket for CloudTrail logs ────────────────────────────────────────────

resource "aws_s3_bucket" "trail" {
  bucket        = "cgep-lab-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true   # allows terraform destroy to remove the bucket+logs
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: CloudTrail service must be allowed to check ACL + write logs.
# aws:SourceArn scopes the permission to exactly this trail (prevents confused-deputy).
data "aws_iam_policy_document" "trail" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cgep-lab-mgmt"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  policy     = data.aws_iam_policy_document.trail.json
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

# ── CloudTrail ────────────────────────────────────────────────────────────────

resource "aws_cloudtrail" "mgmt" {
  name                          = "cgep-lab-mgmt"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true   # AU-2: captures events in every region
  include_global_service_events = true   # IAM, STS, Route 53 events
  enable_log_file_validation    = true   # AU-10: signed hourly digest for tamper detection

  # Management events only — no data events (no extra cost)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

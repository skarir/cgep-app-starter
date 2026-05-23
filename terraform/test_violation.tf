# THIS FILE IS INTENTIONALLY NON-COMPLIANT — used to demonstrate the policy gate.
#
# The iam_least_privilege.rego policy will flag the wildcard actions below
# and block this PR in Step 2 of the grc-gate workflow.
#
# DO NOT MERGE — this is the "red PR" required by the CGE-P capstone.

resource "aws_iam_role_policy" "lambda_overpermissioned" {
  name = "lambda-overpermissioned"
  role = aws_iam_role.lambda.id

  # VIOLATION: wildcard actions on DynamoDB and S3 violate HIPAA 164.312(a)(1).
  # The OPA policy iam_least_privilege.rego pattern ^[a-zA-Z0-9]+:\*
  # matches both "dynamodb:*" and "s3:*" and emits a deny.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBFullAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:*"
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3FullAccess"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
      }
    ]
  })
}

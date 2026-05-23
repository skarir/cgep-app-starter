######################################################################
# Terraform override file — adds compliance attributes to existing
# starter resources without modifying main.tf.
#
# Terraform merges override files into the resource definitions they
# reference. File must be named *_override.tf (or override.tf).
#
# GAP-02: DynamoDB CMK encryption
# GAP-05: Lambda VPC placement
######################################################################

# GAP-02 close: bring DynamoDB under the customer CMK
# HIPAA 164.312(a)(2)(iv)
# Note: changing encryption_type forces replacement of the table.
# Apply this during the baseline week before any real data lands.
resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }
}

# GAP-05 close: move Lambda into the private subnets of the starter VPC
# HIPAA 164.312(e)(1)
resource "aws_lambda_function" "intake" {
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
}

# Lambda in a VPC needs the VPC execution role attachment
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

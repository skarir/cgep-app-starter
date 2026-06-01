# terraform/primitives/oidc/outputs.tf

output "role_arn" {
  value       = aws_iam_role.grc_gate.arn
  description = "ARN of the IAM role assumed by GitHub Actions. Set this as the AWS_ROLE_ARN repo secret."
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.github.arn
  description = "ARN of the GitHub OIDC provider in this AWS account."
}

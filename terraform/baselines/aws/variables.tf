# terraform/baselines/aws/variables.tf

variable "aws_region" {
  type        = string
  description = "AWS region for all baseline resources."
  default     = "us-east-1"
}

variable "enable_config" {
  type        = bool
  description = "Set false if an SCP blocks config:PutConfigurationRecorder in this account."
  default     = false
}

# aws-security-baseline

Terraform module that deploys the AWS-native compliance backbone for the CGE-P capstone. Three services, three NIST 800-53 control families.

## Controls

| Service | Controls | What it does |
|---|---|---|
| **CloudTrail** | AU-2, AU-12, AU-10 | Multi-region management event logging with signed hourly digests for tamper detection (AU-10 = non-repudiation) |
| **Security Hub** | RA-5, SI-4 | Aggregates findings from GuardDuty, Config, and native checks; subscribed to NIST 800-53 Rev 5 and FSBP |
| **AWS Config** | CM-2, CM-6, CM-8 | Records resource configuration state for every supported type; feeds Security Hub controls (disabled by default — see below) |

## Usage

```bash
cd terraform/baselines/aws
terraform init
terraform apply -auto-approve
```

After apply, wait 10–20 minutes for Security Hub findings to populate, then capture evidence:

```bash
aws securityhub get-findings --region us-east-1 --max-results 50 \
  > ../../../evidence/lab-5-2/security-hub-findings.json
```

## Inputs

| Variable | Default | Description |
|---|---|---|
| `aws_region` | `us-east-1` | Region for all baseline resources |
| `enable_config` | `false` | Set `true` to deploy Config recorder (may be SCP-blocked in org accounts) |

## Outputs

| Name | Description |
|---|---|
| `cloudtrail_name` | Trail name (`cgep-lab-mgmt`) |
| `cloudtrail_arn` | Trail ARN |
| `cloudtrail_log_bucket` | S3 bucket receiving management events |
| `security_hub_arn` | Security Hub account ID (RA-5/SI-4 attestation) |
| `nist_800_53_subscription_arn` | NIST 800-53 Rev 5 standards subscription ARN |

## AWS Config note

Config is included in `config.tf` but disabled by default (`enable_config = false`). Org-managed accounts often have an SCP blocking `config:PutConfigurationRecorder`. If this account is org-managed, leave Config disabled — the Security Hub finding `Config.1` ("AWS Config should be enabled") is itself documented evidence that the gap is known. Enable Config with `enable_config = true` in `terraform.tfvars` if your account permits it.

## Cleanup

```bash
# Capture findings first
aws securityhub get-findings --region us-east-1 --max-results 50 \
  > ../../../evidence/lab-5-2/security-hub-findings.json

# Remove Security Hub from state if you want to keep it running
terraform state rm aws_securityhub_account.this

# Destroy the rest
terraform destroy -auto-approve
```

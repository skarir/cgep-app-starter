# cgep-app-starter — Acme Health Patient Intake API

> CGE-P Capstone: Patient Intake API hardened to **HIPAA Security Rule** using IaC, Policy-as-Code, a GitHub Actions evidence pipeline, and an OSCAL component definition.

**Primary framework:** HIPAA Security Rule  
**Grader:** see [Verification instructions](#verification-instructions) below and [WRITEUP.md](WRITEUP.md) for full design rationale.

## What this repo is

A fork of `GRCEngClub/cgep-app-starter` — a minimal AWS workload (Lambda + API Gateway + DynamoDB + S3) that ships non-compliant on purpose — with four CGE-P compliance layers added on top:

| Layer | Location | What it does |
|-------|----------|--------------|
| 1 — Terraform baseline | `terraform/grc_baseline.tf`, `terraform/grc_override.tf` | KMS CMK, S3 evidence vault (Object Lock), CloudTrail, gap-closing overrides |
| 2 — OPA policy suite | `policies/*.rego` | 6 Rego policies with tests covering all key HIPAA gaps |
| 3 — GitHub Actions pipeline | `.github/workflows/grc-gate.yml` | Plan → Policy check → Apply → Cosign sign → Upload to vault |
| 4 — OSCAL component | `oscal/components/component-definition.json` | Machine-readable HIPAA control mapping to signed evidence |

## Gaps closed

| ID | Gap | Status |
|----|-----|--------|
| GAP-01 | S3 SSE-KMS | Closed — `grc_baseline.tf` + `s3_cmk_encryption.rego` |
| GAP-02 | DynamoDB CMK | Closed — `grc_override.tf` + `dynamodb_cmk.rego` |
| GAP-03 | S3 TLS-only policy | Closed — `grc_baseline.tf` + `s3_tls_required.rego` |
| GAP-04 | S3 versioning | Closed — `grc_baseline.tf` + `s3_versioning.rego` |
| GAP-05 | Lambda VPC | Closed — `grc_override.tf` + `lambda_vpc.rego` |
| GAP-06 | Lambda observability | Partial — documented in [WRITEUP.md](WRITEUP.md) |
| GAP-07 | IAM wildcard | Closed — `grc_baseline.tf` + `iam_least_privilege.rego` |
| GAP-08 | API Gateway logging | Partial — documented in [WRITEUP.md](WRITEUP.md) |

## The deploy gate (unchanged)

```bash
make creds  AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
# Expected: {"submission_id": "...", "status": "received"}
```

> **AWS SSO note:** if your profile is SSO-based, use `eval $(aws configure export-credentials --profile <profile> --format env)` before running Terraform commands by hand.

## Verification instructions

### Prerequisites

```bash
terraform --version   # >= 1.6
opa version           # >= 0.65
conftest --version    # >= 0.55
cosign version        # >= 2.4
aws --version         # AWS CLI v2
pip install compliance-trestle
```

### 1 — Apply the GRC baseline

```bash
# Set these GitHub Actions variables/secrets first:
#   EVIDENCE_BUCKET — Object Lock S3 bucket name (created by baseline apply)
#   AWS_ROLE_ARN    — IAM role ARN for GitHub OIDC trust

cd terraform
terraform init
terraform apply -target=aws_kms_key.phi   # KMS key first
terraform apply
```

### 2 — Run OPA unit tests

```bash
opa test ./policies -v
# All tests must pass
```

### 3 — Run the policy gate locally

```bash
cd terraform && terraform show -json tfplan > ../plan.json && cd ..
bash scripts/policy-gate.sh plan.json
```

### 4 — Verify a signed evidence bundle (chain of custody)

```bash
bash scripts/verify-evidence.sh \
  s3://<EVIDENCE_BUCKET>/runs/<RUN_ID>/evidence-bundle-<RUN_ID>.tar.gz
# Expected:
#   PASS integrity:    SHA-256 matches (...)
#   PASS authenticity: Cosign signature verified via Sigstore
#   PASS preservation: Object Lock mode=GOVERNANCE
```

### 5 — Validate the OSCAL component

```bash
trestle validate -f oscal/components/component-definition.json
```

## Layout

```
cgep-app-starter/
├── README.md                            # this file (grader start here)
├── WRITEUP.md                           # design rationale, trade-offs, honest gaps
├── WORKLOAD.md                          # what the API does
├── GAPS.md                              # eight named flaws + remediation status
├── FRAMEWORKS.md                        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile                             # make deploy | test | destroy
├── terraform/
│   ├── main.tf                          # starter (unchanged — intentional gaps)
│   ├── variables.tf
│   ├── outputs.tf
│   ├── grc_baseline.tf                  # Layer 1 — KMS, evidence vault, CloudTrail
│   ├── grc_override.tf                  # Layer 1 — Lambda VPC + DynamoDB SSE overrides
│   └── lambda/handler.py
├── policies/
│   ├── s3_cmk_encryption.rego           # GAP-01: S3 must use CMK  [HIPAA 164.312(a)(2)(iv)]
│   ├── s3_cmk_encryption_test.rego
│   ├── s3_tls_required.rego             # GAP-03: S3 must deny non-TLS [HIPAA 164.312(e)(1)]
│   ├── s3_tls_required_test.rego
│   ├── s3_versioning.rego               # GAP-04: S3 versioning required [HIPAA 164.308(a)(7)]
│   ├── s3_versioning_test.rego
│   ├── dynamodb_cmk.rego                # GAP-02: DynamoDB must use CMK [HIPAA 164.312(a)(2)(iv)]
│   ├── dynamodb_cmk_test.rego
│   ├── lambda_vpc.rego                  # GAP-05: Lambda must be in VPC [HIPAA 164.312(e)(1)]
│   ├── lambda_vpc_test.rego
│   ├── iam_least_privilege.rego         # GAP-07: no IAM wildcard actions [HIPAA 164.312(a)(1)]
│   └── iam_least_privilege_test.rego
├── scripts/
│   ├── policy-gate.sh                   # Conftest wrapper for CI
│   ├── capture-evidence.sh              # bundle + upload to vault
│   └── verify-evidence.sh              # integrity + authenticity + preservation
├── .github/workflows/
│   └── grc-gate.yml                     # Layer 3 — 5-step CI/CD pipeline
├── oscal/components/
│   └── component-definition.json        # Layer 4 — OSCAL HIPAA control mapping
└── test/
    └── intake.sh

```

## Cost

Roughly $0 if destroyed within an hour. CloudTrail + KMS key rotation cost cents/month.
`make destroy` tears down everything except the Object Lock vault (retention active).

## License

MIT. Submissions remain learners' own work.

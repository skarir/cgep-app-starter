# Acme Health — Patient Intake API (GRC-hardened)

I inherited a working but audit-indefensible Patient Intake API and spent a month making it
defensible without slowing the engineering team down. This repo is the result: the original
AWS workload (a fork of `GRCEngClub/cgep-app-starter`), wrapped in the controls, policy gates,
signed-evidence pipeline, and OSCAL that prove it stays compliant on every push.

**Primary framework:** HIPAA Security Rule — the API handles PHI, so HIPAA is non-optional.
I explain the choice, the trade-offs, and what I deliberately left undone in [WRITEUP.md](WRITEUP.md).

**If you're grading this,** start at [Verifying it yourself](#verifying-it-yourself) and skim
[WRITEUP.md](WRITEUP.md) for the reasoning behind each decision.

## How it fits together

The starter ships a Lambda + API Gateway + DynamoDB + S3 app that is non-compliant on purpose.
I left that workload in place and built four things around it:

- **Terraform baseline** (`terraform/`) — a KMS customer-managed key, a versioned S3 evidence
  vault with Object Lock, a multi-region CloudTrail, and the overrides that bring the starter's
  bucket, table, and Lambda under those controls.
- **Policy suite** (`policies/`) — Rego rules, one per gap, each with passing and failing
  fixtures and the HIPAA control ID baked into the deny message so a failed PR tells you exactly
  what to fix.
- **Pipeline** (`.github/workflows/grc-gate.yml`) — five steps in order: plan → policy check →
  apply (gated, merge to `main`) → Cosign sign → upload to the vault. A green PR and a blocked
  red PR are both in the history as proof the gate actually decides.
- **OSCAL component** (`oscal/`) — a component definition + profile + resolved catalog that map
  what I built to NIST 800-53 controls (with the HIPAA section carried as a prop, since there's
  no published HIPAA catalog) and link to the real signed evidence in the vault.

The point of all of it: every push to `main` produces a signed, timestamped artifact in immutable
storage, automatically. An assessor can follow the OSCAL link into the vault and verify a control
without ever talking to me.

## The eight gaps

The starter ships with eight named flaws ([GAPS.md](GAPS.md)). I closed six in code and policy,
and documented the other two honestly rather than half-build them.

| Gap | What it was | How I handled it |
|-----|-------------|------------------|
| GAP-01 | S3 used SSE-S3, not a customer key | Closed — CMK in `grc_baseline.tf`, guarded by `s3_cmk_encryption.rego` |
| GAP-02 | DynamoDB on the AWS-owned key | Closed — `grc_override.tf` + `dynamodb_cmk.rego` |
| GAP-03 | No TLS-only bucket policy | Closed — `grc_baseline.tf` + `s3_tls_required.rego` |
| GAP-04 | No S3 versioning | Closed — `grc_baseline.tf` + `s3_versioning.rego` |
| GAP-05 | Lambda outside the VPC | Closed — `grc_override.tf` + `lambda_vpc.rego` |
| GAP-06 | No Lambda DLQ / X-Ray / concurrency | Documented — see [WRITEUP.md](WRITEUP.md) |
| GAP-07 | IAM wildcards (`dynamodb:*`, `s3:*`) | Closed — `grc_baseline.tf` + `iam_least_privilege.rego` |
| GAP-08 | No API Gateway access logging | Documented — see [WRITEUP.md](WRITEUP.md) |

## Standing the workload up

```bash
make creds  AWS_PROFILE=<your-sandbox-profile>
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
# A healthy run returns: {"submission_id": "...", "status": "received"}
```

On SSO-based profiles, export credentials first so Terraform can see them:
`eval $(aws configure export-credentials --profile <profile> --format env)`.

## Verifying it yourself

You'll need Terraform ≥ 1.6, OPA ≥ 0.65, Conftest ≥ 0.55, Cosign ≥ 2.4, the AWS CLI v2, and
`pip install compliance-trestle`.

**Apply the baseline** (KMS key first, so the vault can use it):

```bash
cd terraform
terraform init
terraform apply -target=aws_kms_key.phi
terraform apply
```

**Run the policy tests and the gate:**

```bash
opa test ./policies -v
terraform show -json tfplan > ../plan.json
bash ../scripts/policy-gate.sh ../plan.json
```

**Verify a signed evidence bundle end to end** — this is the part worth your time:

```bash
EVIDENCE_VAULT=<vault-bucket> bash scripts/verify-evidence.sh <run-id>
# 1. Integrity     SHA-256 recomputes against the sidecar
# 2. Authenticity  Cosign signature verifies against Sigstore Rekor
# 3. Preservation  Object Lock retention is still active
# => CHAIN INTACT
```

**Validate the OSCAL:**

```bash
cd oscal && trestle validate -a
```

## What's where

```
.
├── README.md            you are here
├── WRITEUP.md           design decisions, trade-offs, honest gaps
├── WORKLOAD.md          what the API actually does
├── GAPS.md              the eight flaws and their status
├── FRAMEWORKS.md        HIPAA / SOC 2 / CMMC primer and why I picked HIPAA
├── COMPLIANCE.md        control-to-code mapping
├── docs/verification.md recorded Tier-0 / Tier-1 results
├── terraform/           the starter workload + my GRC baseline and overrides
├── policies/            the Rego suite (rules + tests)
├── scripts/             policy-gate, capture-evidence, verify-evidence
├── oscal/               component definition, profile, resolved catalog
├── .github/workflows/   grc-gate.yml — the five-step pipeline
└── test/                intake smoke test
```

## Cost and teardown

Run it in a sandbox and tear it down within the hour and it's effectively free; left running,
CloudTrail and KMS key rotation cost cents a month. `make destroy` removes everything except the
Object Lock vault, which stays put until its retention window expires — that's the point of it.

## License

MIT — see [LICENSE](LICENSE). The work is my own.

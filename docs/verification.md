# Verification Evidence

Records the latest local Tier-0 / Tier-1 results for this repo. The same checks
run in CI (`.github/workflows/grc-gate.yml`) on every PR and push to `main`.

**Last run:** 2026-06-06

## Tool versions

| Tool | Version |
|---|---|
| terraform | 1.15.4 |
| checkov | latest pip release |
| conftest | 0.55.0 (CI) |
| opa | 0.68.0 (CI) |
| tfsec | latest (CI) |
| cosign | v2.x |
| compliance-trestle | latest |

## Tier-0 — static analysis

### `terraform fmt -check -recursive`
```
$ terraform fmt -check -recursive
$ echo $?
0
```
No diffs.

### `terraform validate`
```
$ cd terraform && terraform init -backend=false && terraform validate
Success! The configuration is valid.
```

### `checkov -d terraform/` (informational)
```
Passed checks: 214, Failed checks: 95, Skipped checks: 0
```
Checkov runs **informational, not as a hard gate**. `terraform/` intentionally
contains non-compliant fixtures (`primitives/compliant-gcs-negative-test`,
`lab-3-4-broken`) and the starter's deliberate GAPS — surfacing those is the job
of the OPA policy gate (Step 2), which fails closed. The failed checks are
dominated by those intentional fixtures plus the un-hardened starter resources
that the policy gate blocks and the Terraform overrides remediate.

### `gitleaks` (secret scan)
No verified secrets. Committed evidence contains the AWS account ID, GCP project
ID, and maintainer email (identifiers, not credentials) — see WRITEUP.

## Tier-1 — policy + OSCAL + chain

### `opa test ./policies` (CI)
All policy unit tests pass (passing + failing fixtures per policy).

### `conftest` policy gate (CI)
Green PR (#4) passes the gate; red PRs (#3 SC-28, #2 IAM wildcard) are blocked.

### `trestle validate -a`
```
VALID: oscal/catalogs/cge-p-hipaa-minimum-resolved/catalog.json
VALID: oscal/component-definitions/acme-patient-intake-api/component-definition.json
VALID: oscal/profiles/cge-p-hipaa-minimum/profile.json
```

### Chain of custody — `scripts/verify-evidence.sh`
```
$ EVIDENCE_VAULT=cgep-lab-grc-evidence-vault-b60d9d5f bash scripts/verify-evidence.sh 27064467751
=== 1. Integrity (SHA-256) ===        OK
=== 2. Authenticity + Timeliness ===  OK (Cosign verified, Rekor timestamp)
=== 3. Preservation (Object Lock) ===  OK (retain until 2026-07-06)
CHAIN INTACT for run 27064467751
```
This is the run referenced by the OSCAL component's evidence links.

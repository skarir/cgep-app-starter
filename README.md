<!--
  RECRUITER-FACING README DRAFT for github.com/skarir/cgep-app-starter
  This replaces / augments the existing README.md.
  Verify the file paths and run IDs against the current repo before committing
  (this draft is built from the documented structure; confirm exact names).
-->

# Acme Health — Patient Intake API · GRC-Hardened Capstone

> **Take a deliberately non-compliant healthcare workload and govern it as code** — from policy enforcement, through NIST/HIPAA control mapping, to cryptographically signed, tamper-proof audit evidence.
>
> Built as the capstone for the **CGE-P (Certified GRC Engineer — Practitioner)** programme. Primary framework: **HIPAA Security Rule**, mapped to **NIST 800-53**.

![GRC Gate](https://img.shields.io/badge/CI-grc--gate-blue) ![Policy as Code](https://img.shields.io/badge/policy-OPA%2FRego-7D4698) ![OSCAL](https://img.shields.io/badge/compliance-OSCAL%20%7C%20NIST%20800--53-success) ![Evidence](https://img.shields.io/badge/evidence-Cosign%20%2B%20Object%20Lock-orange) ![License](https://img.shields.io/badge/license-MIT-green)

---

## What this project demonstrates

A complete **governance-as-code** lifecycle for a regulated cloud workload — the work a GRC engineer does to make compliance *continuous, automated, and provable* rather than a point-in-time spreadsheet exercise:

| Capability | How it's shown here |
|------------|---------------------|
| **Policy-as-Code** | OPA/Rego policies enforce the controls; `conftest`/`opa test` gate every change in CI. |
| **Control mapping (OSCAL)** | NIST 800-53 controls (`sc-28`, `sc-8`, `cp-9`, `ac-3`, `au-2`) expressed in OSCAL component definitions and a resolved HIPAA profile/catalog, validated with `trestle`. HIPAA Security Rule references carried as control properties. |
| **Compliant IaC primitives** | Terraform modules for encryption at rest (KMS), access logging, backup/retention, and least-privilege access — the technical controls behind the framework. |
| **Verifiable evidence** | CI signs evidence bundles with **Cosign** (keyless OIDC, logged to Rekor) and stores them in an **S3 Object-Lock vault** with retention — evidence that can be proven authentic *and* proven un-tampered. |
| **Secure CI/CD** | `grc-gate.yml`: plan → policy check → gated apply (merge to `main`) → sign → upload. Keyless OIDC, no long-lived cloud credentials. Secret scanning (gitleaks) + IaC scanning (checkov). |
| **Multi-cloud** | AWS (Security Hub findings, Object-Lock evidence vault) and GCP (Workload Identity Federation, organisation policy, audit logging). |

---

## How it fits together

```
        ┌─────────────┐   policy gate    ┌──────────────┐   sign + lock   ┌────────────────┐
  PR ──▶│  Terraform  │ ───────────────▶ │  OPA / Rego  │ ──────────────▶ │ Cosign + Rekor │
        │  (controls) │   opa/conftest   │  (the gate)  │   keyless OIDC  │  Object-Lock   │
        └─────────────┘                  └──────────────┘                 │     vault      │
               │                                                          └────────────────┘
               ▼                                                                   │
        ┌─────────────┐                                                            ▼
        │    OSCAL    │  NIST 800-53 ↔ HIPAA  ─────────────────────▶  evidence chain is
        │ control map │  (trestle-validated)                          integrity- + authenticity-
        └─────────────┘                                               verifiable end to end
```

The headline: a change to the workload cannot reach `main` without passing the policy gate, and every compliant state produces **signed, retention-locked evidence** whose authenticity chain (OSCAL → signed bundle → vault) can be replayed and verified by an auditor.

---

## My role

I took the deliberately non-compliant starter and **governed it to a defensible, auditable state**:
- Authored / completed the OPA/Rego policy set and wired it into the CI gate.
- Built the OSCAL control mapping and fixed real correctness bugs (illegal HIPAA control-id tokens → proper NIST 800-53 ids with HIPAA carried as properties; duplicate component UUID).
- Stood up the keyless-OIDC signing pipeline and the Object-Lock evidence vault, and **fixed a genuine security bug** in evidence verification (a Cosign certificate-identity regex that let authenticity checks pass without actually matching the signer).
- Demonstrated the full OSCAL → vault evidence-chain traversal (`CHAIN INTACT`: integrity + Cosign/Rekor authenticity + Object-Lock preservation).

---

## Verifying it yourself

```bash
make plan                       # show what the workload would deploy
scripts/policy-gate.sh          # run the OPA/Rego policy gate (conftest/opa)
scripts/capture-evidence.sh     # capture + Cosign-sign an evidence bundle
scripts/verify-evidence.sh <run-id>   # replay the chain → prints CHAIN INTACT
make destroy                    # tear it all down (avoid cloud charges)
```

> CI runs the same gate end-to-end in `.github/workflows/grc-gate.yml`; a GCP keyless-WIF demo lives in `gcp-wif-demo.yml`.

See **[WRITEUP.md](WRITEUP.md)** for the full narrative, **[COMPLIANCE.md](COMPLIANCE.md)** for the control-by-control status, **[FRAMEWORKS.md](FRAMEWORKS.md)** for the HIPAA↔NIST crosswalk, and **[GAPS.md](GAPS.md)** for the starter's intentional gaps and how each is closed.

---

## What's where

| Path | Contents |
|------|----------|
| `policies/` | OPA/Rego policies — the enforced controls |
| `terraform/` | Compliant IaC primitives (encryption, logging, retention, access) |
| `oscal/` | OSCAL component definitions, resolved HIPAA profile + catalog (trestle-validated) |
| `.github/workflows/grc-gate.yml` | The 5-step GRC pipeline (plan → policy → apply → sign → upload) |
| `scripts/` | Evidence signing + chain-verification tooling |
| `evidence/` | Captured, PII-free verification artifacts |
| `docs/` | Verification guide and supporting docs |

---

## Notes
- **Cost & teardown:** infrastructure is for assessment; see the teardown steps in the docs to avoid cloud charges.
- **License:** MIT.
- This repository is portfolio / educational work demonstrating GRC engineering practice.

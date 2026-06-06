# Profile: CGE-P HIPAA-minimum control selection

This OSCAL **profile** (`profile.json`) selects the controls the capstone component implements — the Layer 4 requirement *"a profile selecting the controls your component implements."*

## Why this profile imports 800-53, not HIPAA

The declared primary framework is the **HIPAA Security Rule**. NIST does not publish a HIPAA OSCAL catalog, so — consistent with the approach in `WRITEUP.md` and the component's `source` (NIST SP 800-66 Rev. 2) — the profile imports the **NIST SP 800-53 Rev. 5** catalog from `usnistgov/oscal-content` and `include-controls` selects the 800-53 controls that back each HIPAA citation.

## HIPAA → 800-53 crosswalk

| Component control-id (HIPAA) | Implements | 800-53 Rev. 5 controls selected |
|---|---|---|
| 164.312(a)(2)(iv) Encryption & decryption | PHI encryption at rest (CMK) | `sc-28`, `sc-13` |
| 164.312(e)(1) Transmission security | TLS-only bucket policy, Lambda in VPC, VPC endpoints | `sc-7`, `sc-8` |
| 164.308(a)(7) Contingency plan | S3 versioning, Object Lock on the evidence vault | `cp-9` |
| 164.312(a)(1) Access control | Least-privilege Lambda IAM, wildcard block in CI | `ac-3`, `ac-6` |
| 164.312(b) Audit controls | CloudTrail (multi-region, log-file validation), signed evidence vault | `au-2`, `au-12` |
| (cross-cutting hardening) | Required tags / configuration settings | `cm-6` |

## Validate

```bash
pip install compliance-trestle
trestle validate -f oscal/profiles/cge-p-hipaa-minimum/profile.json
trestle validate -f oscal/component-definitions/acme-patient-intake-api/component-definition.json
```

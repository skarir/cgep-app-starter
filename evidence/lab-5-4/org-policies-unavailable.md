# Lab 5.4 — Org Policy not available in this environment (honest gap)

`gcloud org-policies list --project=cgep-lab-sunil-2026` returns **0 items** (see `org-policies.txt`).
This is an **environment constraint, not a missing control**.

## Root cause

Project `cgep-lab-sunil-2026` is a **standalone project with no Organization parent**
(`gcloud projects describe ... --format='value(parent)'` is empty). The Organization
Policy Service requires an Organization resource as the hierarchy root. Attempting to
grant the required role fails:

```
$ gcloud projects add-iam-policy-binding cgep-lab-sunil-2026 \
    --member=user:sunil.karir@gmail.com --role=roles/orgpolicy.policyAdmin
ERROR: INVALID_ARGUMENT: Role roles/orgpolicy.policyAdmin is not supported for this resource.
```

A `cge-p` reference environment whose project sits under an Organization can create the
three constraints (`storage.uniformBucketLevelAccess`, `iam.disableServiceAccountKeyCreation`,
`compute.requireOsLogin`); a personal-Gmail standalone project cannot.

## What IS in place (the other two thirds of Lab 5.4)

| Control | Status | Evidence |
|---|---|---|
| Workload Identity Federation (replaces SA JSON keys) | **Applied** | `wif-pools.txt`, `wif-providers.txt` — provider scoped to `assertion.repository == "skarir/cgep-app-starter"` |
| Data Access audit logs (off by default in GCP) | **Applied** | `iam-policy.json` `auditConfigs` — DATA_READ + DATA_WRITE + ADMIN_READ on `storage`, `cloudkms`, `iam` |
| Org Policy (API-level rejection) | **Blocked — no Organization** | `org-policies.txt` (empty) + this note |

## Capstone impact

None. The capstone's preventative layer is the AWS baseline (Lab 5.2: CloudTrail,
KMS CMK, Object Lock) plus the OPA policy gate. Lab 5.4's GCP Org Policy is a
domain-5 study artefact, not on the capstone critical path. The WIF + Data Access
log controls above remain valid, applied, and evidenced.

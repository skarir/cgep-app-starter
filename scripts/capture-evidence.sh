#!/usr/bin/env bash
# capture-evidence.sh — bundle pipeline artefacts and upload to the
# S3 Object Lock evidence vault.
#
# Required environment variables:
#   EVIDENCE_BUCKET   — name of the Object Lock S3 bucket
#   RUN_ID            — unique run identifier (e.g. GitHub Actions run ID)
#
# Bundles:
#   plan.json             — terraform plan output
#   conftest-results.json — Conftest policy gate results
#   terraform.tfstate     — post-apply state (if present)
#
# Produces:
#   evidence-bundle-<RUN_ID>.tar.gz          — the bundle
#   evidence-bundle-<RUN_ID>.tar.gz.sha256   — SHA-256 checksum sidecar
set -euo pipefail

EVIDENCE_BUCKET="${EVIDENCE_BUCKET:?EVIDENCE_BUCKET is required}"
RUN_ID="${RUN_ID:?RUN_ID is required}"

BUNDLE_NAME="evidence-bundle-${RUN_ID}.tar.gz"
SHA_NAME="${BUNDLE_NAME}.sha256"
VAULT_PREFIX="runs/${RUN_ID}"

echo "Capturing evidence for run ${RUN_ID}..."

# Gather artefacts that exist
ARTEFACTS=()
for f in plan.json conftest-results.json terraform/terraform.tfstate; do
  [[ -f "$f" ]] && ARTEFACTS+=("$f")
done

if [[ ${#ARTEFACTS[@]} -eq 0 ]]; then
  echo "Warning: no artefact files found to bundle." >&2
fi

# Create the bundle
tar czf "$BUNDLE_NAME" "${ARTEFACTS[@]+"${ARTEFACTS[@]}"}"
echo "Bundle created: $BUNDLE_NAME"

# SHA-256 checksum (integrity)
sha256sum "$BUNDLE_NAME" | awk '{print $1}' > "$SHA_NAME"
echo "SHA-256: $(cat "$SHA_NAME")"

# Upload bundle and checksum to Object Lock vault
aws s3 cp "$BUNDLE_NAME" "s3://${EVIDENCE_BUCKET}/${VAULT_PREFIX}/${BUNDLE_NAME}"
aws s3 cp "$SHA_NAME"    "s3://${EVIDENCE_BUCKET}/${VAULT_PREFIX}/${SHA_NAME}"

echo "Uploaded to s3://${EVIDENCE_BUCKET}/${VAULT_PREFIX}/"
echo "BUNDLE_PATH=s3://${EVIDENCE_BUCKET}/${VAULT_PREFIX}/${BUNDLE_NAME}"

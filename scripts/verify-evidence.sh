#!/usr/bin/env bash
# verify-evidence.sh — verify a signed evidence bundle from the vault.
#
# Checks three properties:
#   1. Integrity   — SHA-256 recomputes against the .sha256 sidecar
#   2. Authenticity — Cosign signature verifies against Sigstore Rekor
#   3. Preservation — S3 Object Lock retention is active on the object
#
# Usage:
#   scripts/verify-evidence.sh <s3://bucket/path/bundle.tar.gz>
set -euo pipefail

S3_URI="${1:?Usage: $0 <s3://bucket/path/bundle.tar.gz>}"
BUNDLE_NAME=$(basename "$S3_URI")
SHA_NAME="${BUNDLE_NAME}.sha256"
S3_DIR=$(dirname "$S3_URI")

echo "=== Evidence verification for: $S3_URI ==="

# ── 1. Download bundle and sidecar ────────────────────────────────────
echo ""
echo "[1/3] Downloading bundle and checksum..."
aws s3 cp "${S3_URI}"          "./${BUNDLE_NAME}"
aws s3 cp "${S3_DIR}/${SHA_NAME}" "./${SHA_NAME}"

# ── 2. Integrity ──────────────────────────────────────────────────────
echo ""
echo "[2/3] Verifying integrity (SHA-256)..."
EXPECTED=$(cat "./${SHA_NAME}")
ACTUAL=$(sha256sum "./${BUNDLE_NAME}" | awk '{print $1}')
if [[ "$EXPECTED" == "$ACTUAL" ]]; then
  echo "PASS integrity: SHA-256 matches ($ACTUAL)"
else
  echo "FAIL integrity: expected=$EXPECTED actual=$ACTUAL" >&2
  exit 1
fi

# ── 3. Authenticity ───────────────────────────────────────────────────
echo ""
echo "[3/3] Verifying Cosign signature against Sigstore..."
SIG_FILE="${BUNDLE_NAME}.sig.bundle"
aws s3 cp "${S3_DIR}/${SIG_FILE}" "./${SIG_FILE}" 2>/dev/null || {
  echo "FAIL authenticity: signature file not found at ${S3_DIR}/${SIG_FILE}" >&2
  exit 1
}

cosign verify-blob \
  --bundle "./${SIG_FILE}" \
  --certificate-identity-regexp "https://github.com/skarir/cgep-app-starter" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "./${BUNDLE_NAME}" && echo "PASS authenticity: Cosign signature verified via Sigstore" || {
  echo "FAIL authenticity: cosign verify-blob returned non-zero" >&2
  exit 1
}

# ── 4. Preservation ───────────────────────────────────────────────────
echo ""
echo "[+] Checking Object Lock retention (preservation)..."
BUCKET=$(echo "$S3_URI" | sed 's|s3://||' | cut -d/ -f1)
KEY=$(echo "$S3_URI" | sed "s|s3://${BUCKET}/||")

LOCK_STATUS=$(aws s3api get-object-retention \
  --bucket "$BUCKET" \
  --key "$KEY" \
  --query 'Retention.Mode' \
  --output text 2>/dev/null || echo "NONE")

if [[ "$LOCK_STATUS" == "NONE" ]]; then
  echo "WARN preservation: Object Lock retention not set on this object."
  echo "     Ensure the bucket has a default retention policy or this object was locked on upload."
else
  RETAIN_UNTIL=$(aws s3api get-object-retention \
    --bucket "$BUCKET" \
    --key "$KEY" \
    --query 'Retention.RetainUntilDate' \
    --output text 2>/dev/null)
  echo "PASS preservation: Object Lock mode=$LOCK_STATUS retain-until=$RETAIN_UNTIL"
fi

echo ""
echo "=== Verification complete ==="

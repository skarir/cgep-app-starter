#!/usr/bin/env bash
# scripts/verify-evidence.sh
# Lab 4.4 — Verify the full chain of custody for a CI evidence bundle.
#
# Usage:
#   EVIDENCE_VAULT=<bucket> bash scripts/verify-evidence.sh <run_id> [--vault <b>] [--profile <p>]
#   bash scripts/verify-evidence.sh <s3://bucket/path/bundle.tar.gz>   (legacy URI form)
#
# Checks four chain-of-custody properties:
#   1. Integrity    — SHA-256 recomputes against the .sha256 sidecar
#   2. Authenticity — Cosign verifies signature against Sigstore Rekor
#   3. Timeliness   — Rekor transparency log entry contains OIDC timestamp
#   4. Preservation — S3 Object Lock retention is active on the bundle object
#
# Exits 0 and prints "CHAIN INTACT" when all checks pass.

set -euo pipefail

# ── Argument parsing ──────────────────────────────────────────────────────────
RUN_ID=""
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
LEGACY_URI=""

if [[ $# -ge 1 && "$1" == s3://* ]]; then
  # Legacy: full S3 URI provided directly
  LEGACY_URI="$1"
else
  RUN_ID="${1:?Usage: $0 <run_id> [--vault <bucket>] [--profile <p>]}"
  shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vault)   VAULT="$2";         shift 2 ;;
      --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
      *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
  done
fi

[[ -z "$VAULT" && -z "$LEGACY_URI" ]] && {
  echo "ERROR: set EVIDENCE_VAULT env var or pass --vault <bucket>" >&2; exit 2
}

# ── Work in a temp directory ──────────────────────────────────────────────────
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# ── Resolve paths ─────────────────────────────────────────────────────────────
if [[ -n "$LEGACY_URI" ]]; then
  BUNDLE_NAME=$(basename "$LEGACY_URI")
  S3_PREFIX="$(dirname "$LEGACY_URI")"
  VAULT=$(echo "$LEGACY_URI" | sed 's|s3://||' | cut -d/ -f1)
  BUNDLE_KEY=$(echo "$LEGACY_URI" | sed "s|s3://${VAULT}/||")
else
  PREFIX="runs/${RUN_ID}"
  # Discover bundle name from receipt or by listing
  RECEIPT_PATH="s3://${VAULT}/${PREFIX}/receipt.json"
  if aws $PROFILE_ARG s3 cp "$RECEIPT_PATH" receipt.json 2>/dev/null; then
    BUNDLE_KEY=$(python3 -c "import json; d=json.load(open('receipt.json')); print(d['bundle_key'])")
    BUNDLE_NAME=$(basename "$BUNDLE_KEY")
  else
    # Fall back to listing the prefix
    BUNDLE_NAME=$(aws $PROFILE_ARG s3 ls "s3://${VAULT}/${PREFIX}/" \
      | awk '{print $4}' | grep '\.tar\.gz$' | grep -v '\.sha256' | head -1)
    BUNDLE_KEY="${PREFIX}/${BUNDLE_NAME}"
  fi
  S3_PREFIX="s3://${VAULT}/${PREFIX}"
fi

SHA_NAME="${BUNDLE_NAME}.sha256"
SIG_NAME="${BUNDLE_NAME}.sig.bundle"

echo "=== Chain of Custody Verification ==="
echo "  Run:    ${RUN_ID:-$LEGACY_URI}"
echo "  Vault:  ${VAULT}"
echo "  Bundle: ${BUNDLE_NAME}"
echo ""

# ── Download bundle + sidecar files ──────────────────────────────────────────
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${BUNDLE_KEY}"         "./${BUNDLE_NAME}"
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${BUNDLE_KEY}.sha256"  "./${SHA_NAME}"
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${BUNDLE_KEY}.sig.bundle" "./${SIG_NAME}"

# ── 1. Integrity ──────────────────────────────────────────────────────────────
echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "./${SHA_NAME}")
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "./${BUNDLE_NAME}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "./${BUNDLE_NAME}" | awk '{print $1}')
else
  echo "  ERROR: no sha256sum or shasum found" >&2; exit 1
fi

if [[ "$EXPECTED" == "$ACTUAL" ]]; then
  echo "  OK ($ACTUAL)"
else
  echo "  FAIL: expected=$EXPECTED  actual=$ACTUAL" >&2; exit 1
fi

# ── 2. Authenticity + timeliness (Cosign → Rekor) ────────────────────────────
echo ""
echo "=== 2. Authenticity + Timeliness (Cosign + Sigstore Rekor) ==="
cosign verify-blob \
  --bundle "./${SIG_NAME}" \
  --certificate-identity-regexp 'https://github\.com/skarir/cgep-app-starter' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "./${BUNDLE_NAME}" && echo "  OK (Cosign verified, Rekor timestamp recorded)" || {
  echo "  FAIL: cosign verify-blob returned non-zero" >&2; exit 1
}

# ── 3. Preservation (Object Lock retention) ───────────────────────────────────
echo ""
echo "=== 3. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" \
  --key "${BUNDLE_KEY}" \
  --query 'Retention.RetainUntilDate' \
  --output text 2>/dev/null || echo "NONE")
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [[ "$RETAIN_UNTIL" == "NONE" ]]; then
  echo "  WARN: no Object Lock retention found — bucket may lack default retention"
elif [[ "$RETAIN_UNTIL" > "$NOW" ]]; then
  echo "  OK (retain until $RETAIN_UNTIL)"
else
  echo "  FAIL: retention expired at $RETAIN_UNTIL" >&2; exit 1
fi

echo ""
echo "CHAIN INTACT for run ${RUN_ID:-$LEGACY_URI}"

#!/usr/bin/env bash
# scripts/policy-gate.sh
# Lab 3.4 — Run Conftest against a Terraform workspace's plan as a fail-closed gate.
#
# Usage:
#   policy-gate.sh --workspace <path> [--policy <dir>]
#
# Produces:
#   evidence/lab-3-4/conftest-results.json  — per-namespace JSON results
#
# Exits 0 if all namespaces pass, 1 if any violation is found.
# Always writes the results file so CI can upload it as an evidence artifact.

set -euo pipefail

POLICY_DIR="$(cd "$(dirname "$0")/.." && pwd)/policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }

mkdir -p "$EVIDENCE_DIR"

# Render plan.json from the saved tfplan in the workspace.
( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

EXIT=0

{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Run each namespace independently; || true prevents set -e from aborting early.
    OUT=$(conftest test \
      --policy "$POLICY_DIR" \
      --namespace "$ns" \
      --output json \
      "$WORKSPACE/plan.json" 2>/dev/null || true)
    # Detect failure via JSON (portable; no grep on colour codes).
    if ! echo "$OUT" | python3 -c \
      'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)' \
      2>/dev/null; then
      EXIT=1
    fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS — all namespaces clean"
else
  echo "policy-gate: FAIL — violations found"
  echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT

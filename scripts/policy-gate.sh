#!/usr/bin/env bash
# scripts/policy-gate.sh
# Lab 3.4 / 4.3 — Conftest policy gate; two calling conventions:
#
#   CI (workflow):   bash scripts/policy-gate.sh <plan.json>
#   Local (Lab 3.4): bash scripts/policy-gate.sh --workspace <path>
#
# Env vars (optional overrides):
#   RESULTS_FILE   — where to write JSON output   (default: evidence/lab-3-4/conftest-results.json)
#   POLICY_DIR     — path to policies directory   (default: auto-detected relative to script)
#
# Exits 0 if all namespaces pass, 1 if any violation found.

set -euo pipefail

# ── Locate policies dir relative to this script ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY_DIR="${POLICY_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)/policies}"

# ── Parse arguments ───────────────────────────────────────────────────────
PLAN_FILE=""
WORKSPACE=""

if [[ $# -ge 1 && "$1" != "--"* ]]; then
  # Positional argument: policy-gate.sh <plan.json>  (CI calling convention)
  PLAN_FILE="$1"
else
  # Named argument: --workspace <path>  (Lab 3.4 local calling convention)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workspace) WORKSPACE="$2"; shift 2 ;;
      --policy)    POLICY_DIR="$2"; shift 2 ;;
      *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  if [[ -n "$WORKSPACE" ]]; then
    # Render plan.json from the workspace's saved tfplan
    ( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )
    PLAN_FILE="$WORKSPACE/plan.json"
  fi
fi

if [[ -z "$PLAN_FILE" ]]; then
  echo "Usage: $0 <plan.json>  OR  $0 --workspace <path>" >&2
  exit 2
fi

if [[ ! -f "$PLAN_FILE" ]]; then
  echo "ERROR: plan file not found: $PLAN_FILE" >&2
  exit 1
fi

# ── Output file ───────────────────────────────────────────────────────────
RESULTS_FILE="${RESULTS_FILE:-evidence/lab-3-4/conftest-results.json}"
mkdir -p "$(dirname "$RESULTS_FILE")"

# ── Run each namespace; capture JSON; determine pass/fail ─────────────────
EXIT=0

{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test \
      --policy "$POLICY_DIR" \
      --namespace "$ns" \
      --output json \
      "$PLAN_FILE" 2>/dev/null || true)
    if ! echo "$OUT" | python3 -c \
      'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)' \
      2>/dev/null; then
      EXIT=1
    fi
    echo "$OUT"
  done
  echo "]"
} > "$RESULTS_FILE"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS — all namespaces clean"
else
  echo "policy-gate: FAIL — violations found"
  echo "See $RESULTS_FILE"
fi
exit $EXIT

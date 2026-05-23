#!/usr/bin/env bash
# policy-gate.sh — run Conftest against a Terraform plan JSON file.
#
# Usage:
#   scripts/policy-gate.sh <plan.json>
#
# Exits 0 if all policies pass, non-zero if any policy fails.
# Always writes conftest-results.json regardless of pass/fail so CI
# can upload it as an evidence artifact (the pipeline uses || true
# on this script and checks the exit code in a follow-up step).
set -euo pipefail

PLAN_JSON="${1:-plan.json}"
RESULTS_FILE="${RESULTS_FILE:-conftest-results.json}"
POLICY_DIR="${POLICY_DIR:-policies}"

if [[ ! -f "$PLAN_JSON" ]]; then
  echo "Error: plan file not found: $PLAN_JSON" >&2
  exit 1
fi

echo "Running Conftest policy gate..."
echo "  Plan:    $PLAN_JSON"
echo "  Policies: $POLICY_DIR/"
echo "  Results: $RESULTS_FILE"
echo ""

# Run Conftest; capture exit code separately so we still write results
set +e
conftest test \
  --policy "$POLICY_DIR" \
  --output json \
  --all-namespaces \
  "$PLAN_JSON" > "$RESULTS_FILE" 2>&1
CONFTEST_EXIT=$?
set -e

# Pretty-print a summary from the JSON results
python3 - <<'PYEOF'
import json, sys, os

results_file = os.environ.get("RESULTS_FILE", "conftest-results.json")
try:
    with open(results_file) as f:
        results = json.load(f)
except Exception as e:
    print(f"Could not parse results: {e}")
    sys.exit(0)

total_fail = 0
for ns_result in results:
    namespace = ns_result.get("namespace", "unknown")
    failures = ns_result.get("failures", [])
    for failure in failures:
        total_fail += 1
        print(f"FAIL [{namespace}] {failure.get('msg', failure)}")
    successes = ns_result.get("successes", [])
    for success in successes:
        print(f"PASS [{namespace}] {success.get('msg', 'ok')}")

if total_fail:
    print(f"\n{total_fail} policy violation(s) found.")
else:
    print("\nAll policies passed.")
PYEOF

exit $CONFTEST_EXIT

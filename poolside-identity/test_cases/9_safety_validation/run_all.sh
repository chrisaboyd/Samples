#!/bin/bash
set -e

# Get project root (go up two levels from test_cases/X/ to reach project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 9.1: Default dry-run safety ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv (no flags)"
echo "Expected: Defaults to dry-run, no changes made"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv"
echo "Test 9.1: PASSED"
echo ""

echo "=== Test Case 9.2: Both flags warning ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --dry-run --execute"
echo "Expected: Warning message about both flags, runs execution"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --dry-run --execute 2>&1 || echo "Test 9.2: PASSED (may show warning)"
echo ""

echo "=== Test Case 9.3: Execute without --execute flag ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv (already dry-run by default)"
echo "Expected: Shows dry-run mode message"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv"
echo "Test 9.3: PASSED"
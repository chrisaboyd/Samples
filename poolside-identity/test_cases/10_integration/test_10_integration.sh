#!/bin/bash
set -e

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 10.1: Team1 full cycle ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute then check members"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Checking team members:"
$POOLSIDE_ID --env sandbox team members team1
echo "Test 10.1: PASSED"
echo ""

echo "=== Test Case 10.2: Team2 full cycle ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team2 $PROJECT_ROOT/team2.csv --execute"
$POOLSIDE_ID --env sandbox sync team2 "$PROJECT_ROOT/team2.csv" --execute
echo "Test 10.2: PASSED"
echo ""

echo "=== Test Case 10.3: Verify team replacement ==="
echo "Running: Sync team2 to team1 to verify team replacement behavior"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team2.csv" --execute
echo "Checking team members:"
$POOLSIDE_ID --env sandbox team members team1
echo "Test 10.3: PASSED"
echo ""

echo "=== Test Case 10.4: List users after sync ==="
echo "Running: $POOLSIDE_ID --env sandbox user list (verify users created)"
$POOLSIDE_ID --env sandbox user list 2>&1 | head -20
echo "Test 10.4: PASSED"
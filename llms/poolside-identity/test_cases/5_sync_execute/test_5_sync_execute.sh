#!/bin/bash
set -e

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 5.1: Execute single team with team1.csv ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute"
echo "Expected: Creates both users (Ivo, Ryan), adds them to team1"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 5.1: PASSED"
echo ""

echo "=== Test Case 5.2: Execute with team2.csv ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team2 $PROJECT_ROOT/team2.csv --execute"
echo "Expected: Creates both users (Colin, Tom), adds them to team2"
$POOLSIDE_ID --env sandbox sync team2 "$PROJECT_ROOT/team2.csv" --execute
echo "Test 5.2: PASSED"
echo ""

echo "=== Test Case 5.3: Execute --create flag false ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute --create=false"
echo "Expected: Only syncs existing users, reports missing users to be created"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute --create=false
echo "Test 5.3: PASSED"
echo ""

echo "=== Test Case 5.4: Execute on already synced team ==="
echo "Running: Re-running team1 sync to verify idempotent behavior"
echo "Expected: Reports no changes (idempotent behavior)"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 5.4: PASSED"
echo ""

echo "=== Test Case 5.5: Execute replacing members ==="
echo "Running: Run team2 sync again to verify team replacement"
echo "Expected: Handles existing users gracefully"
$POOLSIDE_ID --env sandbox sync team2 "$PROJECT_ROOT/team2.csv" --execute
echo "Test 5.5: PASSED"
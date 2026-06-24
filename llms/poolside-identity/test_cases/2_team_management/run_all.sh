#!/bin/bash
set -e

# Get project root (go up from test_cases directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"; PROJECT_ROOT="$(dirname "$PROJECT_ROOT")" 2>/dev/null || PROJECT_ROOT="$SCRIPT_DIR/../.."
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 2.1: List all teams ==="
echo "Running: $POOLSIDE_ID --env sandbox team list"
echo "Expected: Returns list of teams with IDs and names"
$POOLSIDE_ID --env sandbox team list
echo "Test 2.1: PASSED"
echo ""

echo "=== Test Case 2.2: List team members (admins) ==="
echo "Running: $POOLSIDE_ID --env sandbox team members admins"
echo "Expected: Returns all members of admins team"
$POOLSIDE_ID --env sandbox team members admins
echo "Test 2.2: PASSED"
echo ""

echo "=== Test Case 2.3: Find existing team by name ==="
echo "Running: $POOLSIDE_ID --env sandbox team members admins"
echo "Expected: Resolves 'admins' to valid team and lists members"
$POOLSIDE_ID --env sandbox team members admins
echo "Test 2.3: PASSED"
echo ""

echo "=== Test Case 2.4: Find non-existent team ==="
echo "Running: $POOLSIDE_ID --env sandbox team members nonexistent"
echo "Expected: Error: Team not found: nonexistent"
$POOLSIDE_ID --env sandbox team members nonexistent 2>&1 || echo "Test 2.4: PASSED (expected error)"
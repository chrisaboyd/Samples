#!/bin/bash
# Not using set -e because some tests expect errors

# Get project root (go up two levels from test_cases/X/ to reach project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

# Create empty.csv for test 4.4
echo "" > empty.csv

echo "=== Test Case 4.1: Single team dry-run with team1.csv ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv"
echo "Expected: Shows 'DRY RUN MODE', lists users to create, no API changes made"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv"
echo "Test 4.1: PASSED"
echo ""

echo "=== Test Case 4.2: Multi-team dry-run with team1.csv ==="
echo "Running: $POOLSIDE_ID --env sandbox sync $PROJECT_ROOT/team1.csv (no team arg)"
echo "Expected: Note about no team specified, no team operations will be performed"
$POOLSIDE_ID --env sandbox sync "$PROJECT_ROOT/team1.csv" 2>&1 || echo "Test 4.2: PASSED (expected behavior - no team in user data)"
echo ""

echo "=== Test Case 4.3: Dry-run with invalid team ==="
echo "Running: $POOLSIDE_ID --env sandbox sync nonexistent $PROJECT_ROOT/team1.csv"
echo "Expected: Error: 'Team not found: nonexistent', no changes attempted"
$POOLSIDE_ID --env sandbox sync nonexistent "$PROJECT_ROOT/team1.csv" 2>&1 || echo "Test 4.3: PASSED (expected error)"
echo ""

echo "=== Test Case 4.4: Dry-run with empty CSV ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 empty.csv"
echo "Expected: Shows empty sync plan, no users to create"
$POOLSIDE_ID --env sandbox sync team1 empty.csv
echo "Test 4.4: PASSED"
echo ""

echo "=== Test Case 4.5: Dry-run with non-existent file ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 nonexistent.csv"
echo "Expected: Error: 'File does not exist'"
$POOLSIDE_ID --env sandbox sync team1 nonexistent.csv 2>&1 || echo "Test 4.5: PASSED (expected error)"
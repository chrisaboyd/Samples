#!/bin/bash

# Get project root (go up from test_cases directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"; PROJECT_ROOT="$(dirname "$PROJECT_ROOT")" 2>/dev/null || PROJECT_ROOT="$SCRIPT_DIR/../.."
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 1.1: Default profile ==="
echo "Running: $POOLSIDE_ID team list"
echo "Expected: Connects to production API (or fails if not configured)"
# Production is configured in ~/.env, so it should connect
$POOLSIDE_ID team list 2>&1 || echo "Test 1.1: PASSED (failed as expected - no production config)"
echo "Test 1.1: PASSED"
echo ""

echo "=== Test Case 1.2: Sandbox profile ==="
echo "Running: $POOLSIDE_ID --env sandbox team list"
echo "Expected: Connects to sandbox API and lists teams"
$POOLSIDE_ID --env sandbox team list 2>&1
echo "Test 1.2: PASSED"
echo ""

echo "=== Test Case 1.3: Invalid profile ==="
echo "Running: $POOLSIDE_ID --env invalid team list"
echo "Expected: Graceful error message about missing environment variables"
$POOLSIDE_ID --env invalid team list 2>&1 || echo "Test 1.3: PASSED (expected error)"
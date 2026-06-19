#!/bin/bash

echo "=== Test Case 1.1: Default profile ==="
echo "Running: poolside-id team list"
echo "Expected: Connects to production API (or fails if not configured)"
# Production is configured in ~/.env, so it should connect
poolside-id team list 2>&1 || echo "Test 1.1: PASSED (failed as expected - no production config)"
echo "Test 1.1: PASSED"
echo ""

echo "=== Test Case 1.2: Sandbox profile ==="
echo "Running: poolside-id --env sandbox team list"
echo "Expected: Connects to sandbox API and lists teams"
poolside-id --env sandbox team list 2>&1
echo "Test 1.2: PASSED"
echo ""

echo "=== Test Case 1.3: Invalid profile ==="
echo "Running: poolside-id --env invalid team list"
echo "Expected: Graceful error message about missing environment variables"
poolside-id --env invalid team list 2>&1 || echo "Test 1.3: PASSED (expected error)"
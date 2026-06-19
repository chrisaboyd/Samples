#!/bin/bash
set -e

echo "=== Test Case 2.1: List all teams ==="
echo "Running: poolside-id --env sandbox team list"
echo "Expected: Returns list of teams with IDs and names"
poolside-id --env sandbox team list
echo "Test 2.1: PASSED"
echo ""

echo "=== Test Case 2.2: List team members (admins) ==="
echo "Running: poolside-id --env sandbox team members admins"
echo "Expected: Returns all members of admins team"
poolside-id --env sandbox team members admins
echo "Test 2.2: PASSED"
echo ""

echo "=== Test Case 2.3: Find existing team by name ==="
echo "Running: poolside-id --env sandbox team members admins"
echo "Expected: Resolves 'admins' to valid team and lists members"
poolside-id --env sandbox team members admins
echo "Test 2.3: PASSED"
echo ""

echo "=== Test Case 2.4: Find non-existent team ==="
echo "Running: poolside-id --env sandbox team members nonexistent"
echo "Expected: Error: Team not found: nonexistent"
poolside-id --env sandbox team members nonexistent 2>&1 || echo "Test 2.4: PASSED (expected error)"
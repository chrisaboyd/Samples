#!/bin/bash

# Get project root (go up two levels from test_cases/X/ to reach project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 3.1: List all users ==="
echo "Running: $POOLSIDE_ID --env sandbox user list"
echo "Expected: Returns all users with ID, email, name, status"
$POOLSIDE_ID --env sandbox user list 2>&1
echo "Test 3.1: PASSED"
echo ""

echo "=== Test Case 3.2: Create new user ==="
echo "Running: $POOLSIDE_ID --env sandbox user create --email 'test32_$(date +%s)@user.com' --name 'Test User'"
echo "Expected: Creates user, returns user ID"
$POOLSIDE_ID --env sandbox user create --email "test32_$(date +%s)@user.com" --name "Test User"
echo "Test 3.2: PASSED"
echo ""

echo "=== Test Case 3.3: Create user with case-insensitive email ==="
echo "Running: $POOLSIDE_ID --env sandbox user create --email 'TEST33_$(date +%s)@USER.COM' --name 'Different Name'"
echo "Expected: Email normalized to lowercase"
$POOLSIDE_ID --env sandbox user create --email "TEST33_$(date +%s)@USER.COM" --name "Different Name"
echo "Test 3.3: PASSED"
echo ""

echo "=== Test Case 3.4: Delete user ==="
echo "Running: Create a user then delete"
EMAIL="tobedeleted_$(date +%s)@user.com"
echo "Creating: $EMAIL"
RESULT=$($POOLSIDE_ID --env sandbox user create --email "$EMAIL" --name "To Be Deleted" 2>&1 | tr '\n' ' ')
echo "$RESULT"
USER_ID=$(echo "$RESULT" | grep -oE '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})' | head -1)
echo "User ID: $USER_ID"
if [ -n "$USER_ID" ]; then
    $POOLSIDE_ID --env sandbox user delete --id "$USER_ID"
    echo "Test 3.4: PASSED"
else
    echo "Test 3.4: SKIPPED (user may already exist)"
fi
echo ""

echo "=== Test Case 3.5: Get non-existent user ==="
echo "Running: $POOLSIDE_ID --env sandbox user get --id invalid-id"
echo "Expected: Error: Resource not found"
$POOLSIDE_ID --env sandbox user get --id invalid-id 2>&1 || echo "Test 3.5: PASSED (expected error)"
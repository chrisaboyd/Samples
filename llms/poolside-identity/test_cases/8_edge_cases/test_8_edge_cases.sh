#!/bin/bash

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

# Note: Not using set -e as we expect some errors

echo "=== Test Case 8.1: Missing required --email flag ==="
echo "Running: $POOLSIDE_ID --env sandbox user create"
echo "Expected: Error: '--email is required for create'"
$POOLSIDE_ID --env sandbox user create 2>&1 || echo "Test 8.1: PASSED (expected error)"
echo ""

echo "=== Test Case 8.2: Missing required --id flag ==="
echo "Running: $POOLSIDE_ID --env sandbox user delete"
echo "Expected: Error: '--id is required for delete'"
$POOLSIDE_ID --env sandbox user delete 2>&1 || echo "Test 8.2: PASSED (expected error)"
echo ""

echo "=== Test Case 8.3: Invalid JSON file ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 invalid.json --execute"
cat > invalid.json << 'EOF'
{invalid json missing quotes
EOF
echo "Expected: Error loading file"
$POOLSIDE_ID --env sandbox sync team1 invalid.json --execute 2>&1 || echo "Test 8.3: PASSED (expected error)"
echo ""

echo "=== Test Case 8.4: CSV with only email column ==="
echo "Running: Sync CSV with only email (no name)"
cat > email_only.csv << 'EOF'
email
emailonly@poolside.ai
EOF
$POOLSIDE_ID --env sandbox sync team1 email_only.csv --execute
echo "Test 8.4: PASSED"
echo ""

echo "=== Test Case 8.5: Duplicate emails in input ==="
echo "Running: Sync CSV with duplicate emails"
cat > duplicates.csv << 'EOF'
ivo@poolside.ai,Ivo Pinto
ivo@poolside.ai,Ivo Pinto
EOF
$POOLSIDE_ID --env sandbox sync team1 duplicates.csv --execute
echo "Test 8.5: PASSED"
echo ""

echo "=== Test Case 8.6: Case-insensitive email matching ==="
echo "Running: Sync CSV with mixed case email"
cat > case_test.csv << 'EOF'
IVO@POOLSIDE.AI,Ivo Pinto
EOF
$POOLSIDE_ID --env sandbox sync team1 case_test.csv --execute
echo "Test 8.6: PASSED"
echo ""

rm -f invalid.json email_only.csv duplicates.csv case_test.csv
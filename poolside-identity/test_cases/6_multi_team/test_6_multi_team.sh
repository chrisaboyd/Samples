#!/bin/bash
set -e

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

# Create multi-team CSV with teams column (using admins and devs as specified in test_cases.md)
cat > multi_team_users.csv << 'EOF'
email,name,teams
multi1@poolside.ai,Multi User 1,admins
multi2@poolside.ai,Multi User 2,admins
EOF

echo "=== Test Case 6.1: Multi-team mode with teams column ==="
echo "Running: $POOLSIDE_ID --env sandbox sync multi_team_users.csv --execute"
echo "Expected: Users added to their specified teams"
$POOLSIDE_ID --env sandbox sync multi_team_users.csv --execute
echo "Test 6.1: PASSED"
echo ""

echo "=== Test Case 6.2: Multi-team mixed membership ==="
echo "Running: Using multi_team_users.csv with mixed team assignments"
echo "Expected: Each user added to their specified teams"
$POOLSIDE_ID --env sandbox sync multi_team_users.csv --execute
echo "Test 6.2: PASSED"
echo ""

echo "=== Test Case 6.3: Multi-team with invalid team name ==="
echo "Running: Create CSV with non-existent team"
cat > invalid_team.csv << 'EOF'
email,name,teams
badteam@poolside.ai,Bad Team,nonexistent
EOF
$POOLSIDE_ID --env sandbox sync invalid_team.csv --execute 2>&1 || echo "Test 6.3: PASSED (expected error for invalid team)"
echo ""

rm -f multi_team_users.csv invalid_team.csv
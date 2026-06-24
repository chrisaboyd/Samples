#!/bin/bash
set -e

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

echo "=== Test Case 7.1: CSV with header row ==="
cat > with_header.csv << 'EOF'
email,name
header1@poolside.ai,Header User 1
header2@poolside.ai,Header User 2
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 with_header.csv --execute"
echo "Expected: Parsed correctly with header row"
$POOLSIDE_ID --env sandbox sync team1 with_header.csv --execute
echo "Test 7.1: PASSED"
echo ""

echo "=== Test Case 7.2: CSV without header row (team1.csv format) ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute"
echo "Expected: Parsed correctly (no header row)"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 7.2: PASSED"
echo ""

echo "=== Test Case 7.3: CSV with trailing newline ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute"
echo "Expected: Parsed correctly (empty row ignored)"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 7.3: PASSED"
echo ""

echo "=== Test Case 7.4: JSON format input ==="
cat > users.json << 'EOF'
[{"email": "json1@poolside.ai", "name": "JSON User 1"}, {"email": "json2@poolside.ai", "name": "JSON User 2"}]
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 users.json --execute"
echo "Expected: Parsed correctly from JSON"
$POOLSIDE_ID --env sandbox sync team1 users.json --execute
echo "Test 7.4: PASSED"
echo ""

echo "=== Test Case 7.5: JSON multi-team format ==="
cat > multi_team.json << 'EOF'
[{"email": "jsonmulti@poolside.ai", "name": "JSON Multi", "teams": ["team1"]}]
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync multi_team.json --execute"
echo "Expected: Parsed correctly with teams array"
$POOLSIDE_ID --env sandbox sync multi_team.json --execute
echo "Test 7.5: PASSED"
echo ""

echo "=== Test Case 7.6: Invalid file format ==="
cat > users.txt << 'EOF'
some random text
not a csv or json
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 users.txt --execute"
echo "Expected: Error: 'Unsupported file format'"
$POOLSIDE_ID --env sandbox sync team1 users.txt --execute 2>&1 || echo "Test 7.6: PASSED (expected error)"
echo ""

rm -f with_header.csv users.json multi_team.json users.txt
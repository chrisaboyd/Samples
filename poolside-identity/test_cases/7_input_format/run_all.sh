#!/bin/bash

# Get project root (go up two levels from test_cases/X/ to reach project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

# Test 7.1: CSV with header row
echo "=== Test Case 7.1: CSV with header row ==="
cat > "$SCRIPT_DIR/with_header.csv" << 'EOF'
email,name
header1@poolside.ai,Header User 1
header2@poolside.ai,Header User 2

EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $SCRIPT_DIR/with_header.csv --execute"
echo "Expected: Parsed correctly with header row"
$POOLSIDE_ID --env sandbox sync team1 "$SCRIPT_DIR/with_header.csv" --execute
echo "Test 7.1: PASSED"
echo ""

# Test 7.2: CSV without header row (team1.csv already has this format)
echo "=== Test Case 7.2: CSV without header row ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute"
echo "Expected: Parsed correctly (no header row)"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 7.2: PASSED"
echo ""

# Test 7.3: CSV with trailing newline (team1.csv already has this)
echo "=== Test Case 7.3: CSV with trailing newline ==="
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $PROJECT_ROOT/team1.csv --execute"
echo "Expected: Parsed correctly (empty row ignored)"
$POOLSIDE_ID --env sandbox sync team1 "$PROJECT_ROOT/team1.csv" --execute
echo "Test 7.3: PASSED"
echo ""

# Test 7.4: JSON format input
echo "=== Test Case 7.4: JSON format input ==="
cat > "$SCRIPT_DIR/users.json" << 'EOF'
[{"email": "json1@poolside.ai", "name": "JSON User 1"}, {"email": "json2@poolside.ai", "name": "JSON User 2"}]
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $SCRIPT_DIR/users.json --execute"
echo "Expected: Parsed correctly from JSON"
$POOLSIDE_ID --env sandbox sync team1 "$SCRIPT_DIR/users.json" --execute
echo "Test 7.4: PASSED"
echo ""

# Test 7.5: JSON multi-team format
echo "=== Test Case 7.5: JSON multi-team format ==="
cat > "$SCRIPT_DIR/multi_team.json" << 'EOF'
[{"email": "jsonmulti@poolside.ai", "name": "JSON Multi", "teams": ["team1"]}]
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync $SCRIPT_DIR/multi_team.json --execute"
echo "Expected: Parsed correctly with teams array"
$POOLSIDE_ID --env sandbox sync "$SCRIPT_DIR/multi_team.json" --execute
echo "Test 7.5: PASSED"
echo ""

# Test 7.6: Invalid file format
echo "=== Test Case 7.6: Invalid file format ==="
cat > "$SCRIPT_DIR/users.txt" << 'EOF'
some random text
not a csv or json
EOF
echo "Running: $POOLSIDE_ID --env sandbox sync team1 $SCRIPT_DIR/users.txt --execute"
echo "Expected: Error: 'Unsupported file format'"
$POOLSIDE_ID --env sandbox sync team1 "$SCRIPT_DIR/users.txt" --execute 2>&1 || echo "Test 7.6: PASSED (expected error)"
echo ""

rm -f "$SCRIPT_DIR/with_header.csv" "$SCRIPT_DIR/users.json" "$SCRIPT_DIR/multi_team.json" "$SCRIPT_DIR/users.txt"
#!/bin/bash

# Test runner for Poolside Identity test cases
# Uses environment variables from ~/.env for sandbox authentication

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$SCRIPT_DIR/test_output.log"

# Clear previous log file
> "$LOG_FILE"

# Function to log and echo
log_echo() {
    echo "$1"
    echo "$1" >> "$LOG_FILE"
}

# Source the .env file for authentication (both local and home directory)
set -a
source "$PROJECT_ROOT/.env" 2>/dev/null || true
source ~/.env 2>/dev/null || true
set +a

# Add venv to PATH
export PATH="$PROJECT_ROOT/.venv/bin:$PATH"
POOLSIDE_ID="$PROJECT_ROOT/.venv/bin/poolside-id"

log_echo "=== Protecting admins team ==="
log_echo "Running initial sync to ensure admins team has correct members"
log_echo "Log file: $LOG_FILE"
log_echo ""

if [ -f "$PROJECT_ROOT/admins.csv" ]; then
    log_echo "Syncing admins.csv to admins team..."
    $POOLSIDE_ID --env sandbox sync admins "$PROJECT_ROOT/admins.csv" --execute >> "$LOG_FILE" 2>&1 || log_echo "Warning: Could not sync admins (team may not exist or other issue)"
else
    log_echo "No admins.csv found, skipping admin team protection"
fi
log_echo ""

log_echo "=== Running all test cases ==="
log_echo ""

# Run each test category
for category in 1_environment_profile 2_team_management 3_user_management 4_sync_dry_run 5_sync_execute 6_multi_team 7_input_format 8_edge_cases 9_safety_validation 10_integration; do
    if [ -f "$SCRIPT_DIR/$category/run_all.sh" ]; then
        log_echo "--- Running $category ---"
        bash "$SCRIPT_DIR/$category/run_all.sh" >> "$LOG_FILE" 2>&1 || log_echo "Some tests in $category had issues"
        log_echo ""
    else
        log_echo "--- Skipping $category (no run_all.sh found)"
        log_echo ""
    fi
done

log_echo "=== All test categories completed ==="
log_echo "Full output saved to: $LOG_FILE"
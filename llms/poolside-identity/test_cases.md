# Test Plan: Poolside Identity Tool Testing Strategy

## Overview

A comprehensive test plan covering all functional aspects of the Poolside Identity CLI tool for user/team management and sync operations. Tests use `team1.csv` (Ivo Pinto, Ryan Hammond) and `team2.csv` (Colin Baird, Tom George) as input datasets, targeting the sandbox environment via `--env sandbox`.

## Test Cases by Category

### 1. Environment Profile Tests

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 1.1 Default profile | `poolside-id team list` | Connects to production API (or fails if not configured) |
| 1.2 Sandbox profile | `poolside-id --env sandbox team list` | Connects to sandbox API using POOLSIDE_API_BASE_SANDBOX/POOLSIDE_API_KEY_SANDBOX |
| 1.3 Invalid profile | `poolside-id --env invalid team list` | Graceful error message about missing environment variables |

### 2. Team Management Tests

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 2.1 List all teams | `poolside-id --env sandbox team list` | Returns list of teams with IDs and names |
| 2.2 List team members | `poolside-id --env sandbox team members <team-name>` | Returns all members of specified team |
| 2.3 Find existing team by name | `poolside-id --env sandbox team members admins` | Resolves "admins" to valid team and lists members |
| 2.4 Find non-existent team | `poolside-id --env sandbox team members nonexistent` | Error: "Team not found: nonexistent" |

### 3. User Management Tests

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 3.1 List all users | `poolside-id --env sandbox user list` | Returns all users with ID, email, name, status |
| 3.2 Create new user | `poolside-id --env sandbox user create --email "new+test@user.com" --name "Test User"` | Creates user, returns user ID |
| 3.3 Create user with case-insensitive email | `poolside-id --env sandbox user create --email "NEW+TEST@USER.COM" --name "Different Name"` | Email normalized to lowercase |
| 3.4 Delete user | `poolside-id --env sandbox user delete --id <user-id>` | Deletes user successfully |
| 3.5 Get non-existent user | `poolside-id --env sandbox user get --id invalid-id` | Error: "Resource not found" |

### 4. Sync Operations - Dry Run Tests (No Changes)

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 4.1 Single team dry-run with team1.csv | `poolside-id --env sandbox sync admins team1.csv` | Shows "DRY RUN MODE", lists users to create, no API changes made |
| 4.2 Multi-team dry-run with team1.csv | `poolside-id --env sandbox sync team1.csv` | Error or creates users without team assignment (file has no teams column) |
| 4.3 Dry-run with invalid team | `poolside-id --env sandbox sync nonexistent team1.csv` | Error: "Team not found: nonexistent", no changes attempted |
| 4.4 Dry-run with empty CSV | `poolside-id --env sandbox sync admins empty.csv` (create empty file) | Shows empty sync plan, no users to create |
| 4.5 Dry-run with non-existent file | `poolside-id --env sandbox sync admins nonexistent.csv` | Error: "File does not exist" |

### 5. Sync Operations - Execute Mode Tests

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 5.1 Execute single team with team1.csv | `poolside-id --env sandbox sync admins team1.csv --execute` | Creates both users (Ivo, Ryan), adds them to admins team |
| 5.2 Execute with team2.csv | `poolside-id --env sandbox sync admins team2.csv --execute` | Creates both users (Colin, Tom), adds them to admins team |
| 5.3 Execute --create flag false | `poolside-id --env sandbox sync admins team1.csv --execute --create-missing=false` | Only syncs existing users, reports missing users to be created |
| 5.4 Execute on already synced team | First run 5.1, then run again | Reports no changes (idempotent behavior) |
| 5.5 Execute replacing members | Run 5.1 with team1, then run 5.2 with team2 on same team | Removes Ivo/Ryan from team, adds Colin/Tom to team |

### 6. Multi-Team Sync Tests

| Test Case | Input File Format | Expected Outcome |
|-----------|------------------|----------------|
| 6.1 Multi-team mode with teams column | CSV: `email,name,teams` with `user@ex.com,User,admins,devs` | User added to both admins and devs teams |
| 6.2 Multi-team mixed membership | Users in team1.csv format spread across teams | Each user added to their specified teams |
| 6.3 Multi-team with invalid team name | CSV with non-existent team in teams column | Error for invalid team, handles gracefully |

### 7. Input Format Tests (CSV Parsing)

| Test Case | Input Format | Expected Outcome |
|-----------|--------------|----------------|
| 7.1 CSV with header row | `email,name` header + data rows | Parsed correctly |
| 7.2 CSV without header row | `email,name` format (team1.csv format) | Parsed correctly |
| 7.3 CSV with trailing newline | team1.csv has trailing newline | Parsed correctly (empty row ignored) |
| 7.4 JSON format input | `[{"email": "...", "name": "..."}]` | Parsed correctly |
| 7.5 JSON multi-team format | `[{"email": "...", "teams": ["team-a", "team-b"]}]` | Parsed correctly |
| 7.6 Invalid file format | `users.txt` | Error: "Unsupported file format" |

### 8. Edge Cases & Error Handling

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 8.1 Missing required --email flag | `poolside-id --env sandbox user create` | Error: "Error: --email is required for create" |
| 8.2 Missing required --id flag | `poolside-id --env sandbox user delete` | Error: "Error: --id is required for delete" |
| 8.3 Invalid JSON file | Malformed JSON input | Error: "Error loading file" |
| 8.4 CSV with only email column | `ivo@poolside.ai` only | Name defaults to null, user created with email only |
| 8.5 Duplicate emails in input | Same email twice in CSV | Handled gracefully (idempotent) |
| 8.6 Case-insensitive email matching | `IVO@POOLSIDE.AI` vs `ivo@poolside.ai` | Treated as same user |

### 9. Safety & Validation Tests

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 9.1 Default dry-run safety | `poolside-id --env sandbox sync admins team1.csv` (no flags) | Defaults to dry-run, no changes made |
| 9.2 Both flags warning | `poolside-id --env sandbox sync admins team1.csv --dry-run --execute` | Warning message: "Both --dry-run and --execute specified", runs execution |
| 9.3 Execute without --execute flag | `poolside-id --env sandbox sync admins team1.csv` | Shows dry-run mode message (safe default) |

### 10. Integration Tests (Using team1.csv and team2.csv)

| Test Case | Input | Expected Outcome |
|-----------|-------|----------------|
| 10.1 Team1 full cycle | `poolside-id --env sandbox sync target-team team1.csv --execute` then `team members target-team` | Both Ivo and Ryan visible in target-team |
| 10.2 Team2 full cycle | `poolside-id --env sandbox sync target-team team2.csv --execute` then `team members target-team` | Both Colin and Tom visible in target-team |
| 10.3 Verify team replacement | Run 10.1, then 10.2 on same team | target-team now has only Colin/Tom (Ivo/Ryan removed) |
| 10.4 List users after sync | After 10.1, `poolside-id --env sandbox user list` | Both Ivo and Ryan visible in user list |
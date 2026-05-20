# Poolside Identity V1 API

A Python library and CLI tool for managing Poolside users and teams via the Identity V1 API, without requiring SCIM.

## Features

- **User management**: Create, update, suspend, restore, and delete users
- **Team management**: List teams and manage membership
- **Sync operations**: Sync team membership from CSV/JSON input
- **Safety-first**: Dry-run mode is default for sync operations
- **Type-safe**: Full Pydantic models for API responses
- **Async/await**: Built with httpx for async HTTP

## Installation

```bash
# From source
cd poolside-identity
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

## Configuration

Set environment variables (or copy `.env.example` to `.env`):

```bash
export POOLSIDE_API_BASE="https://api.poolside.ai"  # Your Poolside API URL
export POOLSIDE_API_KEY="your-api-key"               # Service account API key
```

## CLI Usage

### List Teams

```bash
poolside-id team list
```

### List Team Members

```bash
poolside-id team members engineering
```

### Sync Users (Dry-Run Preview)

```bash
# Preview changes without making them
poolside-id sync engineering users.csv

# With JSON input
poolside-id sync engineering users.json
```

### Sync Users (Execute)

```bash
# Apply the changes
poolside-id sync engineering users.csv --execute
```

### Create a User

```bash
poolside-id user create --email "user@example.com" --name "John Doe"
```

### List All Users

```bash
poolside-id user list
```

### Delete a User

```bash
poolside-id user delete --id <user-id>
```

## Input File Formats

### CSV Format

```csv
email,name
alice@example.com,Alice Smith
bob@example.com,Bob Jones
```

### JSON Format

```json
[
  {"email": "alice@example.com", "name": "Alice Smith"},
  {"email": "bob@example.com", "name": "Bob Jones"}
]
```

## Python Library Usage

```python
import asyncio
from poolside_identity import PoolsideIdentityClient, get_client_from_env

async def main():
    async with get_client_from_env() as client:
        # List all teams
        teams = await client.list_teams()
        for team in teams:
            print(f"{team.id}: {team.name}")

        # Find a team by name
        team_id = await client.resolve_team("engineering")

        # List team members
        members = await client.list_team_members(team_id)

        # Sync users to a team
        from poolside_identity import execute_sync, plan_sync

        user_data = [
            {"email": "user@example.com", "name": "New User"}
        ]

        # Preview changes
        plan = await plan_sync(client, "engineering", user_data)
        print(f"Would create {len(plan.users_to_create)} users")

        # Execute changes
        result = await execute_sync(client, "engineering", user_data)
        print(f"Created {result.users_created} users")

asyncio.run(main())
```

## API Reference

### User Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list_users()` | GET `/poolside/v1/users` | List users (filter by email, status, team) |
| `get_user(id)` | GET `/poolside/v1/users/{id}` | Get a user by ID |
| `create_user(email, name, teams)` | POST `/poolside/v1/users` | Create a new user |
| `update_user(id, email, name, status_action)` | PATCH `/poolside/v1/users/{id}` | Update user properties |
| `delete_user(id)` | DELETE `/poolside/v1/users/{id}` | Delete a user |
| `list_user_teams(id)` | GET `/poolside/v1/users/{id}/teams` | List teams for a user |

### Team Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| `list_teams()` | GET `/poolside/v1/teams` | List teams (filter by name) |
| `get_team(id)` | GET `/poolside/v1/teams/{id}` | Get a team by ID |
| `find_team(identifier)` | - | Find team by ID or name |
| `resolve_team(identifier)` | - | Get team ID from ID or name (raises if not found) |
| `list_team_members(id)` | GET `/poolside/v1/teams/{id}/members` | List team members |
| `set_team_members(id, user_ids)` | POST `/poolside/v1/teams/{id}/members/set` | Replace membership |
| `add_team_members(id, user_ids)` | POST `/poolside/v1/teams/{id}/members/add` | Add members |
| `remove_team_members(id, user_ids)` | POST `/poolside/v1/teams/{id}/members/remove` | Remove members |

## Prerequisites

- A Poolside account with tenant-admin privileges
- A team with the "Provision Users with SCIM" permission
- A service account API key

See [Poolside Identity Management API docs](https://docs.poolside.ai/organization/identity-management-api) for setup instructions.

## License

MIT
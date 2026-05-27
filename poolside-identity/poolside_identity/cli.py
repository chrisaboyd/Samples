"""Command-line interface for Poolside Identity API."""

import asyncio
import csv
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from poolside_identity import (
    PoolsideIdentityClient,
    execute_sync,
    get_client_from_env,
    plan_sync,
)
from poolside_identity.exceptions import PoolsideIdentityError

app = typer.Typer(
    name="poolside-id",
    help="Manage Poolside users and teams via the Identity V1 API\n\nExamples:\n  poolside-id --env sandbox team list\n  poolside-id --env sandbox team members admins\n  poolside-id --env sandbox user list\n  poolside-id --env sandbox user create --email user@example.com --name \"User Name\"\n  poolside-id --env sandbox sync team1 users.csv\n  poolside-id --env sandbox sync --execute team1 users.csv\n  poolside-id --env sandbox sync all_users.csv  # multi-team mode",
    no_args_is_help=True,
)
console = Console()


def compact_table(title: str, *columns: tuple[str, str]) -> Table:
    """Create a compact table with minimal padding.

    Args:
        title: Table title
        columns: Tuples of (column_name, style) for each column

    Returns:
        Configured Table instance with compact styling
    """
    table = Table(title=title, pad_edge=False, collapse_padding=True)
    for col_name, style in columns:
        table.add_column(col_name, style=style)
    return table

# Global state for environment profile
_env_profile: Optional[str] = None


@app.callback()
def set_env_profile(
    ctx: typer.Context,
    env: Optional[str] = typer.Option(
        None,
        "--env",
        help="Environment profile (sandbox, production). Uses POOLSIDE_API_BASE_SANDBOX and POOLSIDE_API_KEY_SANDBOX if specified.",
    ),
) -> None:
    """Set the global environment profile from the --env option."""
    global _env_profile
    _env_profile = env


def get_client() -> PoolsideIdentityClient:
    """Get API client from environment.

    Uses the global --env option if set to determine which profile to use.
    """
    env = _env_profile

    try:
        return get_client_from_env(env=env)
    except PoolsideIdentityError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print(
            "[yellow]Set POOLSIDE_API_BASE and POOLSIDE_API_KEY environment variables.[/yellow]"
        )
        console.print(
            "[dim]Tip: You can also create a .env file in your project root or home directory.[/dim]"
        )
        if env:
            console.print(
                f"[dim]For profile '{env}', set POOLSIDE_API_BASE_{env.upper()} and POOLSIDE_API_KEY_{env.upper()}[/dim]"
            )
        sys.exit(1)


async def async_main(func):
    """Run async function with client context."""
    client = get_client()
    async with client:
        return await func(client)


@app.command()
def sync(
    team: Optional[str] = typer.Argument(
        None,
        help="Team name or ID to sync (omit for multi-team mode where users specify their teams)",
    ),
    users_file: Path = typer.Argument(
        ...,
        exists=True,
        help="CSV or JSON file with users (must have 'email' column/key)",
    ),
    create_missing: bool = typer.Option(
        True,
        "--create",
        help="Create users that don't exist",
    ),
    dry_run: bool = typer.Option(
        True,
        "--dry-run",
        help="Show what would happen without making changes",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Actually perform the changes (required for writes)",
    ),
    force_empty: bool = typer.Option(
        False,
        "--force-empty",
        help="Allow sync to remove all members from a team (dangerous!)",
    ),
):
    """Sync users to a team.

    Examples:
        poolside-id sync team1 users.csv              # Preview sync for team1
        poolside-id sync --execute team1 users.csv      # Execute sync for team1
        poolside-id sync users.csv                    # Multi-team mode (teams column in CSV)
        poolside-id sync --execute --force-empty team1 users.csv  # Allow emptying team

    By default, runs in dry-run mode to preview changes.
    Use --execute to actually modify users and team membership.

    User file format (CSV):
        email,name[,teams]
        user1@example.com,User One,team-a,team-b
        user2@example.com,User Two,team-a

    Or with header row:
        email,name,teams
        user1@example.com,User One,team-a,team-b

    JSON format with single team:
        [{"email": "user1@example.com", "name": "User One"}]

    JSON format with multiple teams:
        [{"email": "user1@example.com", "name": "User One", "teams": ["team-a", "team-b"]}]
    """
    if dry_run and execute:
        console.print("[yellow]Warning: Both --dry-run and --execute specified. Running in execute mode.[/yellow]")

    if execute:
        # Actually perform changes
        pass
    elif dry_run:
        console.print("[bold blue]🔍 DRY RUN MODE[/bold blue] - No changes will be made")
    else:
        console.print("[red]Error:[/red] Use --execute to actually perform changes. Safety first!")
        raise typer.Exit(1)

    # Load users from file
    user_data = []
    suffix = users_file.suffix.lower()

    try:
        if suffix == ".csv":
            with open(users_file, "r") as f:
                content = f.read().strip()
                # Check if first line looks like a header (contains 'email' or similar)
                first_line = content.split("\n")[0].lower() if content else ""
                has_header = "email" in first_line and "name" in first_line

                f.seek(0)
                if has_header:
                    reader = csv.DictReader(f)
                    for row in reader:
                        row_dict = dict(row)
                        # Parse teams column as comma-separated list if present
                        if row_dict.get("teams"):
                            row_dict["teams"] = [t.strip() for t in row_dict["teams"].split(",") if t.strip()]
                        user_data.append(row_dict)
                else:
                    # No header - assume format is email,name[,teams]
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 1:
                            user_dict = {"email": row[0].strip(), "name": row[1].strip() if len(row) > 1 else None}
                            # Third column as teams (comma-separated)
                            if len(row) > 2 and row[2].strip():
                                user_dict["teams"] = [t.strip() for t in row[2].split(",") if t.strip()]
                            user_data.append(user_dict)
        elif suffix == ".json":
            with open(users_file, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    user_data = data
                else:
                    user_data = [data]
        else:
            console.print(f"[red]Error:[/red] Unsupported file format: {suffix}")
            console.print("Use .csv or .json files")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error loading file:[/red] {e}")
        raise typer.Exit(1)

    # Validate that we have team information for sync
    if not team and not any(user.get("teams") for user in user_data):
        if execute:
            console.print("[red]Error:[/red] No team specified and no teams in user data. Use <team> argument for single-team mode or add 'teams' column for multi-team mode.")
            raise typer.Exit(1)
        else:
            console.print("[yellow]Note: No team specified and no teams in user data. No team operations will be performed.[/yellow]")

    async def run(client: PoolsideIdentityClient):
        if execute:
            result = await execute_sync(client, team, user_data, create_missing=create_missing, force_empty=force_empty)
            _display_sync_result(result)
        else:
            plan = await plan_sync(client, team, user_data, create_missing=create_missing)
            _display_sync_plan(plan)

    asyncio.run(async_main(run))


def _display_sync_plan(plan):
    """Display a sync plan in a formatted table."""
    if plan.team_name or plan.team_id:
        console.print(f"\n[bold]Sync Plan for Team:[/bold] {plan.team_name or plan.team_id}")
    else:
        console.print("\n[bold]Sync Plan:[/bold] No team specified")

    if plan.users_to_create:
        table = compact_table("Users to Create", ("Email", "cyan"), ("Name", "green"))
        for u in plan.users_to_create:
            table.add_row(u["email"], u.get("name", "-"))
        console.print(table)

    if plan.users_to_update:
        table = compact_table("Users to Update", ("ID", "dim"), ("Name", "green"))
        for u in plan.users_to_update:
            table.add_row(u["id"][:8] + "...", u["name"])
        console.print(table)

    if plan.user_ids_to_remove:
        console.print(f"\n[bold yellow]Users to Remove from Team:[/bold yellow] {len(plan.user_ids_to_remove)}")

    # Show message if no changes are planned
    if not plan.users_to_create and not plan.users_to_update and not plan.user_ids_to_remove:
        console.print("\n[green]No changes needed[/green]")

    console.print(f"\n[dim]Run with --execute to apply changes[/dim]")


def _display_sync_result(result):
    """Display sync execution result."""
    console.print("\n[bold green]✓ Sync Complete[/bold green]")
    console.print(f"  Users created: {result.total_users_created}")
    console.print(f"  Users updated: {result.total_users_updated}")
    console.print(f"  Memberships added: {result.total_memberships_added}")
    console.print(f"  Memberships removed: {result.total_memberships_removed}")


@app.command("user")
def user_cmd(
    action: str = typer.Argument(
        ...,
        help="Action: list, get, create, update, delete, suspend, restore",
    ),
    email: Optional[str] = typer.Option(None, "--email", help="User email"),
    name: Optional[str] = typer.Option(None, "--name", help="User name"),
    user_id: Optional[str] = typer.Option(None, "--id", help="User ID"),
):
    """Manage users.

    Examples:
        poolside-id user list
        poolside-id user create --email user@example.com --name "User Name"
        poolside-id user get --id 019dda90...
        poolside-id user delete --id 019dda90...
    """
    async def run(client: PoolsideIdentityClient):
        if action == "list":
            users = await client.list_users()
            table = compact_table("Users", ("ID", "dim"), ("Email", "cyan"), ("Name", "green"), ("Status", "yellow"))
            for u in users:
                table.add_row(u.id[:8] + "...", u.email, u.name or "-", u.status)
            console.print(table)

        elif action == "create":
            if not email:
                console.print("[red]Error:[/red] --email is required for create")
                raise typer.Exit(1)
            user = await client.create_user(email=email, name=name)
            console.print(f"[green]Created user:[/green] {user.email} ({user.id})")

        elif action == "delete":
            if not user_id:
                console.print("[red]Error:[/red] --id is required for delete")
                raise typer.Exit(1)
            await client.delete_user(user_id)
            console.print(f"[green]Deleted user:[/green] {user_id}")

        elif action == "get":
            if not user_id:
                console.print("[red]Error:[/red] --id is required for get")
                raise typer.Exit(1)
            try:
                user = await client.get_user(user_id)
                table = compact_table("User", ("ID", "dim"), ("Email", "cyan"), ("Name", "green"), ("Status", "yellow"))
                table.add_row(user.id, user.email, user.name or "-", user.status)
                console.print(table)
            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)

        else:
            console.print(f"[red]Error:[/red] Unknown action: {action}")

    asyncio.run(async_main(run))


@app.command("team")
def team_cmd(
    action: str = typer.Argument(
        ...,
        help="Action: list, members",
    ),
    identifier: Optional[str] = typer.Argument(None, help="Team name or ID"),
):
    """Manage teams.

    Examples:
        poolside-id team list
        poolside-id team members admins
        poolside-id team members 019dda90...
    """
    async def run(client: PoolsideIdentityClient):
        if action == "list":
            teams = await client.list_teams()
            table = compact_table("Teams", ("ID", "dim"), ("Name", "cyan"))
            for t in teams:
                table.add_row(t.id[:8] + "...", t.name)
            console.print(table)

        elif action == "members":
            if not identifier:
                console.print("[red]Error:[/red] Team identifier required")
                raise typer.Exit(1)
            team = await client.find_team(identifier)
            if not team:
                console.print(f"[red]Error:[/red] Team not found: {identifier}")
                raise typer.Exit(1)
            members = await client.list_team_members(team.id)
            table = compact_table(f"Members of {team.name}", ("Email", "cyan"), ("Name", "green"), ("Status", "yellow"))
            for m in members:
                table.add_row(m.email, m.name or "-", m.status or "active")
            console.print(table)

        else:
            console.print(f"[red]Error:[/red] Unknown action: {action}")

    asyncio.run(async_main(run))


if __name__ == "__main__":
    app()
"""Command-line interface for Poolside Identity API."""

import asyncio
import csv
import json
import os
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
    help="Manage Poolside users and teams via the Identity V1 API",
)
console = Console()


def get_client() -> PoolsideIdentityClient:
    """Get API client from environment."""
    try:
        return get_client_from_env()
    except PoolsideIdentityError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print(
            "[yellow]Set POOLSIDE_API_BASE and POOLSIDE_API_KEY environment variables.[/yellow]"
        )
        sys.exit(1)


async def async_main(func):
    """Run async function with client context."""
    client = get_client()
    async with client:
        return await func(client)


@app.command()
def sync(
    team: str = typer.Argument(..., help="Team name or ID to sync"),
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
):
    """Sync users to a team.

    By default, runs in dry-run mode to preview changes.
    Use --execute to actually modify users and team membership.

    User file format (CSV):
        email,name
        user1@example.com,User One
        user2@example.com,User Two

    User file format (JSON):
        [{"email": "user1@example.com", "name": "User One"}]
    """
    if dry_run and execute:
        console.print("[yellow]Warning: Both --dry-run and --execute specified. Running in execute mode.[/yellow]")

    if dry_run:
        console.print("[bold blue]🔍 DRY RUN MODE[/bold blue] - No changes will be made")
    elif not execute:
        console.print("[red]Error:[/red] Use --execute to actually perform changes. Safety first!")
        raise typer.Exit(1)

    # Load users from file
    user_data = []
    suffix = users_file.suffix.lower()

    try:
        if suffix == ".csv":
            with open(users_file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    user_data.append(dict(row))
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

    async def run(client: PoolsideIdentityClient):
        if dry_run:
            plan = await plan_sync(client, team, user_data, create_missing=create_missing)
            _display_sync_plan(plan)
        else:
            result = await execute_sync(client, team, user_data, create_missing=create_missing)
            _display_sync_result(result)

    asyncio.run(async_main(run))


def _display_sync_plan(plan):
    """Display a sync plan in a formatted table."""
    console.print(f"\n[bold]Sync Plan for Team:[/bold] {plan.team_name or plan.team_id}")

    if plan.users_to_create:
        table = Table(title="Users to Create")
        table.add_column("Email", style="cyan")
        table.add_column("Name", style="green")
        for u in plan.users_to_create:
            table.add_row(u["email"], u.get("name", "-"))
        console.print(table)

    if plan.users_to_update:
        table = Table(title="Users to Update")
        table.add_column("Email", style="cyan")
        table.add_column("Name", style="green")
        for u in plan.users_to_update:
            table.add_row(u["email"], u["name"])
        console.print(table)

    if plan.user_ids_to_remove:
        console.print(f"\n[bold yellow]Users to Remove from Team:[/bold yellow] {len(plan.user_ids_to_remove)}")

    console.print(f"\n[dim]Run with --execute to apply changes[/dim]")


def _display_sync_result(result):
    """Display sync execution result."""
    console.print("\n[bold green]✓ Sync Complete[/bold green]")
    console.print(f"  Users created: {result.users_created}")
    console.print(f"  Users updated: {result.users_updated}")
    console.print(f"  Memberships added: {result.memberships_added}")
    console.print(f"  Memberships removed: {result.memberships_removed}")


@app.command("user")
def user_cmd(
    action: str = typer.Argument(
        ...,
        help="Action: list, get, create, update, delete, suspend, restore",
    ),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="User email"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="User name"),
    user_id: Optional[str] = typer.Option(None, "--id", help="User ID"),
):
    """Manage users."""
    async def run(client: PoolsideIdentityClient):
        if action == "list":
            users = await client.list_users()
            table = Table(title="Users")
            table.add_column("ID", style="dim")
            table.add_column("Email", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Status", style="yellow")
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
    """Manage teams."""
    async def run(client: PoolsideIdentityClient):
        if action == "list":
            teams = await client.list_teams()
            table = Table(title="Teams")
            table.add_column("ID", style="dim")
            table.add_column("Name", style="cyan")
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
            table = Table(title=f"Members of {team.name}")
            table.add_column("Email", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Status", style="yellow")
            for m in members:
                table.add_row(m.email, m.name or "-", m.status)
            console.print(table)

        else:
            console.print(f"[red]Error:[/red] Unknown action: {action}")

    asyncio.run(async_main(run))


if __name__ == "__main__":
    app()
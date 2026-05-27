"""Synchronization operations for Poolside Identity API."""

from typing import Optional

from poolside_identity.client import PoolsideIdentityClient
from poolside_identity.models import (
    BulkStats,
    SyncPlan,
    SyncResult,
    User,
)
from poolside_identity.operations import teams, users


async def plan_sync(
    client: PoolsideIdentityClient,
    team_identifier: Optional[str] = None,
    user_data: Optional[list[dict]] = None,
    create_missing: bool = True,
) -> SyncPlan:
    """Create a sync plan without executing.

    Args:
        client: The API client instance
        team_identifier: Single team name or ID (for backward compatibility)
        user_data: List of user dicts with 'email' and optional 'name', 'teams'
        create_missing: Whether to create users that don't exist

    Returns:
        SyncPlan with planned changes
    """
    user_data = user_data or []
    plan = SyncPlan()

    # Build a mapping of team identifiers to user data
    # If team_identifier specified, all users go into that team
    # Otherwise, users specify their own teams
    team_membership: dict[str, list[dict]] = {}  # team_id -> list of user dicts

    for user_dict in user_data:
        email = user_dict["email"].lower()
        name = user_dict.get("name")
        user_teams = user_dict.get("teams", [])

        if team_identifier:
            # Single team mode - all users go into the specified team
            team = await client.find_team(team_identifier)
            if team:
                plan.team_name = team.name
                plan.team_id = team.id
            team_id = await client.resolve_team(team_identifier)
            if team_id not in team_membership:
                team_membership[team_id] = []
            team_membership[team_id].append({"email": email, "name": name})
        elif user_teams:
            # Multi-team mode - each user specifies their teams
            for team_name in user_teams:
                team = await client.find_team(team_name)
                if team:
                    if team.id not in team_membership:
                        team_membership[team.id] = []
                    team_membership[team.id].append({"email": email, "name": name})
                else:
                    # Team not found in multi-team mode - this is an error
                    from poolside_identity.exceptions import NotFoundError
                    raise NotFoundError(f"Team not found: {team_name}")

    # For single-team mode, always initialize the team membership even if user_data is empty
    # This allows us to compute what members to remove when syncing an empty user list
    if team_identifier and not team_membership:
        team = await client.find_team(team_identifier)
        if team:
            plan.team_name = team.name
            plan.team_id = team.id
        team_id = await client.resolve_team(team_identifier)
        team_membership[team_id] = []

    # For each team, calculate what needs to change
    for team_id, team_users in team_membership.items():
        # Get existing team members for this specific team
        existing_members = await teams.list_team_members(client, team_id)
        existing_member_map = {m.id: m for m in existing_members}

        user_ids_to_add = []
        user_ids_to_remove = []
        desired_emails_for_team = set()

        for user_dict in team_users:
            email = user_dict["email"]
            desired_emails_for_team.add(email)

            existing_users = await users.list_users(client, email=email)

            if existing_users:
                user = existing_users[0]
                user_ids_to_add.append(user.id)

                # Check if update needed
                if user_dict.get("name") and user.name != user_dict["name"]:
                    plan.users_to_update.append({"id": user.id, "name": user_dict["name"]})
            else:
                # User doesn't exist
                if create_missing:
                    plan.users_to_create.append({"email": email, "name": user_dict.get("name")})

        # Users to remove from this team (those not in desired list for this team)
        for member in existing_members:
            if member.email.lower() not in desired_emails_for_team:
                user_ids_to_remove.append(member.id)

        plan.team_syncs[team_id] = {
            "user_ids_to_add": user_ids_to_add,
            "user_ids_to_remove": user_ids_to_remove,
        }

        # For single-team mode, also set user_ids_to_remove on the plan for display
        if team_identifier:
            plan.user_ids_to_remove = user_ids_to_remove

    return plan


async def execute_sync(
    client: PoolsideIdentityClient,
    team_identifier: Optional[str] = None,
    user_data: Optional[list[dict]] = None,
    create_missing: bool = True,
    force_empty: bool = False,
) -> SyncResult:
    """Execute a sync operation.

    Warning: This modifies Poolside users and team membership!

    Args:
        client: The API client instance
        team_identifier: Single team name or ID (for backward compatibility)
        user_data: List of user dicts with 'email' and optional 'name', 'teams'
        create_missing: Whether to create users that don't exist
        force_empty: Allow sync to result in empty team membership

    Returns:
        SyncResult with execution statistics
    """
    plan = await plan_sync(client, team_identifier, user_data, create_missing)
    result = SyncResult()

    users_created = 0
    users_updated = 0

    # Create missing users
    for user_dict in plan.users_to_create:
        await users.create_user(
            client,
            email=user_dict["email"],
            name=user_dict.get("name"),
        )
        users_created += 1

    # Update existing users
    for user_dict in plan.users_to_update:
        await users.update_user(
            client,
            user_id=user_dict["id"],
            name=user_dict["name"],
        )
        users_updated += 1

    # Execute team syncs
    total_added = 0
    total_removed = 0

    for team_id, team_plan in plan.team_syncs.items():
        # Safety check: Warn if this would wipe all team members
        if not team_plan["user_ids_to_add"] and team_plan["user_ids_to_remove"] and not force_empty:
            # This would result in an empty team - warn but allow it
            from poolside_identity.exceptions import PoolsideIdentityError
            raise PoolsideIdentityError(
                f"Sync would remove all members from team. Use --force-empty to confirm destructive team wipe."
            )

        if team_plan["user_ids_to_add"] or team_plan["user_ids_to_remove"]:
            memberships = await teams.set_team_members(
                client,
                team_id,
                team_plan["user_ids_to_add"],
            )
            total_added += memberships.added
            total_removed += memberships.removed

            result.team_results.append({
                "team_id": team_id,
                "memberships_added": memberships.added,
                "memberships_removed": memberships.removed,
            })

    result.total_users_created = users_created
    result.total_users_updated = users_updated
    result.total_memberships_added = total_added
    result.total_memberships_removed = total_removed

    return result
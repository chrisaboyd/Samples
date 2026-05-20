"""Team operations for Poolside Identity API."""

from typing import Optional

from poolside_identity.models import (
    BulkStats,
    Team,
    User,
    UserIdentifiers,
)


async def list_teams(
    client,
    name: Optional[str] = None,
    name_prefix: Optional[str] = None,
) -> list[Team]:
    """List teams with optional filtering.

    Args:
        client: The API client instance
        name: Exact team name match
        name_prefix: Team name prefix match

    Returns:
        List of Team objects
    """
    params = {}
    if name:
        params["name"] = name
    if name_prefix:
        params["name_prefix"] = name_prefix

    items = []
    next_url = "/poolside/v1/teams"

    while next_url:
        response = await client._request("GET", next_url, params=params)
        raw_items = response.get("teams", [])
        items.extend([Team.model_validate(item) for item in raw_items])

        next_url = response.get("links", {}).get("next")
        if next_url and next_url.startswith(client.base_url):
            next_url = next_url.replace(client.base_url, "")
        params = None

    return items


async def get_team(client, team_id: str) -> Team:
    """Get a specific team by ID.

    Args:
        client: The API client instance
        team_id: The team's unique identifier

    Returns:
        Team object
    """
    response = await client._request("GET", f"/poolside/v1/teams/{team_id}")
    return Team.model_validate(response)


async def find_team_by_name(client, identifier: str) -> Optional[Team]:
    """Find a team by exact name or name prefix.

    Args:
        client: The API client instance
        identifier: Team name or partial name

    Returns:
        Team object or None if not found
    """
    # Try exact name match first
    teams = await list_teams(client, name=identifier)
    if teams:
        return teams[0]

    # Try prefix match
    teams = await list_teams(client, name_prefix=identifier)
    if teams:
        # If multiple matches, return the best match or raise
        return teams[0]

    return None


async def list_team_members(client, team_id: str) -> list[User]:
    """List members of a team.

    Args:
        client: The API client instance
        team_id: The team's unique identifier

    Returns:
        List of User objects who are team members
    """
    response = await client._request("GET", f"/poolside/v1/teams/{team_id}/members")
    from poolside_identity.models import ListUsersPage

    page = ListUsersPage.model_validate(response)
    return page.users


async def set_team_members(client, team_id: str, user_ids: list[str]) -> BulkStats:
    """Replace team membership with exact list of users.

    Args:
        client: The API client instance
        team_id: The team's unique identifier
        user_ids: List of user IDs to set as team members

    Returns:
        BulkStats with added/removed counts
    """
    body = UserIdentifiers(user_ids=user_ids)
    response = await client._request(
        "POST",
        f"/poolside/v1/teams/{team_id}/members/set",
        json_data=body.model_dump(),
    )
    return BulkStats.model_validate(response)


async def add_team_members(client, team_id: str, user_ids: list[str]) -> BulkStats:
    """Add users to a team without affecting existing members.

    Args:
        client: The API client instance
        team_id: The team's unique identifier
        user_ids: List of user IDs to add

    Returns:
        BulkStats with added/removed counts
    """
    body = UserIdentifiers(user_ids=user_ids)
    response = await client._request(
        "POST",
        f"/poolside/v1/teams/{team_id}/members/add",
        json_data=body.model_dump(),
    )
    return BulkStats.model_validate(response)


async def remove_team_members(client, team_id: str, user_ids: list[str]) -> BulkStats:
    """Remove users from a team without affecting other members.

    Args:
        client: The API client instance
        team_id: The team's unique identifier
        user_ids: List of user IDs to remove

    Returns:
        BulkStats with added/removed counts
    """
    body = UserIdentifiers(user_ids=user_ids)
    response = await client._request(
        "POST",
        f"/poolside/v1/teams/{team_id}/members/remove",
        json_data=body.model_dump(),
    )
    return BulkStats.model_validate(response)
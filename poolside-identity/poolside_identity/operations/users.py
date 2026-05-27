"""User operations for Poolside Identity API."""

from typing import Optional

from poolside_identity.models import (
    CreateUserBody,
    ListUsersPage,
    UpdateUserBody,
    User,
)


async def list_users(
    client,
    email: Optional[str] = None,
    status: Optional[str] = None,
    team: Optional[str] = None,
) -> list[User]:
    """List users with optional filtering.

    Args:
        client: The API client instance
        email: Filter by exact email match (case-insensitive)
        status: Filter by status (comma-separated)
        team: Filter by team ID

    Returns:
        List of User objects
    """
    params = {}
    if email:
        params["email"] = email.lower()
    if status:
        params["status"] = status
    if team:
        params["team"] = team

    items = []
    next_url = "/poolside/v1/users"

    while next_url:
        response = await client._request("GET", next_url, params=params)
        raw_items = response.get("users") or []
        items.extend([User.model_validate(item) for item in raw_items])

        next_url = response.get("links", {}).get("next")
        if next_url and next_url.startswith(client.base_url):
            next_url = next_url.replace(client.base_url, "")
        params = None

    return items


async def get_user(client, user_id: str) -> User:
    """Get a specific user by ID.

    Args:
        client: The API client instance
        user_id: The user's unique identifier

    Returns:
        User object
    """
    response = await client._request("GET", f"/poolside/v1/users/{user_id}")
    return User.model_validate(response)


async def create_user(
    client,
    email: str,
    name: Optional[str] = None,
    team_ids: Optional[list[str]] = None,
) -> User:
    """Create a new user.

    Args:
        client: The API client instance
        email: User's email address
        name: Optional display name
        team_ids: Optional list of team IDs to add user to

    Returns:
        Created User object
    """
    body = CreateUserBody(
        email=email.lower(),
        name=name,
        teams=[{"id": tid} for tid in team_ids] if team_ids else None,
    )
    response = await client._request("POST", "/poolside/v1/users", json_data=body.model_dump(exclude_none=True))
    return User.model_validate(response)


async def update_user(
    client,
    user_id: str,
    email: Optional[str] = None,
    name: Optional[str] = None,
    status_action: Optional[str] = None,
) -> User:
    """Update a user's properties.

    Args:
        client: The API client instance
        user_id: The user's unique identifier
        email: New email address
        name: New display name
        status_action: "suspend" or "unsuspend" to change user status

    Returns:
        Updated User object
    """
    body = UpdateUserBody(
        email=email.lower() if email else None,
        name=name,
        status_action=status_action,
    )
    response = await client._request(
        "PATCH",
        f"/poolside/v1/users/{user_id}",
        json_data=body.model_dump(exclude_none=True),
    )
    return User.model_validate(response)


async def delete_user(client, user_id: str) -> None:
    """Delete a user.

    Args:
        client: The API client instance
        user_id: The user's unique identifier
    """
    await client._request("DELETE", f"/poolside/v1/users/{user_id}")


async def list_user_teams(client, user_id: str) -> list:
    """List teams a user belongs to.

    Args:
        client: The API client instance
        user_id: The user's unique identifier

    Returns:
        List of Team objects
    """
    response = await client._request("GET", f"/poolside/v1/users/{user_id}/teams")
    from poolside_identity.models import ListUserTeamsPage

    page = ListUserTeamsPage.model_validate(response)
    return page.teams
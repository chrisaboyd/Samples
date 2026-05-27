"""Poolside Identity V1 API client."""

import os
from pathlib import Path
from typing import Optional

import httpx

from poolside_identity.exceptions import (
    APIError,
    APIKeyError,
    NotFoundError,
)
from poolside_identity.models import (
    BulkStats,
    Team,
    TeamMember,
    UpdateUserBody,
    User,
)
from poolside_identity.operations import teams, users


class PoolsideIdentityClient:
    """Async client for Poolside Identity V1 API."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
    ):
        """Initialize the client.

        Args:
            base_url: Base URL for the Poolside API (e.g., "https://api.example.com")
            api_key: API key for authentication
            timeout: Request timeout in seconds

        Raises:
            APIKeyError: If api_key is not provided
        """
        if not api_key:
            raise APIKeyError("API key is required. Set POOLSIDE_API_KEY environment variable.")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make an HTTP request to the API.

        Args:
            method: HTTP method
            path: API endpoint path
            json_data: JSON body for POST/PATCH requests
            params: Query parameters

        Returns:
            Response JSON as dictionary

        Raises:
            NotFoundError: If resource not found (404)
            APIError: For other API errors
        """
        try:
            response = await self._client.request(
                method,
                path,
                json=json_data,
                params=params,
            )

            if response.status_code == 404:
                raise NotFoundError(f"Resource not found: {path}")
            elif response.status_code >= 400:
                try:
                    error_data = response.json()
                    error = error_data.get("detail", error_data.get("title", "Unknown error"))
                except Exception:
                    error = response.text
                raise APIError(
                    f"API error {response.status_code}: {error}",
                    status_code=response.status_code,
                    detail=error,
                )

            if response.status_code == 204:
                return {}
            return response.json()

        except httpx.HTTPError as e:
            raise APIError(f"HTTP error: {e}") from e

    async def _paginate(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
    ) -> list[dict]:
        """Handle paginated API responses.

        Args:
            method: HTTP method
            path: API endpoint path
            params: Query parameters

        Returns:
            Combined list of all items across pages
        """
        items = []
        next_url = path

        while next_url:
            response = await self._request(method, next_url, params=params)
            items.extend(response.get("users", response.get("teams", [])))

            # Check for next page
            next_url = response.get("links", {}).get("next")
            # If next is a full URL, extract just the path
            if next_url and next_url.startswith("http"):
                next_url = next_url.replace(self.base_url, "")
            params = None  # Only use params on first request

        return items

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "PoolsideIdentityClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    # User operations - delegate to operations/users.py
    async def list_users(
        self,
        email: Optional[str] = None,
        status: Optional[str] = None,
        team: Optional[str] = None,
    ) -> list[User]:
        """List users with optional filtering."""
        return await users.list_users(self, email=email, status=status, team=team)

    async def get_user(self, user_id: str) -> User:
        """Get a user by ID."""
        return await users.get_user(self, user_id)

    async def create_user(
        self,
        email: str,
        name: Optional[str] = None,
        team_ids: Optional[list[str]] = None,
    ) -> User:
        """Create a user."""
        return await users.create_user(self, email=email, name=name, team_ids=team_ids)

    async def update_user(
        self,
        user_id: str,
        email: Optional[str] = None,
        name: Optional[str] = None,
        status_action: Optional[str] = None,
    ) -> User:
        """Update a user."""
        return await users.update_user(
            self,
            user_id=user_id,
            email=email,
            name=name,
            status_action=status_action,
        )

    async def delete_user(self, user_id: str) -> None:
        """Delete a user."""
        return await users.delete_user(self, user_id)

    async def list_user_teams(self, user_id: str) -> list[Team]:
        """List teams a user belongs to."""
        return await users.list_user_teams(self, user_id)

    # Team operations - delegate to operations/teams.py
    async def list_teams(
        self,
        name: Optional[str] = None,
        name_prefix: Optional[str] = None,
    ) -> list[Team]:
        """List teams with optional filtering."""
        return await teams.list_teams(self, name=name, name_prefix=name_prefix)

    async def get_team(self, team_id: str) -> Team:
        """Get a team by ID."""
        return await teams.get_team(self, team_id)

    async def find_team(self, identifier: str) -> Optional[Team]:
        """Find a team by ID or name.

        Args:
            identifier: Team ID or team name

        Returns:
            Team object if found, None otherwise
        """
        from pydantic_core import ValidationError

        # Try as ID first (UUID format)
        try:
            return await self.get_team(identifier)
        except (NotFoundError, ValidationError):
            pass

        # Try as name
        return await teams.find_team_by_name(self, identifier)

    async def resolve_team(self, identifier: str) -> str:
        """Resolve team name or ID to team ID.

        Args:
            identifier: Team ID or team name

        Returns:
            Team ID

        Raises:
            NotFoundError: If team not found
        """
        team = await self.find_team(identifier)
        if not team:
            raise NotFoundError(f"Team not found: {identifier}")
        return team.id

    async def list_team_members(self, team_id: str) -> list[TeamMember]:
        """List team members."""
        return await teams.list_team_members(self, team_id)

    async def set_team_members(self, team_id: str, user_ids: list[str]) -> BulkStats:
        """Set team membership exactly."""
        return await teams.set_team_members(self, team_id, user_ids)

    async def add_team_members(self, team_id: str, user_ids: list[str]) -> BulkStats:
        """Add members to team."""
        return await teams.add_team_members(self, team_id, user_ids)

    async def remove_team_members(self, team_id: str, user_ids: list[str]) -> BulkStats:
        """Remove members from team."""
        return await teams.remove_team_members(self, team_id, user_ids)


def get_client_from_env(env: Optional[str] = None) -> PoolsideIdentityClient:
    """Create a client from environment variables.

    Required environment variables:
        POOLSIDE_API_BASE: Base URL for the Poolside API
        POOLSIDE_API_KEY: API key for authentication

    For environment profiles (e.g., sandbox, production):
        POOLSIDE_API_BASE_SANDBOX: Sandbox base URL
        POOLSIDE_API_KEY_SANDBOX: Sandbox API key

    This function automatically loads environment variables from:
        1. .env file in the current working directory
        2. ~/.env file in your home directory

    Args:
        env: Optional environment profile name (e.g., "sandbox", "production").
             When provided, looks for POOLSIDE_API_BASE_{PROFILE} and
             POOLSIDE_API_KEY_{PROFILE} first.

    Returns:
        Configured PoolsideIdentityClient

    Raises:
        APIKeyError: If required environment variables are missing
    """
    # Auto-load .env files for convenience
    try:
        from dotenv import load_dotenv

        # Load .env from current directory (if exists)
        load_dotenv(".env", override=False)
        # Also check ~/.env as a fallback
        load_dotenv(Path.home() / ".env", override=False)
    except ImportError:
        pass  # python-dotenv not available, use existing env vars

    # Determine env prefix for profile-specific variables
    env_upper = env.upper() if env else None
    prefix = f"POOLSIDE_API_"

    # Try profile-specific variables first if env is provided
    if env_upper:
        base_url = (
            os.getenv(f"{prefix}BASE_{env_upper}")
            or os.getenv(f"{prefix}BASE_URL_{env_upper}")
            or os.getenv(f"POOLSIDE_BASE_URL_{env_upper}")
            or os.getenv(f"POOLSIDE_BASE_{env_upper}")
        )
        api_key = os.getenv(f"{prefix}KEY_{env_upper}")

        # If profile-specific variables not found but default env vars exist, don't fall back
        # This ensures invalid profiles error out instead of silently using defaults
        if not base_url or not api_key:
            if not base_url:
                raise APIKeyError(
                    f"POOLSIDE_API_BASE_{env_upper} environment variable is required for profile '{env}'. "
                    f"Set it or create a .env file with POOLSIDE_API_BASE_{env_upper}=<url>"
                )
            if not api_key:
                raise APIKeyError(
                    f"POOLSIDE_API_KEY_{env_upper} environment variable is required for profile '{env}'. "
                    f"Set it or create a .env file with POOLSIDE_API_KEY_{env_upper}=<key>"
                )
    else:
        base_url = None
        api_key = None

    # Fall back to default variables (only when no profile specified)
    base_url = base_url or os.getenv("POOLSIDE_API_BASE") or os.getenv("POOLSIDE_BASE_URL")
    api_key = api_key or os.getenv("POOLSIDE_API_KEY")

    if not base_url:
        if env:
            raise APIKeyError(
                f"POOLSIDE_API_BASE_{env_upper} environment variable is required for profile '{env}'. "
                f"Set it or create a .env file with POOLSIDE_API_BASE_{env_upper}=<url>"
            )
        raise APIKeyError(
            "POOLSIDE_API_BASE environment variable is required. "
            "Set it or create a .env file with POOLSIDE_API_BASE=<url>"
        )

    return PoolsideIdentityClient(base_url=base_url, api_key=api_key)
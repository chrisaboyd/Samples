"""Poolside Identity V1 API client library.

A Python library for managing Poolside users and teams via the Identity V1 API.

Usage:
    from poolside_identity import PoolsideIdentityClient, get_client_from_env

    # Using environment variables
    async with get_client_from_env() as client:
        users = await client.list_users()

    # Or with explicit credentials
    async with PoolsideIdentityClient(
        base_url="https://api.example.com",
        api_key="your-api-key"
    ) as client:
        teams = await client.list_teams()
"""

from poolside_identity.client import PoolsideIdentityClient, get_client_from_env
from poolside_identity.models import (
    BulkStats,
    ErrorModel,
    ListTeamsPage,
    ListUsersPage,
    SyncPlan,
    SyncResult,
    Team,
    TeamMember,
    User,
    UserIdentifiers,
)
from poolside_identity.sync import execute_sync, plan_sync

__all__ = [
    "PoolsideIdentityClient",
    "get_client_from_env",
    "User",
    "Team",
    "TeamMember",
    "BulkStats",
    "UserIdentifiers",
    "ListUsersPage",
    "ListTeamsPage",
    "ErrorModel",
    "SyncPlan",
    "SyncResult",
    "plan_sync",
    "execute_sync",
]
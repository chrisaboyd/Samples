"""Pydantic models for Poolside Identity V1 API."""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, EmailStr


class UserStatus(str):
    """User status values."""

    CREATED = "created"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class User(BaseModel):
    """Represents a Poolside user."""

    model_config = ConfigDict(extra="ignore")

    id: str
    email: EmailStr
    status: Literal["created", "active", "suspended", "deleted"]
    name: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    teams: Optional[dict] = None  # ListUserTeamsPage as raw dict for list endpoints


class UserAttributes(BaseModel):
    """User attributes containing SCIM data."""

    model_config = ConfigDict(extra="forbid")

    scim: Optional[dict] = None


class TeamRef(BaseModel):
    """Reference to a team by ID."""

    model_config = ConfigDict(extra="forbid")

    id: str


class Team(BaseModel):
    """Represents a Poolside team."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str


class Links(BaseModel):
    """Pagination links."""

    model_config = ConfigDict(extra="forbid")

    next: Optional[str] = None


class ListUsersPage(BaseModel):
    """Paginated list of users."""

    model_config = ConfigDict(extra="forbid")

    users: list[User]
    links: Links


class ListUserTeamsPage(BaseModel):
    """Paginated list of user teams."""

    model_config = ConfigDict(extra="forbid")

    teams: list[Team]
    links: Links


class ListTeamsPage(BaseModel):
    """Paginated list of teams."""

    model_config = ConfigDict(extra="forbid")

    teams: list[Team]
    links: Links


class CreateUserBody(BaseModel):
    """Request body for creating a user."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    name: Optional[str] = None
    teams: Optional[list[TeamRef]] = None


class UpdateUserBody(BaseModel):
    """Request body for updating a user."""

    model_config = ConfigDict(extra="forbid")

    email: Optional[EmailStr] = None
    name: Optional[str] = None
    status_action: Optional[Literal["suspend", "unsuspend"]] = None


class UserIdentifiers(BaseModel):
    """Request body for team membership operations."""

    model_config = ConfigDict(extra="forbid")

    user_ids: list[str]


class BulkStats(BaseModel):
    """Result of bulk membership operations."""

    model_config = ConfigDict(extra="forbid")

    added: int
    removed: int


class ErrorDetail(BaseModel):
    """Detailed error information."""

    location: Optional[str] = None
    message: Optional[str] = None
    value: Optional[str] = None


class ErrorModel(BaseModel):
    """API error response."""

    type: str = "about:blank"
    title: str
    status: int
    detail: Optional[str] = None
    errors: Optional[list[ErrorDetail]] = None
    instance: Optional[str] = None


# Sync-specific models


class SyncPlan(BaseModel):
    """Dry-run plan showing what would happen during sync."""

    model_config = ConfigDict(extra="forbid")

    # Per-team sync plans
    team_syncs: dict[str, dict] = {}  # team_id -> {user_ids_to_add, user_ids_to_remove}
    # Users to create (with optional team assignments)
    users_to_create: list[dict] = []
    # Users to update
    users_to_update: list[dict] = []


class SyncResult(BaseModel):
    """Result of executing a sync operation."""

    model_config = ConfigDict(extra="forbid")

    team_results: list[dict] = []  # List of {team_id, memberships_added, memberships_removed}
    total_users_created: int = 0
    total_users_updated: int = 0
    total_memberships_added: int = 0
    total_memberships_removed: int = 0
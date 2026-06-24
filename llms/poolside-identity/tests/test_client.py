"""Tests for Poolside Identity client."""

import pytest
import pytest_httpx

from poolside_identity import PoolsideIdentityClient
from poolside_identity.exceptions import NotFoundError
from poolside_identity.models import TeamMember, User, Team, BulkStats


@pytest.fixture
def client():
    """Create test client."""
    return PoolsideIdentityClient(
        base_url="https://api.test.poolside.ai",
        api_key="test-api-key",
    )


class TestPoolsideIdentityClient:
    """Tests for PoolsideIdentityClient."""

    @pytest.mark.asyncio
    async def test_list_users_success(self, client, httpx_mock):
        """Test listing users."""
        httpx_mock.add_response(
            json={
                "users": [
                    {
                        "id": "user-123",
                        "email": "test@example.com",
                        "status": "active",
                        "name": "Test User",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z",
                        "teams": {"teams": [], "links": {}},
                    }
                ],
                "links": {},
            }
        )

        users = await client.list_users()
        assert len(users) == 1
        assert isinstance(users[0], User)
        assert users[0].email == "test@example.com"

    @pytest.mark.asyncio
    async def test_list_users_with_email_filter(self, client, httpx_mock):
        """Test listing users with email filter."""
        httpx_mock.add_response(
            json={
                "users": [
                    {
                        "id": "user-123",
                        "email": "specific@example.com",
                        "status": "active",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z",
                        "teams": {"teams": [], "links": {}},
                    }
                ],
                "links": {},
            }
        )

        users = await client.list_users(email="Specific@Example.com")
        assert len(users) == 1
        assert users[0].email == "specific@example.com"

    @pytest.mark.asyncio
    async def test_list_users_with_status_filter(self, client, httpx_mock):
        """Test listing users with status filter."""
        httpx_mock.add_response(
            json={
                "users": [
                    {
                        "id": "user-123",
                        "email": "active@example.com",
                        "status": "active",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z",
                        "teams": {"teams": [], "links": {}},
                    },
                    {
                        "id": "user-456",
                        "email": "active2@example.com",
                        "status": "active",
                        "created_at": "2024-01-01T00:00:00Z",
                        "updated_at": "2024-01-01T00:00:00Z",
                        "teams": {"teams": [], "links": {}},
                    },
                ],
                "links": {},
            }
        )

        users = await client.list_users(status="active")
        assert len(users) == 2
        assert all(u.status == "active" for u in users)

    @pytest.mark.asyncio
    async def test_get_user_success(self, client, httpx_mock):
        """Test getting a user by ID."""
        httpx_mock.add_response(
            json={
                "id": "user-123",
                "email": "test@example.com",
                "status": "active",
                "name": "Test User",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "teams": {"teams": [], "links": {}},
            }
        )

        user = await client.get_user("user-123")
        assert isinstance(user, User)
        assert user.id == "user-123"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, client, httpx_mock):
        """Test getting a non-existent user."""
        httpx_mock.add_response(status_code=404)

        with pytest.raises(NotFoundError):
            await client.get_user("nonexistent")

    @pytest.mark.asyncio
    async def test_create_user_success(self, client, httpx_mock):
        """Test creating a user."""
        httpx_mock.add_response(
            status_code=201,
            json={
                "id": "user-new",
                "email": "new@example.com",
                "status": "created",
                "name": "New User",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "teams": {"teams": [], "links": {}},
            }
        )

        user = await client.create_user(email="New@Example.com", name="New User")
        assert isinstance(user, User)
        assert user.email == "new@example.com"

    @pytest.mark.asyncio
    async def test_list_teams_success(self, client, httpx_mock):
        """Test listing teams."""
        httpx_mock.add_response(
            json={
                "teams": [
                    {"id": "team-123", "name": "Engineering"},
                    {"id": "team-456", "name": "Product"},
                ],
                "links": {},
            }
        )

        teams = await client.list_teams()
        assert len(teams) == 2
        assert isinstance(teams[0], Team)
        assert teams[0].name == "Engineering"

    @pytest.mark.asyncio
    async def test_list_team_members_success(self, client, httpx_mock):
        """Test listing team members."""
        httpx_mock.add_response(
            json={
                "users": [
                    {"id": "user-123", "email": "member@example.com", "name": "Team Member"},
                ],
                "links": {"next": None},
            }
        )

        members = await client.list_team_members("team-123")
        assert len(members) == 1
        assert isinstance(members[0], TeamMember)
        assert members[0].email == "member@example.com"

    @pytest.mark.asyncio
    async def test_list_team_members_with_schema(self, client, httpx_mock):
        """Test listing team members with schema field (sandbox format)."""
        httpx_mock.add_response(
            json={
                "users": [
                    {"id": "user-456", "email": "sandbox@example.com", "name": "Sandbox User"},
                ],
                "links": {"next": None},
                "$schema": "https://combine-sandbox.poolsi.de/schemas/ListTeamMembersPage.json",
            }
        )

        members = await client.list_team_members("team-456")
        assert len(members) == 1
        assert isinstance(members[0], TeamMember)
        assert members[0].id == "user-456"

    @pytest.mark.asyncio
    async def test_set_team_members_success(self, client, httpx_mock):
        """Test setting team members."""
        httpx_mock.add_response(
            json={"added": 2, "removed": 1}
        )

        stats = await client.set_team_members("team-123", ["user-1", "user-2"])
        assert isinstance(stats, BulkStats)
        assert stats.added == 2
        assert stats.removed == 1

    @pytest.mark.asyncio
    async def test_resolve_team_by_id(self, client, httpx_mock):
        """Test resolving team by ID."""
        httpx_mock.add_response(
            json={
                "id": "team-123",
                "name": "Engineering",
            }
        )

        team_id = await client.resolve_team("team-123")
        assert team_id == "team-123"

    @pytest.mark.asyncio
    async def test_resolve_team_by_name(self, client, httpx_mock):
        """Test resolving team by name."""
        # get_team fails (not a valid ID format)
        httpx_mock.add_response(status_code=404)
        # find_team_by_name -> list_teams succeeds
        httpx_mock.add_response(
            json={
                "teams": [{"id": "team-456", "name": "Engineering"}],
                "links": {},
            }
        )

        team_id = await client.resolve_team("Engineering")
        assert team_id == "team-456"

    @pytest.mark.asyncio
    async def test_resolve_team_not_found(self, client, httpx_mock):
        """Test resolving non-existent team."""
        # get_team fails
        httpx_mock.add_response(status_code=404)
        # list_teams(name=...) fails (returns empty)
        httpx_mock.add_response(json={"teams": [], "links": {}})
        # list_teams(name_prefix=...) fails (returns empty) - called by find_team_by_name
        httpx_mock.add_response(json={"teams": [], "links": {}})

        with pytest.raises(NotFoundError):
            await client.resolve_team("NonExistent")


class TestTeamMember:
    """Tests for TeamMember model."""

    def test_team_member_required_fields(self):
        """Test TeamMember requires only id and email."""
        member = TeamMember(id="user-123", email="test@example.com")
        assert member.id == "user-123"
        assert member.email == "test@example.com"
        assert member.status is None
        assert member.name is None

    def test_team_member_optional_fields(self):
        """Test TeamMember accepts optional fields."""
        member = TeamMember(
            id="user-123",
            email="test@example.com",
            name="Test User",
            status="active",
        )
        assert member.name == "Test User"
        assert member.status == "active"

    def test_team_member_ignores_extra_fields(self):
        """Test TeamMember ignores extra fields like $schema."""
        member = TeamMember(
            id="user-123",
            email="test@example.com",
            extra_field="ignored",
        )
        assert not hasattr(member, "extra_field")


class TestGetClientFromEnv:
    """Tests for get_client_from_env with profile support."""

    def test_default_env_variables(self, monkeypatch):
        """Test default environment variables are used."""
        monkeypatch.setenv("POOLSIDE_API_BASE", "https://api.example.com")
        monkeypatch.setenv("POOLSIDE_API_KEY", "test-key")

        from poolside_identity.client import get_client_from_env
        client = get_client_from_env()
        assert client.base_url == "https://api.example.com"

    def test_sandbox_profile_env_variables(self, monkeypatch):
        """Test sandbox profile environment variables are used."""
        monkeypatch.setenv("POOLSIDE_API_BASE", "https://api.example.com")
        monkeypatch.setenv("POOLSIDE_API_KEY", "production-key")
        monkeypatch.setenv("POOLSIDE_API_BASE_SANDBOX", "https://sandbox.example.com")
        monkeypatch.setenv("POOLSIDE_API_KEY_SANDBOX", "sandbox-key")

        from poolside_identity.client import get_client_from_env
        client = get_client_from_env(env="sandbox")
        assert client.base_url == "https://sandbox.example.com"
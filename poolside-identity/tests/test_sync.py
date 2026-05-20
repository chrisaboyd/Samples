"""Tests for synchronization functionality."""

import pytest

from poolside_identity import PoolsideIdentityClient
from poolside_identity.sync import plan_sync


class TestSync:
    """Tests for sync operations."""

    @pytest.mark.asyncio
    async def test_plan_sync_no_changes(self):
        """Test sync plan when users already match."""
        from unittest.mock import AsyncMock, patch

        async with PoolsideIdentityClient(
            base_url="https://api.test.poolside.ai",
            api_key="test-api-key",
        ) as client:
            # Patch resolve_team to return team ID directly, and list operations
            with patch.object(client, 'resolve_team', new_callable=AsyncMock) as mock_resolve:
                mock_resolve.return_value = "team-123"
                
                with patch.object(client, '_request', new_callable=AsyncMock) as mock_request:
                    mock_request.side_effect = [
                        {  # list_team_members
                            "users": [{
                                "id": "user-1",
                                "email": "existing@example.com",
                                "status": "active",
                                "name": "Existing User",
                                "created_at": "2024-01-01T00:00:00Z",
                                "updated_at": "2024-01-01T00:00:00Z",
                                "teams": {"teams": [], "links": {}},
                            }],
                            "links": {},
                        },
                        {  # list_users
                            "users": [{
                                "id": "user-1",
                                "email": "existing@example.com",
                                "status": "active",
                                "name": "Existing User",
                                "created_at": "2024-01-01T00:00:00Z",
                                "updated_at": "2024-01-01T00:00:00Z",
                                "teams": {"teams": [], "links": {}},
                            }],
                            "links": {},
                        },
                    ]

                    plan = await plan_sync(
                        client,
                        team_identifier="team-123",
                        user_data=[{"email": "existing@example.com"}],
                    )

        assert len(plan.users_to_create) == 0
        assert len(plan.users_to_update) == 0

    @pytest.mark.asyncio
    async def test_plan_sync_create_missing(self):
        """Test sync plan when users need to be created."""
        from unittest.mock import AsyncMock, patch

        async with PoolsideIdentityClient(
            base_url="https://api.test.poolside.ai",
            api_key="test-api-key",
        ) as client:
            with patch.object(client, 'resolve_team', new_callable=AsyncMock) as mock_resolve:
                mock_resolve.return_value = "team-123"
                
                with patch.object(client, '_request', new_callable=AsyncMock) as mock_request:
                    mock_request.side_effect = [
                        {"users": [], "links": {}},  # list_team_members - empty
                        {"users": [], "links": {}},  # list_users for new1 - not found
                        {"users": [], "links": {}},  # list_users for new2 - not found
                    ]

                    plan = await plan_sync(
                        client,
                        team_identifier="team-123",
                        user_data=[
                            {"email": "new1@example.com", "name": "New User 1"},
                            {"email": "new2@example.com", "name": "New User 2"},
                        ],
                        create_missing=True,
                    )

        assert len(plan.users_to_create) == 2
        assert plan.users_to_create[0]["email"] == "new1@example.com"
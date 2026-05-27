"""Tests for synchronization functionality."""

import csv

import pytest

from poolside_identity import PoolsideIdentityClient
from poolside_identity.sync import plan_sync


class TestSync:
    """Tests for sync operations."""

    @pytest.mark.asyncio
    async def test_plan_sync_no_changes(self):
        """Test sync plan when users already match."""
        from unittest.mock import AsyncMock, patch
        from poolside_identity.models import Team

        async with PoolsideIdentityClient(
            base_url="https://api.test.poolside.ai",
            api_key="test-api-key",
        ) as client:
            # Patch find_team to return a mock team
            with patch.object(client, 'find_team', new_callable=AsyncMock) as mock_find:
                mock_find.return_value = Team(id="team-123", name="test-team")
                
                with patch.object(client, 'resolve_team', new_callable=AsyncMock) as mock_resolve:
                    mock_resolve.return_value = "team-123"
                    
                    with patch.object(client, '_request', new_callable=AsyncMock) as mock_request:
                        mock_request.side_effect = [
                            {  # list_team_members (returns TeamMember format)
                                "users": [{
                                    "id": "user-1",
                                    "email": "existing@example.com",
                                    "name": "Existing User",
                                }],
                                "links": {},
                            },
                            {  # list_users (returns User format)
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
        from poolside_identity.models import Team

        async with PoolsideIdentityClient(
            base_url="https://api.test.poolside.ai",
            api_key="test-api-key",
        ) as client:
            with patch.object(client, 'find_team', new_callable=AsyncMock) as mock_find:
                mock_find.return_value = Team(id="team-123", name="test-team")
                
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


class TestCSVParsing:
    """Tests for CSV file parsing."""

    def test_csv_with_header(self, tmp_path):
        """Test CSV with header row is parsed correctly."""
        import csv
        
        csv_path = tmp_path / "users.csv"
        with open(csv_path, "w") as f:
            writer = csv.DictWriter(f, fieldnames=["email", "name"])
            writer.writeheader()
            writer.writerow({"email": "test@example.com", "name": "Test User"})
        
        user_data = []
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                user_data.append(dict(row))
        
        assert len(user_data) == 1
        assert user_data[0]["email"] == "test@example.com"
        assert user_data[0]["name"] == "Test User"

    def test_csv_without_header(self, tmp_path):
        """Test CSV without header row is parsed correctly (email,name format)."""
        csv_path = tmp_path / "users.csv"
        with open(csv_path, "w") as f:
            f.write("ivo@poolside.ai,Ivo Pinto\nryan@poolside.ai,Ryan Hammond\n")
        
        user_data = []
        with open(csv_path, "r") as f:
            content = f.read().strip()
            first_line = content.split("\n")[0].lower() if content else ""
            has_header = "email" in first_line and "name" in first_line
            
            f.seek(0)
            if has_header:
                reader = csv.DictReader(f)
                for row in reader:
                    user_data.append(dict(row))
            else:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 1:
                        user_data.append({"email": row[0].strip(), "name": row[1].strip() if len(row) > 1 else None})
        
        assert len(user_data) == 2
        assert user_data[0]["email"] == "ivo@poolside.ai"
        assert user_data[0]["name"] == "Ivo Pinto"
        assert user_data[1]["email"] == "ryan@poolside.ai"
        assert user_data[1]["name"] == "Ryan Hammond"

    def test_csv_with_teams_column(self, tmp_path):
        """Test CSV with teams column for multi-team mode."""
        import csv
        
        csv_path = tmp_path / "users.csv"
        with open(csv_path, "w") as f:
            writer = csv.DictWriter(f, fieldnames=["email", "name", "teams"])
            writer.writeheader()
            writer.writerow({"email": "user1@example.com", "name": "User One", "teams": "team-a,team-b"})
            writer.writerow({"email": "user2@example.com", "name": "User Two", "teams": "team-a"})
        
        user_data = []
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Parse teams as list if present
                row_dict = dict(row)
                if row_dict.get("teams"):
                    row_dict["teams"] = [t.strip() for t in row_dict["teams"].split(",") if t.strip()]
                user_data.append(row_dict)
        
        assert len(user_data) == 2
        assert user_data[0]["email"] == "user1@example.com"
        assert user_data[0]["teams"] == ["team-a", "team-b"]
        assert user_data[1]["teams"] == ["team-a"]
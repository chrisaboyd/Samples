# Tests

This directory contains tests for your MCP servers and agents.

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_mcp_server.py

# Run tests matching a pattern
pytest -k "test_tool"
```

## Test Structure

```
tests/
├── __init__.py
├── README.md
├── test_mcp_server.py     # MCP server tests
├── test_tools.py          # Individual tool tests
├── test_agent.py          # Agent tests
└── conftest.py            # Pytest fixtures
```

## Writing Tests

### Testing Tools

```python
import pytest
from mcp_servers.your_server.tools.your_tool import run_your_tool

@pytest.mark.asyncio
async def test_your_tool_success():
    """Test tool with valid input."""
    result = await run_your_tool(param="valid_input")

    assert result.status == "success"
    assert result.data is not None

@pytest.mark.asyncio
async def test_your_tool_invalid_input():
    """Test tool with invalid input."""
    with pytest.raises(ValueError):
        await run_your_tool(param="")
```

### Testing MCP Server

```python
import pytest
import json
from mcp_servers.your_server.server import list_tools, call_tool

@pytest.mark.asyncio
async def test_list_tools():
    """Test that tools are properly listed."""
    tools = await list_tools()

    assert len(tools) > 0
    assert any(t.name == "your_tool" for t in tools)

@pytest.mark.asyncio
async def test_call_tool():
    """Test tool execution via MCP interface."""
    result = await call_tool("your_tool", {"param": "test"})

    assert len(result) == 1
    data = json.loads(result[0].text)
    assert "error" not in data
```

### Testing Agents (Integration)

```python
import pytest
from agents import YourAgent

@pytest.mark.asyncio
async def test_agent_simple_task():
    """Test agent with a simple task."""
    agent = YourAgent()

    # This requires the MCP server to be available
    result = await agent.run("Simple test task")

    assert result is not None
    assert len(result) > 0
```

## Fixtures

Create shared fixtures in `conftest.py`:

```python
import pytest

@pytest.fixture
def sample_input():
    """Provide sample input for tests."""
    return {
        "param1": "test_value",
        "param2": 42,
    }

@pytest.fixture
def mock_api_response():
    """Mock response from external API."""
    return {
        "status": "ok",
        "data": [{"id": 1, "name": "test"}],
    }
```

## Mocking External Dependencies

```python
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_tool_with_mock_api():
    """Test tool with mocked external API."""
    mock_response = {"result": "mocked"}

    with patch("mcp_servers.your_server.tools.your_tool.external_api") as mock_api:
        mock_api.fetch = AsyncMock(return_value=mock_response)

        result = await run_your_tool(param="test")

        assert result.status == "success"
        mock_api.fetch.assert_called_once()
```

## Test Configuration

In `pyproject.toml`:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
]
```

Run only fast tests:

```bash
pytest -m "not slow"
```

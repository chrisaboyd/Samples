"""
Pytest configuration and fixtures.

Add shared fixtures here that can be used across all test files.
"""

import pytest


@pytest.fixture
def sample_tool_input():
    """Provide sample input for tool tests."""
    return {
        "input_param": "test_value",
        "optional_param": 10,
    }


@pytest.fixture
def sample_tool_output():
    """Expected output format from tools."""
    return {
        "status": "success",
        "message": "Processed: test_value",
        "optional_value": 10,
    }


# Add more fixtures as needed for your tests

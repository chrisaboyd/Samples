"""Pytest configuration for poolside-identity tests."""

import pytest


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line("markers", "httpx: mark test as using httpx mock")


# Allow unregistered responses to prevent teardown errors when tests complete early
@pytest.fixture
def httpx_mock_allow_all(httpx_mock):
    """Fixture that allows unregistered responses."""
    httpx_mock.add_response()
    return httpx_mock
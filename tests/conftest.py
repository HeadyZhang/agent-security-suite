"""Pytest configuration and shared fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def fixtures_path() -> Path:
    """Return the path to test fixtures."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_agents_path(fixtures_path: Path) -> Path:
    """Return the path to vulnerable agent fixtures."""
    return fixtures_path / "vulnerable_agents"


@pytest.fixture
def safe_agents_path(fixtures_path: Path) -> Path:
    """Return the path to safe agent fixtures."""
    return fixtures_path / "safe_agents"


@pytest.fixture
def mcp_configs_path(fixtures_path: Path) -> Path:
    """Return the path to MCP config fixtures."""
    return fixtures_path / "mcp_configs"

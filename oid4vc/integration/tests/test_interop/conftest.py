from os import getenv
from urllib.parse import urlparse

import pytest_asyncio

from credo_wrapper import CredoWrapper
from sphereon_wrapper import SphereaonWrapper


def _normalize_url(env_var: str, default: str) -> str:
    """Return a URL with scheme ensured, preferring environment overrides."""

    value = getenv(env_var, default)
    parsed = urlparse(value)
    if not parsed.scheme:
        return f"http://{value}"
    return value


SPHEREON_BASE_URL = _normalize_url("SPHEREON_WRAPPER_URL", "http://localhost:3010")
CREDO_BASE_URL = _normalize_url("CREDO_AGENT_URL", "http://localhost:3020")


@pytest_asyncio.fixture
async def sphereon():
    """Create a wrapper instance and connect to the server."""
    wrapper = SphereaonWrapper(SPHEREON_BASE_URL)
    async with wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def credo():
    """Create a wrapper instance and connect to the server."""
    wrapper = CredoWrapper(CREDO_BASE_URL)
    async with wrapper:
        yield wrapper

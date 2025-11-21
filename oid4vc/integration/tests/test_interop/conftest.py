from os import getenv

import httpx
import pytest_asyncio

from credo_wrapper import CredoWrapper

# Service endpoints from docker-compose.yml environment variables
CREDO_AGENT_URL = getenv("CREDO_AGENT_URL", "http://localhost:3020")
ACAPY_ISSUER_ADMIN_URL = getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_VERIFIER_ADMIN_URL = getenv("ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031")


@pytest_asyncio.fixture
async def credo():
    """Create a Credo wrapper instance."""
    wrapper = CredoWrapper(CREDO_AGENT_URL)
    async with wrapper as wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def acapy_issuer():
    """HTTP client for ACA-Py issuer admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_ISSUER_ADMIN_URL) as client:
        yield client


@pytest_asyncio.fixture
async def acapy_verifier():
    """HTTP client for ACA-Py verifier admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_VERIFIER_ADMIN_URL) as client:
        yield client

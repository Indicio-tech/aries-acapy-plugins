"""Simplified integration test fixtures for OID4VC v1 flows.

This module provides pytest fixtures for testing the complete OID4VC v1 flow:
Keycloak Issues → Credo Receives → Credo Presents → ACA-Py Verifies
"""

import asyncio
import os
from typing import Any

import httpx
import pytest
import pytest_asyncio
from acapy_controller import Controller

# Environment configuration
CREDO_AGENT_URL = os.getenv("CREDO_AGENT_URL", "http://localhost:3020")
ACAPY_ISSUER_ADMIN_URL = os.getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_ISSUER_OID4VCI_URL = os.getenv(
    "ACAPY_ISSUER_OID4VCI_URL", "http://localhost:8022"
)
ACAPY_VERIFIER_ADMIN_URL = os.getenv(
    "ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031"
)
ACAPY_VERIFIER_OID4VP_URL = os.getenv(
    "ACAPY_VERIFIER_OID4VP_URL", "http://localhost:8032"
)


@pytest_asyncio.fixture
async def credo_client():
    """HTTP client for Credo agent service."""
    async with httpx.AsyncClient(base_url=CREDO_AGENT_URL, timeout=30.0) as client:
        # Wait for service to be ready
        for _ in range(5):  # Reduced since services should already be ready
            try:
                response = await client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.RequestError:
                pass
            await asyncio.sleep(1)
        else:
            pytest.skip("Credo agent service not available")

        yield client


@pytest_asyncio.fixture
async def acapy_issuer_admin():
    """ACA-Py issuer admin API controller."""
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        try:
            await controller.get("/status/ready")
            break
        except httpx.RequestError:
            await asyncio.sleep(1)
    else:
        pytest.skip("ACA-Py issuer service not available")

    yield controller


@pytest_asyncio.fixture
async def acapy_verifier_admin():
    """ACA-Py verifier admin API controller."""
    controller = Controller(ACAPY_VERIFIER_ADMIN_URL)

    # Wait for ACA-Py verifier to be ready
    for _ in range(30):
        try:
            await controller.get("/status/ready")
            break
        except httpx.RequestError:
            await asyncio.sleep(1)
    else:
        pytest.skip("ACA-Py verifier service not available")

    yield controller


# Legacy fixture for backward compatibility
@pytest_asyncio.fixture
async def acapy_admin(acapy_verifier_admin):
    """Legacy alias for acapy_verifier_admin to maintain backward compatibility."""
    yield acapy_verifier_admin

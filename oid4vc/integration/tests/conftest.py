"""Simplified integration test fixtures for OID4VC v1 flows.

This module provides pytest fixtures for testing the complete OID4VC v1 flow:
ACA-Py Issues → Credo Receives → Credo Presents → ACA-Py Verifies
"""

import asyncio
import os

import httpx
import pytest_asyncio

from acapy_controller import Controller

# Environment configuration
CREDO_AGENT_URL = os.getenv("CREDO_AGENT_URL", "http://localhost:3020")
SPHEREON_WRAPPER_URL = os.getenv("SPHEREON_WRAPPER_URL", "http://localhost:3010")
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
            response = await client.get("/health")
            if response.status_code == 200:
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Credo agent service not available")

        yield client


@pytest_asyncio.fixture
async def sphereon_client():
    """HTTP client for Sphereon wrapper service."""
    async with httpx.AsyncClient(base_url=SPHEREON_WRAPPER_URL, timeout=30.0) as client:
        # Wait for service to be ready
        for _ in range(5):
            try:
                response = await client.get("/health")
                if response.status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            await asyncio.sleep(1)
        else:
            raise RuntimeError("Sphereon wrapper service not available")

        yield client


@pytest_asyncio.fixture
async def acapy_issuer_admin():
    """ACA-Py issuer admin API controller."""
    controller = Controller(ACAPY_ISSUER_ADMIN_URL)

    # Wait for ACA-Py issuer to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py issuer service not available")

    yield controller


@pytest_asyncio.fixture
async def acapy_verifier_admin():
    """ACA-Py verifier admin API controller."""
    controller = Controller(ACAPY_VERIFIER_ADMIN_URL)

    # Wait for ACA-Py verifier to be ready
    for _ in range(30):
        status = await controller.get("/status/ready")
        if status.get("ready") is True:
            break
        await asyncio.sleep(1)
    else:
        raise RuntimeError("ACA-Py verifier service not available")

    yield controller


# Legacy fixture for backward compatibility
@pytest_asyncio.fixture
async def acapy_admin(acapy_verifier_admin):
    """Legacy alias for acapy_verifier_admin to maintain backward compatibility."""
    yield acapy_verifier_admin


# Controller fixture for DCQL tests
@pytest_asyncio.fixture
async def controller(acapy_verifier_admin):
    """Controller fixture for DCQL tests - uses verifier admin API."""
    yield acapy_verifier_admin

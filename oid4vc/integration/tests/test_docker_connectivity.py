"""Simple connectivity test to verify Docker network communication."""

import httpx
import pytest


@pytest.mark.asyncio
async def test_docker_network_connectivity():
    """Test that services can communicate within Docker network."""

    # Test Keycloak client service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://keycloak-client:3011/health")
        assert response.status_code == 200
        print(f"✅ Keycloak client health: {response.json()}")

    # Test Credo agent service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://credo-agent:3020/health")
        assert response.status_code == 200
        print(f"✅ Credo agent health: {response.json()}")

    # Test ACA-Py admin service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://acapy-verifier:8031/status/live")
        assert response.status_code == 200
        print(f"✅ ACA-Py admin health: {response.json()}")


@pytest.mark.asyncio
async def test_credential_offer_creation():
    """Test credential offer creation using internal Docker network."""

    async with httpx.AsyncClient(timeout=30.0) as client:
        offer_request = {
            "credential_configuration_id": "IdentityCredential",
            "user_id": "testuser",
            "format": "mso_mdoc",
        }

        response = await client.post(
            "http://keycloak-client:3011/credential-offer", json=offer_request
        )

        assert response.status_code == 200
        offer_data = response.json()
        assert "credential_offer" in offer_data

        # The credential_issuer should use the configured issuer URL
        credential_offer = offer_data["credential_offer"]
        # Updated to match internal Docker network configuration
        assert (
            credential_offer["credential_issuer"]
            == "http://keycloak-client:3011"
        )
        assert "UniversityDegreeCredential" in credential_offer["credential_configuration_ids"]

        print("✅ Credential offer created successfully:")
        print(f"   Issuer: {credential_offer['credential_issuer']}")
        print(
            f"   Configuration IDs: {credential_offer['credential_configuration_ids']}"
        )

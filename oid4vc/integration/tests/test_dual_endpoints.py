"""
Test for dual OID4VCI well-known endpoints compatibility.

This test validates that our ACA-Py OID4VC plugin serves both:
1. /.well-known/openid-credential-issuer (OID4VCI v1.0 standard)
2. /.well-known/openid_credential_issuer (deprecated, for Credo compatibility)

Both endpoints should return identical data, but the deprecated one should include
appropriate deprecation headers.
"""

import asyncio
import json

import httpx
import pytest


@pytest.mark.asyncio
async def test_dual_oid4vci_endpoints():
    """Test that both OID4VCI well-known endpoints work and return identical data."""

    acapy_oid4vci_base = "http://acapy-issuer:8022"

    async with httpx.AsyncClient() as client:
        # Test standard endpoint (with dash)
        print("🧪 Testing standard endpoint: /.well-known/openid-credential-issuer")
        standard_response = await client.get(
            f"{acapy_oid4vci_base}/.well-known/openid-credential-issuer"
        )

        assert (
            standard_response.status_code == 200
        ), f"Standard endpoint failed: {standard_response.status_code}"
        standard_data = standard_response.json()

        print(f"✅ Standard endpoint returned: {json.dumps(standard_data, indent=2)}")

        # Test deprecated endpoint (with underscore)
        print("🧪 Testing deprecated endpoint: /.well-known/openid_credential_issuer")
        deprecated_response = await client.get(
            f"{acapy_oid4vci_base}/.well-known/openid_credential_issuer"
        )

        assert (
            deprecated_response.status_code == 200
        ), f"Deprecated endpoint failed: {deprecated_response.status_code}"
        deprecated_data = deprecated_response.json()

        print(
            f"✅ Deprecated endpoint returned: {json.dumps(deprecated_data, indent=2)}"
        )

        # Verify both endpoints return identical data
        assert (
            standard_data == deprecated_data
        ), "Endpoints should return identical JSON data"
        print("✅ Both endpoints return identical data")

        # Verify required fields are present
        assert "credential_issuer" in standard_data, "credential_issuer field missing"
        assert (
            "credential_endpoint" in standard_data
        ), "credential_endpoint field missing"
        assert (
            "credential_configurations_supported" in standard_data
        ), "credential_configurations_supported field missing"

        print("✅ All required OID4VCI metadata fields present")

        # Verify deprecated endpoint has proper deprecation headers
        assert (
            deprecated_response.headers.get("Deprecation") == "true"
        ), "Deprecated endpoint missing Deprecation header"
        assert (
            "deprecated" in deprecated_response.headers.get("Warning", "").lower()
        ), "Deprecated endpoint missing Warning header"
        assert (
            "Sunset" in deprecated_response.headers
        ), "Deprecated endpoint missing Sunset header"

        print("✅ Deprecated endpoint has proper deprecation headers")
        print(f"   Deprecation: {deprecated_response.headers.get('Deprecation')}")
        print(f"   Warning: {deprecated_response.headers.get('Warning')}")
        print(f"   Sunset: {deprecated_response.headers.get('Sunset')}")


@pytest.mark.asyncio
async def test_credo_can_reach_underscore_endpoint():
    """Test that Credo agent can successfully reach the underscore endpoint."""

    # This simulates what Credo client libraries do when discovering issuer metadata
    acapy_oid4vci_base = "http://acapy-issuer:8022"

    async with httpx.AsyncClient() as client:
        print("🧪 Testing Credo-style endpoint discovery...")

        # Credo clients expect the underscore format
        response = await client.get(
            f"{acapy_oid4vci_base}/.well-known/openid_credential_issuer"
        )

        assert (
            response.status_code == 200
        ), f"Credo-style endpoint discovery failed: {response.status_code}"

        metadata = response.json()

        # Verify the metadata has the fields Credo expects
        # Note: In docker environment, this returns the internal docker alias
        expected_issuer = acapy_oid4vci_base.replace(
            "acapy-issuer", "acapy-issuer.local"
        )
        assert (
            metadata.get("credential_issuer") == expected_issuer
        ), "credential_issuer mismatch"
        assert (
            metadata.get("credential_endpoint") == f"{expected_issuer}/credential"
        ), "credential_endpoint mismatch"
        assert (
            "credential_configurations_supported" in metadata
        ), "Missing credential_configurations_supported"

        print(
            "✅ Credo can successfully discover issuer metadata via underscore endpoint"
        )
        print(f"   Issuer: {metadata.get('credential_issuer')}")
        print(f"   Credential Endpoint: {metadata.get('credential_endpoint')}")
        print(
            f"   Supported Configs: {len(metadata.get('credential_configurations_supported', {}))}"
        )


@pytest.mark.asyncio
async def test_acapy_services_health():
    """Test that all ACA-Py services are healthy and ready for OID4VC operations."""

    async with httpx.AsyncClient() as client:
        # Test ACA-Py issuer
        print("🧪 Testing ACA-Py issuer health...")
        issuer_response = await client.get("http://acapy-issuer:8021/status/ready")
        assert issuer_response.status_code == 200, "ACA-Py issuer not ready"
        issuer_status = issuer_response.json()
        assert issuer_status.get("ready") is True, "ACA-Py issuer not ready"
        print("✅ ACA-Py issuer is ready")

        # Test ACA-Py verifier
        print("🧪 Testing ACA-Py verifier health...")
        verifier_response = await client.get("http://acapy-verifier:8031/status/ready")
        assert verifier_response.status_code == 200, "ACA-Py verifier not ready"
        verifier_status = verifier_response.json()
        assert verifier_status.get("ready") is True, "ACA-Py verifier not ready"
        print("✅ ACA-Py verifier is ready")

        # Test Credo agent
        print("🧪 Testing Credo agent health...")
        credo_response = await client.get("http://credo-agent:3020/health")
        assert credo_response.status_code == 200, "Credo agent not healthy"
        credo_status = credo_response.json()
        assert credo_status.get("status") == "healthy", "Credo agent not healthy"
        print("✅ Credo agent is healthy")


@pytest.mark.asyncio
async def test_oid4vci_server_endpoints():
    """Test that OID4VCI server is properly exposing all required endpoints."""

    acapy_oid4vci_base = "http://acapy-issuer:8022"

    async with httpx.AsyncClient() as client:
        print("🧪 Testing OID4VCI server endpoint availability...")

        # Test credential endpoint
        # Note: This will likely return 405 (Method Not Allowed) or 400 (Bad Request)
        # since we're not sending proper credential request, but should not be 404
        credential_response = await client.get(f"{acapy_oid4vci_base}/credential")
        assert credential_response.status_code != 404, "Credential endpoint not found"
        print("✅ Credential endpoint is available")

        # Test token endpoint (if available)
        token_response = await client.get(f"{acapy_oid4vci_base}/token")
        assert token_response.status_code != 404, "Token endpoint not found"
        print("✅ Token endpoint is available")

        print("✅ All OID4VCI server endpoints are properly exposed")


if __name__ == "__main__":
    # Allow running this test file directly for debugging
    import sys

    async def run_all_tests():
        print("🚀 Starting dual endpoint compatibility tests...\n")

        await test_acapy_services_health()
        print()

        await test_dual_oid4vci_endpoints()
        print()

        await test_credo_can_reach_underscore_endpoint()
        print()

        await test_oid4vci_server_endpoints()
        print()

        print("🎉 All tests passed! Dual endpoint compatibility is working correctly.")

    if len(sys.argv) > 1 and sys.argv[1] == "run":
        asyncio.run(run_all_tests())
    else:
        print("Use 'python test_dual_endpoints.py run' to run tests directly")

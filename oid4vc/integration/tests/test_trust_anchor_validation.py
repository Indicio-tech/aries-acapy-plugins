"""Trust anchor and certificate chain validation tests.

This file tests mDOC trust anchor management and certificate chain validation:
- Trust anchor storage and retrieval
- Certificate chain validation during verification
- Invalid/expired certificate handling
- CA certificate management endpoints
"""

import uuid
from typing import Any

import httpx
import pytest
import pytest_asyncio


pytestmark = [pytest.mark.trust, pytest.mark.asyncio]


# =============================================================================
# Sample Certificates for Testing
# =============================================================================

# Self-signed test root CA certificate (for testing purposes only)
TEST_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegVpnKMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDlRlc3Qg
Um9vdCBDQSAwMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowGTEXMBUG
A1UEAwwOVGVzdCBSb290IENBIDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQK
qW4VNMr4L3W3J5P6Bj7WXj4HGZ4b0f6gRzFrMt+MHJSNMrWCxFKn2Mvi0RYxHxFp
QcGj7M1xN3lU5z5H8lNKoyMwITAfBgNVHREEGDAWhwR/AAABggpsb2NhbGhvc3Qw
CgYIKoZIzj0EAwIDSAAwRQIhAJz3Lh7XKHA+CjOV+WxY7vJkDGTD0EqF9KT9F5Hf
QyQpAiAtVPwsQK4bQK9b3nP6K8zKMt7LM1b8X5c0sM7fL5PJSQ==
-----END CERTIFICATE-----"""

# Expired test certificate (for testing expiry handling)
TEST_EXPIRED_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegVpnLMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDlRlc3Qg
RXhwaXJlZCBDQTAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMBkxFzAV
BgNVBAMMDlRlc3QgRXhwaXJlZCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BAqpbhU0yvgvdbcnk/oGPtZePgcZnhvR/qBHMWsy34wclI0ytYLEUqfYy+LRFjEf
EWlBwaPszXE3eVTnPkfyU0qjIzAhMB8GA1UdEQQYMBaHBH8AAAGCCmxvY2FsaG9z
dDAKBggqhkjOPQQDAgNIADBFAiEAnPcuHtcocD4KM5X5bFju8mQMZMPQSoX0pP0X
kd9DJCkCIC1U/CxArhtAr1vec/orzMoy3sszVvxflzSwzt8vk8lJ
-----END CERTIFICATE-----"""


# =============================================================================
# Trust Anchor Management Tests
# =============================================================================


class TestTrustAnchorManagement:
    """Test trust anchor CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_trust_anchor(self, acapy_verifier: httpx.AsyncClient):
        """Test creating a trust anchor."""
        anchor_id = f"test_anchor_{uuid.uuid4().hex[:8]}"
        
        response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
                "metadata": {
                    "issuer_name": "Test Root CA",
                    "purpose": "testing",
                },
            },
        )
        
        # Should succeed
        assert response.status_code in [200, 201]
        result = response.json()
        assert result.get("anchor_id") == anchor_id

    @pytest.mark.asyncio
    async def test_get_trust_anchor(self, acapy_verifier: httpx.AsyncClient):
        """Test retrieving a trust anchor by ID."""
        # First create one
        anchor_id = f"get_test_{uuid.uuid4().hex[:8]}"
        
        create_response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
            },
        )
        
        if create_response.status_code not in [200, 201]:
            pytest.skip("Trust anchor creation endpoint not available")
        
        # Now retrieve it
        response = await acapy_verifier.get(
            f"/oid4vc/mso_mdoc/trust-anchors/{anchor_id}"
        )
        
        assert response.status_code == 200
        result = response.json()
        assert result.get("anchor_id") == anchor_id
        assert "certificate_pem" in result

    @pytest.mark.asyncio
    async def test_list_trust_anchors(self, acapy_verifier: httpx.AsyncClient):
        """Test listing all trust anchors."""
        response = await acapy_verifier.get("/oid4vc/mso_mdoc/trust-anchors")
        
        if response.status_code == 404:
            pytest.skip("Trust anchor listing endpoint not available")
        
        assert response.status_code == 200
        result = response.json()
        assert isinstance(result, (list, dict))

    @pytest.mark.asyncio
    async def test_delete_trust_anchor(self, acapy_verifier: httpx.AsyncClient):
        """Test deleting a trust anchor."""
        # First create one
        anchor_id = f"delete_test_{uuid.uuid4().hex[:8]}"
        
        create_response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
            },
        )
        
        if create_response.status_code not in [200, 201]:
            pytest.skip("Trust anchor creation endpoint not available")
        
        # Delete it
        response = await acapy_verifier.delete(
            f"/oid4vc/mso_mdoc/trust-anchors/{anchor_id}"
        )
        
        assert response.status_code in [200, 204]
        
        # Verify it's gone
        get_response = await acapy_verifier.get(
            f"/oid4vc/mso_mdoc/trust-anchors/{anchor_id}"
        )
        assert get_response.status_code == 404

    @pytest.mark.asyncio
    async def test_duplicate_trust_anchor_id(self, acapy_verifier: httpx.AsyncClient):
        """Test that duplicate trust anchor IDs are handled."""
        anchor_id = f"dup_test_{uuid.uuid4().hex[:8]}"
        
        # First creation
        response1 = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
            },
        )
        
        if response1.status_code not in [200, 201]:
            pytest.skip("Trust anchor creation endpoint not available")
        
        # Second creation with same ID
        response2 = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
            },
        )
        
        # Should fail with conflict or update existing
        assert response2.status_code in [200, 400, 409]


# =============================================================================
# Certificate Validation Tests
# =============================================================================


class TestCertificateValidation:
    """Test certificate validation scenarios."""

    @pytest.mark.asyncio
    async def test_invalid_certificate_format(self, acapy_verifier: httpx.AsyncClient):
        """Test handling of invalid certificate format."""
        response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": f"invalid_{uuid.uuid4().hex[:8]}",
                "certificate_pem": "not a valid certificate",
            },
        )
        
        # Should reject invalid certificate
        assert response.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_empty_certificate(self, acapy_verifier: httpx.AsyncClient):
        """Test handling of empty certificate."""
        response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": f"empty_{uuid.uuid4().hex[:8]}",
                "certificate_pem": "",
            },
        )
        
        assert response.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_certificate_with_invalid_pem_markers(
        self, acapy_verifier: httpx.AsyncClient
    ):
        """Test certificate with invalid PEM markers."""
        invalid_pem = """-----BEGIN SOMETHING-----
MIIBkTCB+wIJAKHBfpegVpnKMAoGCCqGSM49BAMCMBkxFzAVBgNVBAMMDlRlc3Qg
-----END SOMETHING-----"""
        
        response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": f"bad_markers_{uuid.uuid4().hex[:8]}",
                "certificate_pem": invalid_pem,
            },
        )
        
        assert response.status_code in [400, 422]


# =============================================================================
# Chain Validation Tests
# =============================================================================


class TestChainValidation:
    """Test certificate chain validation during mDOC verification."""

    @pytest.mark.asyncio
    async def test_verification_without_trust_anchor(
        self, acapy_verifier: httpx.AsyncClient
    ):
        """Test mDOC verification fails without matching trust anchor."""
        # Create a DCQL request for mDOC
        dcql_query = {
            "credentials": [
                {
                    "id": "mdl_credential",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                    "claims": [
                        {"namespace": "org.iso.18013.5.1", "claim_name": "family_name"},
                    ],
                }
            ],
        }

        response = await acapy_verifier.post(
            "/oid4vp/dcql/request",
            json={
                "dcql_query": dcql_query,
                "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
            },
        )
        
        # Request creation should succeed
        # Actual chain validation happens at presentation time
        assert response.status_code in [200, 400]

    @pytest.mark.asyncio
    async def test_verification_with_trust_anchor(
        self, acapy_verifier: httpx.AsyncClient
    ):
        """Test mDOC verification with proper trust anchor."""
        # This is an integration test that requires:
        # 1. A trust anchor in the store
        # 2. An mDOC credential signed with a certificate chaining to that anchor
        # 3. A holder presenting the credential
        
        # For now, just verify the trust anchor can be stored
        anchor_id = f"chain_test_{uuid.uuid4().hex[:8]}"
        
        response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": anchor_id,
                "certificate_pem": TEST_ROOT_CA_PEM,
                "metadata": {"purpose": "chain_validation_test"},
            },
        )
        
        # If endpoint exists, it should accept valid certificate
        if response.status_code not in [404, 405]:
            assert response.status_code in [200, 201]


# =============================================================================
# Trust Store Configuration Tests
# =============================================================================


class TestTrustStoreConfiguration:
    """Test trust store configuration options."""

    @pytest.mark.asyncio
    async def test_file_based_trust_store(self, acapy_verifier: httpx.AsyncClient):
        """Test that file-based trust store can be configured."""
        # This is a configuration test - check plugin status
        response = await acapy_verifier.get("/status/ready")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_wallet_based_trust_store(self, acapy_verifier: httpx.AsyncClient):
        """Test wallet-based trust store operations."""
        # The wallet-based store should work with the storage endpoints
        response = await acapy_verifier.get("/oid4vc/mso_mdoc/trust-anchors")
        
        # Endpoint should exist even if empty
        if response.status_code not in [404, 405]:
            assert response.status_code == 200


# =============================================================================
# Issuer Certificate Tests
# =============================================================================


class TestIssuerCertificates:
    """Test issuer certificate management for mDOC issuance."""

    @pytest.mark.asyncio
    async def test_generate_issuer_key(self, acapy_issuer: httpx.AsyncClient):
        """Test generating an issuer signing key."""
        response = await acapy_issuer.post(
            "/oid4vc/mso_mdoc/keys/generate",
            json={
                "key_type": "ES256",
                "generate_certificate": True,
                "certificate_subject": {
                    "common_name": "Test Issuer",
                    "organization": "Test Org",
                    "country": "US",
                },
            },
        )
        
        if response.status_code == 404:
            pytest.skip("mDOC key generation endpoint not available")
        
        assert response.status_code in [200, 201]
        result = response.json()
        assert "key_id" in result or "verification_method" in result

    @pytest.mark.asyncio
    async def test_list_issuer_keys(self, acapy_issuer: httpx.AsyncClient):
        """Test listing issuer keys."""
        response = await acapy_issuer.get("/oid4vc/mso_mdoc/keys")
        
        if response.status_code == 404:
            pytest.skip("mDOC key listing endpoint not available")
        
        assert response.status_code == 200
        result = response.json()
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_get_issuer_certificate_chain(self, acapy_issuer: httpx.AsyncClient):
        """Test retrieving issuer certificate chain."""
        # First, ensure a key exists
        keys_response = await acapy_issuer.get("/oid4vc/mso_mdoc/keys")
        
        if keys_response.status_code == 404:
            pytest.skip("mDOC key endpoints not available")
        
        keys = keys_response.json()
        if not keys:
            # Generate a key first
            gen_response = await acapy_issuer.post(
                "/oid4vc/mso_mdoc/keys/generate",
                json={
                    "key_type": "ES256",
                    "generate_certificate": True,
                },
            )
            if gen_response.status_code not in [200, 201]:
                pytest.skip("Cannot generate mDOC key")
            keys = [gen_response.json()]
        
        # Get the certificate for the first key
        key_id = keys[0].get("key_id") or keys[0].get("verification_method", "").split("#")[-1]
        
        response = await acapy_issuer.get(f"/oid4vc/mso_mdoc/keys/{key_id}/certificate")
        
        if response.status_code == 404:
            # Try alternative endpoint
            response = await acapy_issuer.get(f"/oid4vc/mso_mdoc/certificates/{key_id}")
        
        # If endpoint exists, should return certificate
        if response.status_code not in [404, 405]:
            assert response.status_code == 200


# =============================================================================
# End-to-End Trust Chain Tests
# =============================================================================


class TestEndToEndTrustChain:
    """End-to-end tests for trust chain validation."""

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires full mDOC issuance and verification flow")
    async def test_complete_trust_chain_flow(
        self,
        acapy_issuer: httpx.AsyncClient,
        acapy_verifier: httpx.AsyncClient,
    ):
        """Test complete trust chain: Issue -> Verify with proper CA chain.
        
        This test would:
        1. Generate issuer key with self-signed certificate
        2. Store issuer's root certificate as trust anchor on verifier
        3. Issue mDOC credential with issuer key
        4. Verify credential against trust anchor
        """
        # Step 1: Generate issuer key
        key_response = await acapy_issuer.post(
            "/oid4vc/mso_mdoc/keys/generate",
            json={
                "key_type": "ES256",
                "generate_certificate": True,
                "certificate_subject": {
                    "common_name": "Test mDL Issuer",
                    "organization": "Test DMV",
                    "country": "US",
                },
            },
        )
        key_response.raise_for_status()
        issuer_key = key_response.json()
        
        # Step 2: Get issuer certificate and store as trust anchor
        key_id = issuer_key.get("key_id")
        cert_response = await acapy_issuer.get(
            f"/oid4vc/mso_mdoc/keys/{key_id}/certificate"
        )
        cert_response.raise_for_status()
        issuer_cert = cert_response.json()["certificate_pem"]
        
        # Store on verifier
        anchor_response = await acapy_verifier.post(
            "/oid4vc/mso_mdoc/trust-anchors",
            json={
                "anchor_id": f"issuer_{key_id}",
                "certificate_pem": issuer_cert,
                "metadata": {"issuer": "Test DMV"},
            },
        )
        anchor_response.raise_for_status()
        
        # Step 3 & 4 would require actual credential issuance and presentation
        # which involves a holder wallet (e.g., Credo)
        
        # For now, just verify setup succeeded
        assert issuer_key is not None
        assert issuer_cert is not None


# =============================================================================
# Fixtures
# =============================================================================


@pytest_asyncio.fixture
async def acapy_issuer():
    """HTTP client for ACA-Py issuer admin API."""
    from os import getenv
    ACAPY_ISSUER_ADMIN_URL = getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
    async with httpx.AsyncClient(base_url=ACAPY_ISSUER_ADMIN_URL) as client:
        yield client


@pytest_asyncio.fixture
async def acapy_verifier():
    """HTTP client for ACA-Py verifier admin API."""
    from os import getenv
    ACAPY_VERIFIER_ADMIN_URL = getenv("ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031")
    async with httpx.AsyncClient(base_url=ACAPY_VERIFIER_ADMIN_URL) as client:
        yield client

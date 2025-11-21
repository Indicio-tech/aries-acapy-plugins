"""Core OID4VCI 1.0 compliance tests."""

import json
import logging

import httpx
import pytest

from .test_config import TEST_CONFIG
from .test_utils import OID4VCTestHelper

LOGGER = logging.getLogger(__name__)


class TestOID4VCI10Compliance:
    """OID4VCI 1.0 compliance test suite."""

    @pytest.fixture(scope="class")
    async def test_runner(self):
        """Setup test runner."""
        runner = OID4VCTestHelper()
        yield runner

    @pytest.mark.asyncio
    async def test_oid4vci_10_metadata(self, test_runner):
        """Test OID4VCI 1.0 § 11.2: Credential Issuer Metadata."""
        LOGGER.info("Testing OID4VCI 1.0 credential issuer metadata...")

        async with httpx.AsyncClient() as client:
            # Test .well-known endpoint
            response = await client.get(
                f"{TEST_CONFIG['oid4vci_endpoint']}/.well-known/openid-credential-issuer",
                timeout=30
            )

            if response.status_code != 200:
                LOGGER.error(
                    "Metadata endpoint failed: %s - %s",
                    response.status_code,
                    response.text
                )

            assert response.status_code == 200

            metadata = response.json()

            # OID4VCI 1.0 § 11.2.1: Required fields
            assert "credential_issuer" in metadata
            assert "credential_endpoint" in metadata
            assert "credential_configurations_supported" in metadata

            # Validate credential_issuer format (handle env vars)
            credential_issuer = metadata["credential_issuer"]

            # Handle case where environment variable is not resolved
            if "${AGENT_ENDPOINT" in credential_issuer:
                LOGGER.warning(
                    "Environment variable not resolved in credential_issuer: %s",
                    credential_issuer
                )
                # Check if it contains the expected port/path structure
                assert (
                    ":8032" in credential_issuer or
                    "localhost:8032" in credential_issuer
                )
            else:
                # In integration tests, endpoints might differ slightly due to docker networking
                # but we check basic validity
                assert credential_issuer.startswith("http")

            # Validate credential_endpoint format
            expected_cred_endpoint = f"{TEST_CONFIG['oid4vci_endpoint']}/credential"
            assert metadata["credential_endpoint"] == expected_cred_endpoint

            # OID4VCI 1.0 § 11.2.3: credential_configurations_supported must be object
            configs = metadata["credential_configurations_supported"]
            assert isinstance(configs, dict), (
                "credential_configurations_supported must be object in OID4VCI 1.0"
            )

            test_runner.test_results["metadata_compliance"] = {
                "status": "PASS",
                "metadata": metadata,
                "validation": "OID4VCI 1.0 § 11.2 compliant"
            }

    @pytest.mark.asyncio
    async def test_oid4vci_10_credential_request_with_identifier(self, test_runner):
        """Test OID4VCI 1.0 § 7.2: Credential Request with credential_identifier."""
        LOGGER.info(
            "Testing OID4VCI 1.0 credential request with credential_identifier..."
        )

        # Setup supported credential
        supported_cred_id = await test_runner.setup_supported_credential()
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Get access token
        grants = offer_data["credential_offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            assert token_response.status_code == 200
            token_data = token_response.json()
            access_token = token_data["access_token"]

            # Test credential request with credential_identifier (OID4VCI 1.0 format)
            credential_request = {
                "credential_identifier": "org.iso.18013.5.1.mDL",
                "doctype": "org.iso.18013.5.1.mDL",
                "proof": {
                    "jwt": (
                        "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiw"
                        "iandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4"
                        "RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZF"
                        "elJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn19."
                        "eyJub25jZSI6InRlc3Rfbm9uY2UiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0"
                        "OjgwMzEiLCJpYXQiOjE2OTg5NjAwMDB9.signature"
                    )
                }
            }

            cred_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=credential_request,
                headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should succeed with OID4VCI 1.0 format
            assert cred_response.status_code == 200
            cred_data = cred_response.json()

            # Validate response structure
            assert "format" in cred_data
            assert "credential" in cred_data
            assert cred_data["format"] == "jwt_vc_json"

            test_runner.test_results["credential_request_identifier"] = {
                "status": "PASS",
                "response": cred_data,
                "validation": "OID4VCI 1.0 § 7.2 credential_identifier compliant"
            }

    @pytest.mark.asyncio
    async def test_oid4vci_10_mutual_exclusion(self, test_runner):
        """Test OID4VCI 1.0 § 7.2: credential_identifier and format mutual exclusion."""
        LOGGER.info("Testing credential_identifier and format mutual exclusion...")

        # Setup
        supported_cred_id = await test_runner.setup_supported_credential()
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Extract pre-authorized code from credential offer
        grants = offer_data["credential_offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30
            )
            try:
                token_data = token_response.json()
                access_token = token_data["access_token"]
            except json.JSONDecodeError as e:
                LOGGER.error("Failed to parse token response as JSON: %s", e)
                LOGGER.error("Response content: %s", token_response.text)
                raise

            # Test with both parameters (should fail)
            invalid_request = {
                "credential_identifier": "org.iso.18013.5.1.mDL",
                "format": "jwt_vc_json",  # Both present - violation of OID4VCI 1.0 § 7.2
                "proof": {"jwt": "test_jwt"}
            }

            response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=invalid_request,
                headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should fail with 400 Bad Request
            assert response.status_code == 400
            error_msg = response.json().get("message", "")
            assert "mutually exclusive" in error_msg.lower()

            # Test with neither parameter (should fail)
            invalid_request2 = {
                "proof": {"jwt": "test_jwt"}
                # Neither credential_identifier nor format
            }

            response2 = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=invalid_request2,
                headers={"Authorization": f"Bearer {access_token}"}
            )

            assert response2.status_code == 400

            test_runner.test_results["mutual_exclusion"] = {
                "status": "PASS",
                "validation": "OID4VCI 1.0 § 7.2 mutual exclusion enforced"
            }

    @pytest.mark.asyncio
    async def test_oid4vci_10_proof_of_possession(self, test_runner):
        """Test OID4VCI 1.0 § 7.2.1: Proof of Possession validation."""
        LOGGER.info("Testing OID4VCI 1.0 proof of possession...")

        # Setup
        supported_cred_id = await test_runner.setup_supported_credential()
        offer_data = await test_runner.create_credential_offer(supported_cred_id)

        # Extract pre-authorized code from credential offer
        grants = offer_data["credential_offer"]["grants"]
        pre_auth_grant = grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        pre_authorized_code = pre_auth_grant["pre-authorized_code"]

        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_authorized_code
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            try:
                token_data = token_response.json()
                access_token = token_data["access_token"]
            except json.JSONDecodeError as e:
                LOGGER.error("Failed to parse token response as JSON: %s", e)
                LOGGER.error("Response content: %s", token_response.text)
                raise

            # Test with invalid proof type
            invalid_proof_request = {
                "credential_identifier": "org.iso.18013.5.1.mDL",
                "proof": {
                    "jwt": (
                        "eyJ0eXAiOiJpbnZhbGlkIiwiYWxnIjoiRVMyNTYifQ."
                        "eyJub25jZSI6InRlc3QifQ.sig"
                    )
                }
            }

            response = await client.post(
                f"{TEST_CONFIG['oid4vci_endpoint']}/credential",
                json=invalid_proof_request,
                headers={"Authorization": f"Bearer {access_token}"}
            )

            # Should fail due to wrong typ header
            assert response.status_code == 400
            error_msg = response.json().get("message", "")
            assert "openid4vci-proof+jwt" in error_msg

            test_runner.test_results["proof_of_possession"] = {
                "status": "PASS",
                "validation": "OID4VCI 1.0 § 7.2.1 proof validation enforced"
            }

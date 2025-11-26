"""Test utilities for OID4VCI 1.0 compliance tests."""

import logging
import time
from typing import Any

import httpx

from .test_config import (
    CREDENTIAL_SUBJECT_DATA,
    MDOC_AVAILABLE,
    MSO_MDOC_CREDENTIAL_CONFIG,
    TEST_CONFIG,
    mdl,
)

LOGGER = logging.getLogger(__name__)


class OID4VCTestHelper:
    """Helper class for OID4VCI 1.0 compliance tests."""

    def __init__(self):
        """Initialize test helper."""
        self.test_results = {}

    async def setup_supported_credential(self) -> str:
        """Setup supported credential and return its ID."""
        # Use timestamp to ensure unique ID across tests
        unique_id = f"UniversityDegree-{int(time.time() * 1000)}"

        # Create credential configuration
        config = {
            "id": unique_id,
            "format": "jwt_vc_json",
            "identifier": "UniversityDegreeCredential",
            "cryptographic_binding_methods_supported": ["did:key", "did:jwk"],
            "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
            "display": [
                {
                    "name": "University Degree",
                    "locale": "en-US",
                    "background_color": "#1e3a8a",
                    "text_color": "#ffffff",
                }
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/credential-supported/create",
                json=config,
            )
            response.raise_for_status()
            result = response.json()
            LOGGER.info("Credential setup response: %s", result)
            # Return the supported_cred_id, not the identifier
            return result["supported_cred_id"]

    async def create_credential_offer(self, supported_cred_id: str) -> dict[str, Any]:
        """Create credential offer."""
        offer_data = {
            "supported_cred_id": supported_cred_id,
            "credential_subject": CREDENTIAL_SUBJECT_DATA,
            "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",  # Test DID
        }

        async with httpx.AsyncClient() as client:
            # First create the exchange
            response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/exchange/create",
                json=offer_data,
            )
            response.raise_for_status()
            exchange_data = response.json()
            LOGGER.info("Exchange creation response: %s", exchange_data)

            # Then generate the credential offer with code
            offer_response = await client.get(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/credential-offer",
                params={"exchange_id": exchange_data["exchange_id"]},
            )
            offer_response.raise_for_status()
            offer_result = offer_response.json()
            LOGGER.info("Credential offer response: %s", offer_result)

            # Merge exchange data with offer data
            return {**exchange_data, **offer_result}

    async def setup_mdoc_credential(self) -> str:
        """Setup mso_mdoc credential and return its ID."""
        if not MDOC_AVAILABLE:
            raise RuntimeError("isomdl_uniffi not available for mdoc testing")

        # Use timestamp to ensure unique ID across tests
        unique_id = f"mDL-{int(time.time() * 1000)}"

        # Create mso_mdoc credential configuration
        config = {
            "id": unique_id,
            "format": "mso_mdoc",
            "identifier": "org.iso.18013.5.1.mDL",
            "doctype": "org.iso.18013.5.1.mDL",
            "cryptographic_binding_methods_supported": ["cose_key"],
            "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
            "display": MSO_MDOC_CREDENTIAL_CONFIG["display"],
            "claims": MSO_MDOC_CREDENTIAL_CONFIG["claims"],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/credential-supported/create",
                json=config,
            )
            response.raise_for_status()
            result = response.json()
            LOGGER.info("mso_mdoc credential setup response: %s", result)
            return result["supported_cred_id"]

    async def create_mdoc_credential_offer(
        self, supported_cred_id: str
    ) -> dict[str, Any]:
        """Create credential offer for mso_mdoc format."""
        if not MDOC_AVAILABLE:
            raise RuntimeError("isomdl_uniffi not available")

        # Generate test mdoc using isomdl_uniffi
        holder_key = mdl.P256KeyPair()

        offer_data = {
            "supported_cred_id": supported_cred_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "birth_date": "1990-01-01",
                    "issue_date": "2023-01-01",
                    "expiry_date": "2033-01-01",
                    "issuing_country": "US",
                    "document_number": "12345678",
                }
            },
            "holder_binding": {"method": "cose_key", "key": holder_key.public_jwk()},
        }

        async with httpx.AsyncClient() as client:
            # Create the exchange
            response = await client.post(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/exchange/create",
                json=offer_data,
            )
            response.raise_for_status()
            exchange_data = response.json()
            LOGGER.info("mso_mdoc exchange creation response: %s", exchange_data)

            # Generate the credential offer
            offer_response = await client.get(
                f"{TEST_CONFIG['admin_endpoint']}/oid4vci/credential-offer",
                params={"exchange_id": exchange_data["exchange_id"]},
            )
            offer_response.raise_for_status()
            offer_result = offer_response.json()
            LOGGER.info("mso_mdoc credential offer response: %s", offer_result)

            # Include holder key for testing
            return {**exchange_data, **offer_result, "holder_key": holder_key}

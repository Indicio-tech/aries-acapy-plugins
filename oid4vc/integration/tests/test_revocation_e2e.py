"""End-to-end revocation tests for Credo and Sphereon."""

import asyncio
import json
import logging
import uuid
import pytest
import httpx
import jwt
import zlib
import gzip
import base64
from bitarray import bitarray

from .test_config import TEST_CONFIG, MDOC_AVAILABLE

LOGGER = logging.getLogger(__name__)

@pytest.mark.asyncio
async def test_credo_revocation_flow(
    acapy_issuer_admin,
    credo_client,
):
    """Test revocation flow with Credo agent.
    
    1. Setup Issuer with Status List.
    2. Issue credential to Credo.
    3. Revoke credential.
    4. Verify status list is updated.
    """
    LOGGER.info("Starting Credo revocation flow test...")

    # 1. Setup Issuer
    # Create a supported credential
    cred_id = f"RevocableCred-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["ES256"],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                }
            },
            "format": "jwt_vc_json",
            "id": cred_id,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "display": [
                {
                    "name": "Revocable Credential",
                    "locale": "en-US",
                }
            ],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "ed25519"}},
    )
    issuer_did = did_result["result"]["did"]

    # Create Status List Definition
    status_def = await acapy_issuer_admin.post(
        "/status-list/defs",
        json={
            "supported_cred_id": supported_cred_id,
            "status_purpose": "revocation",
            "list_size": 1024,
            "list_type": "w3c",
            "issuer_did": issuer_did
        }
    )
    definition_id = status_def["id"]

    # 2. Issue Credential to Credo
    # Create exchange
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "Alice"},
            "did": issuer_did,
        },
    )
    exchange_id = exchange["exchange_id"]
    
    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_id},
    )
    credential_offer = offer_response["credential_offer"]

    # Credo accepts offer
    response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": credential_offer,
            "holder_did_method": "key",
        },
    )
    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    credential_data = result["credential"]

    credential_jwt = None
    if isinstance(credential_data, dict):
        if "compact" in credential_data:
            credential_jwt = credential_data["compact"]
        elif "jwt" in credential_data and "serializedJwt" in credential_data["jwt"]:
            credential_jwt = credential_data["jwt"]["serializedJwt"]
        # Credo 0.6.0 format: record.credentialInstances[0].<format>
        # - compactSdJwtVc for SD-JWT
        # - credential for W3C JWT (jwt_vc_json)
        elif "record" in credential_data:
            record = credential_data["record"]
            if "credentialInstances" in record and len(record["credentialInstances"]) > 0:
                instance = record["credentialInstances"][0]
                if "compactSdJwtVc" in instance:
                    credential_jwt = instance["compactSdJwtVc"]
                elif "credential" in instance:
                    # W3C JWT credential format
                    credential_jwt = instance["credential"]
                elif "compactJwtVc" in instance:
                    credential_jwt = instance["compactJwtVc"]
    elif isinstance(credential_data, str):
        credential_jwt = credential_data
    
    if credential_jwt is None:
        pytest.skip(f"Could not extract JWT from credential data: {type(credential_data)}")

    # Verify credential has status list (only for JWT-based credentials)
    # SD-JWT format: header.payload.signature~disclosure1~disclosure2~...
    # Regular JWT format: header.payload.signature
    jwt_part = credential_jwt.split('~')[0] if '~' in credential_jwt else credential_jwt
    payload = jwt.decode(jwt_part, options={"verify_signature": False})
    vc = payload.get("vc", payload)
    assert "credentialStatus" in vc
    
    # Check for bitstring format
    credential_status = vc["credentialStatus"]
    assert credential_status["type"] == "BitstringStatusListEntry"
    assert "id" in credential_status
    
    # Extract index from id (format: url#index)
    status_list_index = int(credential_status["id"].split("#")[1])
    status_list_url = credential_status["id"].split("#")[0]
    
    # Fix hostname for docker network if needed
    if "acapy-issuer.local" in status_list_url:
        status_list_url = status_list_url.replace("acapy-issuer.local", "acapy-issuer")
    elif "localhost" in status_list_url:
        status_list_url = status_list_url.replace("localhost", "acapy-issuer")
    
    LOGGER.info(f"Credential issued with status list index: {status_list_index}")

    # 3. Revoke Credential
    # We use exchange_id as credential_id for status list binding in OID4VC plugin
    LOGGER.info(f"Revoking credential with ID: {exchange_id}")
    
    update_response = await acapy_issuer_admin.patch(
        f"/status-list/defs/{definition_id}/creds/{exchange_id}",
        json={"status": "1"}
    )

    # Publish update
    publish_response = await acapy_issuer_admin.put(
        f"/status-list/defs/{definition_id}/publish"
    )

    # 4. Verify Status List Updated
    async with httpx.AsyncClient() as client:
        response = await client.get(status_list_url)
        assert response.status_code == 200
        status_list_jwt = response.text
        
        sl_payload = jwt.decode(status_list_jwt, options={"verify_signature": False})
        
        # W3C format
        encoded_list = sl_payload["vc"]["credentialSubject"]["encodedList"]
        
        # Decode bitstring
        missing_padding = len(encoded_list) % 4
        if missing_padding:
            encoded_list += '=' * (4 - missing_padding)
        
        compressed_bytes = base64.urlsafe_b64decode(encoded_list)
        bit_bytes = gzip.decompress(compressed_bytes)
        
        ba = bitarray()
        ba.frombytes(bit_bytes)
        
        assert ba[status_list_index] == 1, "Bit should be set to 1 (revoked)"
        LOGGER.info("Revocation verified successfully for Credo flow")


@pytest.mark.asyncio
# @pytest.mark.skip(reason="Sphereon not available in dev env")
async def test_sphereon_revocation_flow(
    acapy_issuer_admin,
    sphereon_client,
):
    """Test revocation flow with Sphereon agent.
    
    1. Setup Issuer with Status List.
    2. Issue credential to Sphereon.
    3. Revoke credential.
    4. Verify status list is updated.
    """
    LOGGER.info("Starting Sphereon revocation flow test...")

    # 1. Setup Issuer
    cred_id = f"RevocableCredSphereon-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "display": [
                {
                    "name": "Revocable Credential Sphereon",
                    "locale": "en-US",
                }
            ],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/wallet/did/create",
        json={"method": "key", "options": {"key_type": "ed25519"}},
    )
    issuer_did = did_result["result"]["did"]

    # Create Status List Definition
    status_def = await acapy_issuer_admin.post(
        "/status-list/defs",
        json={
            "supported_cred_id": supported_cred_id,
            "status_purpose": "revocation",
            "list_size": 1024,
            "list_type": "w3c",
            "issuer_did": issuer_did
        }
    )
    definition_id = status_def["id"]

    # 2. Issue Credential to Sphereon
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "Bob"},
            "did": issuer_did,
        },
    )
    exchange_id = exchange["exchange_id"]
    
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_id},
    )
    credential_offer = offer_response["credential_offer"]

    # Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer},
    )
    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    credential_jwt = result["credential"]

    # Verify credential has status list
    payload = jwt.decode(credential_jwt, options={"verify_signature": False})
    vc = payload.get("vc", payload)
    assert "credentialStatus" in vc
    
    # Check for bitstring format
    credential_status = vc["credentialStatus"]
    assert credential_status["type"] == "BitstringStatusListEntry"
    assert "id" in credential_status
    
    # Extract index from id (format: url#index)
    status_list_index = int(credential_status["id"].split("#")[1])
    status_list_url = credential_status["id"].split("#")[0]
    
    # Fix hostname for docker network if needed
    if "acapy-issuer.local" in status_list_url:
        status_list_url = status_list_url.replace("acapy-issuer.local", "acapy-issuer")
    elif "localhost" in status_list_url:
        status_list_url = status_list_url.replace("localhost", "acapy-issuer")
    
    LOGGER.info(f"Credential issued with status list index: {status_list_index}")

    # 3. Revoke Credential
    LOGGER.info(f"Revoking credential with ID: {exchange_id}")
    
    update_response = await acapy_issuer_admin.patch(
        f"/status-list/defs/{definition_id}/creds/{exchange_id}",
        json={"status": "1"}
    )

    # Publish update
    publish_response = await acapy_issuer_admin.put(
        f"/status-list/defs/{definition_id}/publish"
    )

    # 4. Verify Status List Updated
    async with httpx.AsyncClient() as client:
        response = await client.get(status_list_url)
        assert response.status_code == 200
        status_list_jwt = response.text
        
        sl_payload = jwt.decode(status_list_jwt, options={"verify_signature": False})
        
        # W3C format
        encoded_list = sl_payload["vc"]["credentialSubject"]["encodedList"]
        
        # Decode bitstring
        missing_padding = len(encoded_list) % 4
        if missing_padding:
            encoded_list += '=' * (4 - missing_padding)
        
        compressed_bytes = base64.urlsafe_b64decode(encoded_list)
        bit_bytes = gzip.decompress(compressed_bytes)
        
        ba = bitarray()
        ba.frombytes(bit_bytes)
        
        assert ba[status_list_index] == 1, "Bit should be set to 1 (revoked)"
        LOGGER.info("Revocation verified successfully for Sphereon flow")

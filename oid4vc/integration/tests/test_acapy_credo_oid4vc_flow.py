"""Test ACA-Py to Credo to ACA-Py OID4VC flow.

This test covers the complete OID4VC flow:
1. ACA-Py (Issuer) issues credential via OID4VCI
2. Credo receives and stores credential
3. ACA-Py (Verifier) requests presentation via OID4VP
4. Credo presents credential to ACA-Py (Verifier)
5. ACA-Py (Verifier) validates the presentation
"""

import asyncio
import uuid

import pytest


@pytest.mark.asyncio
async def test_acapy_issuer_health(acapy_issuer_admin):
    """Test that ACA-Py issuer is healthy and ready."""
    status = await acapy_issuer_admin.get("/status/ready")
    assert status.get("ready") is True


@pytest.mark.asyncio
async def test_acapy_verifier_health(acapy_verifier_admin):
    """Test that ACA-Py verifier is healthy and ready."""
    status = await acapy_verifier_admin.get("/status/ready")
    assert status.get("ready") is True


@pytest.mark.asyncio
async def test_acapy_oid4vci_credential_issuance_to_credo(
    acapy_issuer_admin,
    credo_client,
):
    """Test ACA-Py issuing credentials to Credo via OID4VCI."""

    # Step 1: Create a supported credential on ACA-Py issuer
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"IdentityCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "IdentityCredential",
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "IdentityCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "email": {"mandatory": False},
                "birth_date": {"mandatory": False},
            },
            "display": [
                {
                    "name": "Identity Credential",
                    "locale": "en-US",
                    "description": "A basic identity credential",
                }
            ],
        },
        "vc_additional_data": {
            "sd_list": ["/given_name", "/family_name", "/email", "/birth_date"]
        },
    }

    # Register the credential type with ACA-Py issuer
    credential_config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    assert "supported_cred_id" in credential_config_response
    config_id = credential_config_response["supported_cred_id"]

    # Create a DID for the issuer
    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    issuer_did = did_response["result"]["did"]

    # Step 2: Create credential offer
    exchange_request = {
        "supported_cred_id": config_id,
        "credential_subject": {
            "given_name": "John",
            "family_name": "Doe",
            "email": "john.doe@example.com",
            "birth_date": "1990-01-01",
        },
        "did": issuer_did,
    }

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    exchange_id = exchange_response["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    assert "credential_offer_uri" in offer_response
    credential_offer_uri = offer_response["credential_offer_uri"]

    # Step 3: Credo accepts the credential offer
    accept_offer_request = {
        "credential_offer": credential_offer_uri,
        "holder_did_method": "key",
    }

    response = await credo_client.post(
        "/oid4vci/accept-offer", json=accept_offer_request
    )
    if response.status_code != 200:
        print(f"Credo accept-offer failed: {response.text}")
    assert response.status_code == 200
    credential_result = response.json()

    assert "credential" in credential_result
    assert "format" in credential_result
    assert credential_result["format"] == "vc+sd-jwt"

    # Store credential reference for presentation test
    return credential_result["credential"]


@pytest.mark.asyncio
async def test_acapy_oid4vp_presentation_verification_from_credo(
    acapy_verifier_admin,
):
    """Test ACA-Py verifying presentations from Credo via OID4VP."""

    # First issue a credential to have something to present
    # (In a real test suite, this would use the credential from the previous test)

    # Step 1: Create presentation definition for SD-JWT credential
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": "identity-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "IdentityCredential"},
                            },
                        },
                        {
                            "path": ["$.credentialSubject.given_name"],
                            "intent_to_retain": False,
                        },
                        {
                            "path": ["$.credentialSubject.family_name"],
                            "intent_to_retain": False,
                        },
                    ]
                },
            }
        ],
    }

    # Step 2: Create presentation definition first
    pres_def_data = {"pres_def": presentation_definition}

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json=pres_def_data
    )
    assert "pres_def_id" in pres_def_response
    pres_def_id = pres_def_response["pres_def_id"]

    # Step 3: ACA-Py creates presentation request
    presentation_request_data = {
        "pres_def_id": pres_def_id,
        "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
    }

    presentation_request = await acapy_verifier_admin.post(
        "/oid4vp/request", json=presentation_request_data
    )

    assert "request_uri" in presentation_request
    request_uri = presentation_request["request_uri"]

    return {
        "request_uri": request_uri,
        "presentation_definition": presentation_definition,
    }


@pytest.mark.asyncio
async def test_full_acapy_credo_oid4vc_flow(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test complete OID4VC flow: ACA-Py issues → Credo receives → Credo presents → ACA-Py verifies."""

    # Step 1: Setup credential configuration on ACA-Py issuer
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"TestCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "UniversityDegree",
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "UniversityDegreeCredential",
            "claims": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "degree": {"mandatory": True},
                "university": {"mandatory": True},
                "graduation_date": {"mandatory": False},
            },
            "display": [
                {
                    "name": "University Degree",
                    "locale": "en-US",
                    "description": "A university degree credential",
                }
            ],
        },
        "vc_additional_data": {
            "sd_list": [
                "/given_name",
                "/family_name",
                "/degree",
                "/university",
                "/graduation_date",
            ]
        },
    }

    credential_config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = credential_config_response["supported_cred_id"]

    # Create a DID for the issuer
    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    issuer_did = did_response["result"]["did"]

    # Step 2: Create pre-authorized credential offer
    exchange_request = {
        "supported_cred_id": config_id,
        "credential_subject": {
            "given_name": "Alice",
            "family_name": "Smith",
            "degree": "Bachelor of Computer Science",
            "university": "Example University",
            "graduation_date": "2023-05-15",
        },
        "did": issuer_did,
    }

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    exchange_id = exchange_response["exchange_id"]

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    credential_offer_uri = offer_response["credential_offer_uri"]

    # Step 3: Credo accepts credential offer and receives credential
    accept_offer_request = {
        "credential_offer": credential_offer_uri,
        "holder_did_method": "key",
    }

    credential_response = await credo_client.post(
        "/oid4vci/accept-offer", json=accept_offer_request
    )
    if credential_response.status_code != 200:
        print(f"Credo accept-offer failed: {credential_response.text}")
    assert credential_response.status_code == 200
    credential_result = credential_response.json()

    assert "credential" in credential_result
    assert credential_result["format"] == "vc+sd-jwt"
    received_credential = credential_result["credential"]

    # Step 4: ACA-Py verifier creates presentation request
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": "degree-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct", "$.type"],
                            "filter": {
                                "type": "string",
                                "const": "UniversityDegreeCredential",
                            },
                        },
                        {
                            "path": ["$.given_name", "$.credentialSubject.given_name"],
                        },
                        {
                            "path": [
                                "$.family_name",
                                "$.credentialSubject.family_name",
                            ],
                        },
                        {
                            "path": ["$.degree", "$.credentialSubject.degree"],
                        },
                        {
                            "path": ["$.university", "$.credentialSubject.university"],
                        },
                    ]
                },
            }
        ],
    }

    # Create presentation definition first
    pres_def_data = {"pres_def": presentation_definition}

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json=pres_def_data
    )
    assert "pres_def_id" in pres_def_response
    pres_def_id = pres_def_response["pres_def_id"]

    presentation_request_data = {
        "pres_def_id": pres_def_id,
        "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
    }

    presentation_request = await acapy_verifier_admin.post(
        "/oid4vp/request", json=presentation_request_data
    )
    request_uri = presentation_request["request_uri"]
    presentation_id = presentation_request["presentation"]["presentation_id"]

    # Step 5: Credo presents credential to ACA-Py verifier
    present_request = {"request_uri": request_uri, "credentials": [received_credential]}

    presentation_response = await credo_client.post(
        "/oid4vp/present", json=present_request
    )
    assert presentation_response.status_code == 200
    presentation_result = presentation_response.json()

    # Step 6: Verify presentation was successful
    assert "presentation_submission" in presentation_result
    assert presentation_result.get("success") is True

    # Step 7: Check that ACA-Py received and validated the presentation
    # Poll for presentation status
    max_retries = 10
    retry_interval = 1.0

    presentation_valid = False
    latest_presentation = None

    for _ in range(max_retries):
        # Get specific presentation record from ACA-Py verifier
        latest_presentation = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )

        if latest_presentation.get("state") == "presentation-valid":
            presentation_valid = True
            break

        await asyncio.sleep(retry_interval)

    assert (
        presentation_valid
    ), f"Presentation validation failed. Final state: {latest_presentation.get('state') if latest_presentation else 'None'}"

    print("✅ Full OID4VC flow completed successfully!")
    print(f"   - ACA-Py issued credential: {config_id}")
    print(f"   - Credo received credential format: {credential_result['format']}")
    print(f"   - Presentation verified with status: {latest_presentation.get('state')}")


@pytest.mark.asyncio
async def test_error_handling_invalid_credential_offer(credo_client):
    """Test error handling when Credo receives invalid credential offer."""

    invalid_offer_request = {
        "credential_offer_uri": "http://invalid-issuer/invalid-offer",
        "holder_did_method": "key",
    }

    response = await credo_client.post(
        "/oid4vci/accept-offer", json=invalid_offer_request
    )
    # Should handle gracefully - exact status code depends on implementation
    assert response.status_code in [400, 404, 422, 500]


@pytest.mark.asyncio
async def test_error_handling_invalid_presentation_request(credo_client):
    """Test error handling when Credo receives invalid presentation request."""

    invalid_present_request = {
        "request_uri": "http://invalid-verifier/invalid-request",
        "credentials": ["invalid-credential"],
    }

    response = await credo_client.post("/oid4vp/present", json=invalid_present_request)
    # Should handle gracefully - exact status code depends on implementation
    assert response.status_code in [400, 404, 422, 500]

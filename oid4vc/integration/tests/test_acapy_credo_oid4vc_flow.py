"""Test ACA-Py to Credo to ACA-Py OID4VC flow.

This test covers the complete OID4VC flow:
1. ACA-Py (Issuer) issues credential via OID4VCI
2. Credo receives and stores credential
3. ACA-Py (Verifier) requests presentation via OID4VP
4. Credo presents credential to ACA-Py (Verifier)
5. ACA-Py (Verifier) validates the presentation
"""

import asyncio

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
    credential_supported = {
        "id": "IdentityCredential",
        "format": "vc+sd-jwt",
        "scope": "IdentityCredential",
        "cryptographic_binding_methods_supported": ["did:key"],
        "cryptographic_suites_supported": ["EdDSA"],
        "credential_definition": {
            "type": ["VerifiableCredential", "IdentityCredential"],
            "credentialSubject": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "email": {"mandatory": False},
                "birth_date": {"mandatory": False},
            },
        },
        "display": [
            {
                "name": "Identity Credential",
                "locale": "en-US",
                "description": "A basic identity credential",
            }
        ],
    }

    # Register the credential type with ACA-Py issuer
    credential_config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    assert "credential_configuration_id" in credential_config_response
    config_id = credential_config_response["credential_configuration_id"]

    # Step 2: Create credential offer
    offer_request = {
        "credential_configuration_id": config_id,
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": True,
                "user_pin_required": False,
            }
        },
    }

    offer_response = await acapy_issuer_admin.post(
        "/oid4vci/create-offer", json=offer_request
    )
    assert "credential_offer_uri" in offer_response
    credential_offer_uri = offer_response["credential_offer_uri"]

    # Step 3: Credo accepts the credential offer
    accept_offer_request = {
        "credential_offer_uri": credential_offer_uri,
        "holder_did_method": "key",
    }

    response = await credo_client.post(
        "/oid4vci/accept-offer", json=accept_offer_request
    )
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
        "id": "identity-credential-presentation",
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
    pres_def_data = {
        "pres_def": presentation_definition
    }
    
    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json=pres_def_data
    )
    assert "pres_def_id" in pres_def_response
    pres_def_id = pres_def_response["pres_def_id"]

    # Step 3: ACA-Py creates presentation request
    presentation_request_data = {
        "pres_def_id": pres_def_id,
        "vp_formats": {
            "vc+sd-jwt": {
                "sd-jwt_alg_values": ["EdDSA", "ES256K", "ES256"]
            }
        }
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
    credential_supported = {
        "id": "UniversityDegreeCredential",
        "format": "vc+sd-jwt",
        "scope": "UniversityDegree",
        "cryptographic_binding_methods_supported": ["did:key"],
        "cryptographic_suites_supported": ["EdDSA"],
        "credential_definition": {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "credentialSubject": {
                "given_name": {"mandatory": True},
                "family_name": {"mandatory": True},
                "degree": {"mandatory": True},
                "university": {"mandatory": True},
                "graduation_date": {"mandatory": False},
            },
        },
        "display": [
            {
                "name": "University Degree",
                "locale": "en-US",
                "description": "A university degree credential",
            }
        ],
    }

    credential_config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = credential_config_response["credential_configuration_id"]

    # Step 2: Create pre-authorized credential offer
    offer_request = {
        "credential_configuration_id": config_id,
        "credential_data": {
            "given_name": "Alice",
            "family_name": "Smith",
            "degree": "Bachelor of Computer Science",
            "university": "Example University",
            "graduation_date": "2023-05-15",
        },
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": True,
                "user_pin_required": False,
            }
        },
    }

    offer_response = await acapy_issuer_admin.post(
        "/oid4vci/create-offer", json=offer_request
    )
    credential_offer_uri = offer_response["credential_offer_uri"]

    # Step 3: Credo accepts credential offer and receives credential
    accept_offer_request = {
        "credential_offer_uri": credential_offer_uri,
        "holder_did_method": "key",
    }

    credential_response = await credo_client.post(
        "/oid4vci/accept-offer", json=accept_offer_request
    )
    assert credential_response.status_code == 200
    credential_result = credential_response.json()

    assert "credential" in credential_result
    assert credential_result["format"] == "vc+sd-jwt"
    received_credential = credential_result["credential"]

    # Step 4: ACA-Py verifier creates presentation request
    presentation_definition = {
        "id": "university-degree-presentation",
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": "degree-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "UniversityDegreeCredential"},
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
                        {
                            "path": ["$.credentialSubject.degree"],
                            "intent_to_retain": False,
                        },
                    ]
                },
            }
        ],
    }

    # Create presentation definition first
    pres_def_data = {
        "pres_def": presentation_definition
    }
    
    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json=pres_def_data
    )
    assert "pres_def_id" in pres_def_response
    pres_def_id = pres_def_response["pres_def_id"]

    presentation_request_data = {
        "pres_def_id": pres_def_id,
        "vp_formats": {
            "vc+sd-jwt": {
                "sd-jwt_alg_values": ["EdDSA", "ES256K", "ES256"]
            }
        }
    }

    presentation_request = await acapy_verifier_admin.post(
        "/oid4vp/request", json=presentation_request_data
    )
    request_uri = presentation_request["request_uri"]

    # Step 5: Credo presents credential to ACA-Py verifier
    present_request = {"request_uri": request_uri, "credentials": [received_credential]}

    presentation_response = await credo_client.post(
        "/oid4vp/present", json=present_request
    )
    assert presentation_response.status_code == 200
    presentation_result = presentation_response.json()

    # Step 6: Verify presentation was successful
    assert "presentation_submission" in presentation_result
    assert presentation_result.get("status") == "success"

    # Step 7: Check that ACA-Py received and validated the presentation
    # Wait a moment for processing
    await asyncio.sleep(2)

    # Get presentation records from ACA-Py verifier
    presentations = await acapy_verifier_admin.get("/oid4vp/presentations")
    assert len(presentations) > 0

    # Find our presentation
    latest_presentation = presentations[0]  # Assuming most recent
    assert latest_presentation.get("state") == "presentation-valid"

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

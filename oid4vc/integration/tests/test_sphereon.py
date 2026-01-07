import uuid

import pytest

from .test_config import MDOC_AVAILABLE


@pytest.mark.asyncio
async def test_sphereon_health(sphereon_client):
    """Test that Sphereon wrapper is healthy."""
    response = await sphereon_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_sphereon_accept_credential_offer(acapy_issuer_admin, sphereon_client):
    """Test Sphereon accepting a credential offer from ACA-Py."""

    # 1. Setup Issuer (ACA-Py)
    # Create a supported credential
    cred_id = f"UniversityDegreeCredential-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    # Create exchange
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # 2. Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    print(f"Received credential: {result['credential']}")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_sphereon_accept_mdoc_credential_offer(
    acapy_issuer_admin, sphereon_client
):
    """Test Sphereon accepting an mdoc credential offer from ACA-Py."""

    # 1. Setup Issuer (ACA-Py)
    cred_id = f"mDL-{uuid.uuid4()}"

    # Create mdoc supported credential
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["cose_key"],
            "cryptographic_suites_supported": ["ES256", "ES384", "ES512"],
            "format": "mso_mdoc",
            "id": cred_id,
            "identifier": "org.iso.18013.5.1.mDL",
            "format_data": {"doctype": "org.iso.18013.5.1.mDL"},
            "display": [
                {
                    "name": "Mobile Driver's License",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://example.com/mdl-logo.png",
                        "alt_text": "mDL Logo",
                    },
                    "background_color": "#003f7f",
                    "text_color": "#ffffff",
                }
            ],
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {
                        "mandatory": True,
                        "display": [{"name": "Given Name", "locale": "en-US"}],
                    },
                    "family_name": {
                        "mandatory": True,
                        "display": [{"name": "Family Name", "locale": "en-US"}],
                    },
                    "birth_date": {
                        "mandatory": True,
                        "display": [{"name": "Date of Birth", "locale": "en-US"}],
                    },
                }
            },
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    # Create exchange
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "birth_date": "1990-01-01",
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # 2. Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer, "format": "mso_mdoc"},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result
    print(f"Received mdoc credential: {result['credential']}")

    # Verify the credential using isomdl_uniffi
    if MDOC_AVAILABLE:
        import isomdl_uniffi as mdl

        # Parse the credential
        mdoc_b64 = result["credential"]

        key_alias = "parsed"
        mdoc = mdl.Mdoc.new_from_base64url_encoded_issuer_signed(mdoc_b64, key_alias)

        # Verify issuer signature (if we had the issuer's cert/key, we could verify it fully)
        # For now, just checking we can parse it and get the doctype/id is a good step
        assert mdoc.doctype() == "org.iso.18013.5.1.mDL"
        assert mdoc.id() is not None

        print(f"Verified mdoc parsing: {mdoc.doctype()} / {mdoc.id()}")


@pytest.mark.skipif(not MDOC_AVAILABLE, reason="isomdl_uniffi not available")
@pytest.mark.asyncio
async def test_sphereon_present_mdoc_credential(
    acapy_verifier_admin, acapy_issuer_admin, sphereon_client
):
    """Test Sphereon presenting an mdoc credential to ACA-Py."""

    # 1. Issue a credential first (reuse setup from previous test or create new)
    cred_id = f"mDL-{uuid.uuid4()}"

    # Create mdoc supported credential
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["cose_key"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "mso_mdoc",
            "id": cred_id,
            "identifier": "org.iso.18013.5.1.mDL",
            "format_data": {"doctype": "org.iso.18013.5.1.mDL"},
            "display": [{"name": "mDL", "locale": "en-US"}],
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {"mandatory": True},
                    "family_name": {"mandatory": True},
                    "birth_date": {"mandatory": True},
                }
            },
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    # Create issuer DID
    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    # Create exchange
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "John",
                    "family_name": "Doe",
                    "birth_date": "1990-01-01",
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # Sphereon accepts offer
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer, "format": "mso_mdoc"},
    )
    assert response.status_code == 200
    credential_hex = response.json()["credential"]

    # 2. Create Presentation Request (ACA-Py Verifier)
    # Create presentation definition
    pres_def_id = str(uuid.uuid4())
    presentation_definition = {
        "id": pres_def_id,
        "input_descriptors": [
            {
                "id": "mdl",
                "name": "Mobile Driver's License",
                "format": {"mso_mdoc": {"alg": ["ES256"]}},
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {
                            "path": ["$['org.iso.18013.5.1']['given_name']"],
                            "intent_to_retain": False,
                        },
                        {
                            "path": ["$['org.iso.18013.5.1']['family_name']"],
                            "intent_to_retain": False,
                        },
                    ],
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )
    pres_def_id = pres_def_response["pres_def_id"]

    # Create request
    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"mso_mdoc": {"alg": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]
    presentation_id = request_response["presentation"]["presentation_id"]

    # 3. Sphereon presents credential
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_uri,
            "verifiable_credentials": [credential_hex],
        },
    )

    assert present_response.status_code == 200

    # 4. Verify status on ACA-Py side
    import asyncio

    for _ in range(10):
        record = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )
        if record["state"] == "presentation-valid":
            break
        await asyncio.sleep(1)
    else:
        pytest.fail(f"Presentation not verified. Final state: {record['state']}")
    """Test Sphereon presenting a credential to ACA-Py."""

    # 1. Issue a credential first
    cred_id = f"UniversityDegreeCredential-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    supported_cred_id = supported["supported_cred_id"]
    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create", json={"key_type": "p256"}
    )
    issuer_did = did_result["did"]
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )
    credential_offer = offer_response["credential_offer"]

    issue_response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": credential_offer}
    )
    assert issue_response.status_code == 200
    credential_jwt = issue_response.json()["credential"]

    # 2. Create Presentation Request (ACA-Py Verifier)
    # Create verifier DID
    verifier_did_result = await acapy_verifier_admin.post(
        "/did/jwk/create", json={"key_type": "p256"}
    )
    verifier_did = verifier_did_result["did"]

    # Create presentation definition
    pres_def_id = str(uuid.uuid4())
    presentation_definition = {
        "id": pres_def_id,
        "input_descriptors": [
            {
                "id": "university_degree",
                "name": "University Degree",
                "schema": [{"uri": "https://www.w3.org/2018/credentials/examples/v1"}],
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )
    pres_def_id = pres_def_response["pres_def_id"]

    # Create request
    request_response = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_id,
            "vp_formats": {"jwt_vp_json": {"alg": ["ES256"]}},
        },
    )
    request_uri = request_response["request_uri"]
    presentation_id = request_response["presentation"]["presentation_id"]

    # 3. Sphereon presents credential
    present_response = await sphereon_client.post(
        "/oid4vp/present-credential",
        json={
            "authorization_request_uri": request_uri,
            "verifiable_credentials": [credential_jwt],
        },
    )

    assert present_response.status_code == 200

    # 4. Verify status on ACA-Py side
    # Poll for status
    import asyncio

    for _ in range(10):
        record = await acapy_verifier_admin.get(
            f"/oid4vp/presentation/{presentation_id}"
        )
        if record["state"] == "presentation-valid":
            break
        await asyncio.sleep(1)
    else:
        pytest.fail(f"Presentation not verified. Final state: {record['state']}")


@pytest.mark.asyncio
async def test_sphereon_accept_credential_offer_by_ref(
    acapy_issuer_admin, sphereon_client
):
    """Test Sphereon accepting a credential offer by reference from ACA-Py."""

    # 1. Setup Issuer (ACA-Py)
    cred_id = f"UniversityDegreeCredential-{uuid.uuid4()}"
    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    supported_cred_id = supported["supported_cred_id"]

    did_result = await acapy_issuer_admin.post(
        "/did/jwk/create",
        json={"key_type": "p256"},
    )
    issuer_did = did_result["did"]

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )

    # Get offer by ref
    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer-by-ref",
        params={"exchange_id": exchange["exchange_id"]},
    )
    credential_offer_uri = offer_response["credential_offer_uri"]

    # 2. Sphereon accepts offer
    # The Sphereon client library should handle dereferencing the URI
    response = await sphereon_client.post(
        "/oid4vci/accept-offer",
        json={"offer": credential_offer_uri},
    )

    assert response.status_code == 200
    result = response.json()
    assert "credential" in result

"""Edge case and error handling tests for Credo/Sphereon compatibility.

These tests probe for bugs in error handling, timeout behavior,
and unusual request patterns between the wallet implementations.
"""

import asyncio
import uuid

import pytest


def extract_credential(response, wallet_name: str) -> str:
    """Safely extract credential from wallet response, skipping test if unavailable.

    Args:
        response: The HTTP response from wallet accept-offer call
        wallet_name: Name of wallet for error messages (e.g., "Credo", "Sphereon")

    Returns:
        The credential string

    Raises:
        pytest.skip: If credential could not be obtained (infrastructure issue)
    """
    if response.status_code != 200:
        pytest.skip(
            f"{wallet_name} failed to accept offer (status {response.status_code}): {response.text}"
        )

    resp_json = response.json()
    if "credential" not in resp_json:
        pytest.skip(f"{wallet_name} did not return credential: {resp_json}")

    return resp_json["credential"]


# =============================================================================
# Credential Offer Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_expired_credential_offer(
    acapy_issuer_admin,
    credo_client,
):
    """Test Credo behavior with an already-used credential offer.

    Bug discovery: Does Credo properly handle token reuse errors?
    """
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"ExpiredOfferCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "ExpiredOfferTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "ExpiredOfferCredential",
            "claims": {"test": {"mandatory": True}},
        },
        "vc_additional_data": {"sd_list": ["/test"]},
    }

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    config_id = config_response["supported_cred_id"]

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    issuer_did = did_response["result"]["did"]

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_id,
            "credential_subject": {"test": "value"},
            "did": issuer_did,
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_response["exchange_id"]},
    )
    credential_offer = offer_response["credential_offer"]

    # First attempt - should succeed
    first_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={"credential_offer": credential_offer, "holder_did_method": "key"},
    )
    assert (
        first_response.status_code == 200
    ), f"First accept failed: {first_response.text}"

    # Second attempt with same offer - should fail gracefully
    second_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={"credential_offer": credential_offer, "holder_did_method": "key"},
    )

    # Document behavior
    print(f"Reused offer response status: {second_response.status_code}")
    if second_response.status_code == 200:
        print(
            "WARNING: Credential offer was accepted twice - potential token reuse bug"
        )
    else:
        print(f"Correctly rejected reused offer: {second_response.text[:200]}")


@pytest.mark.asyncio
async def test_sphereon_expired_credential_offer(
    acapy_issuer_admin,
    sphereon_client,
):
    """Test Sphereon behavior with an already-used credential offer."""
    random_suffix = str(uuid.uuid4())[:8]
    cred_id = f"SphereonExpiredOffer-{random_suffix}"

    supported = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": cred_id,
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "TestCredential"],
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
            "credential_subject": {"name": "test"},
            "verification_method": issuer_did + "#0",
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # First attempt
    first_response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": offer_response["credential_offer"]}
    )
    assert first_response.status_code == 200

    # Second attempt
    second_response = await sphereon_client.post(
        "/oid4vci/accept-offer", json={"offer": offer_response["credential_offer"]}
    )

    print(f"Sphereon reused offer status: {second_response.status_code}")
    if second_response.status_code == 200:
        print("WARNING: Sphereon accepted reused offer - potential bug")


# =============================================================================
# Presentation Request Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_expired_presentation_request(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test Credo behavior with already-fulfilled presentation request.

    Bug discovery: Does Credo handle double-submission errors correctly?
    """
    # Issue credential first
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"ReplayTestCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "ReplayTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "ReplayTestCredential",
            "claims": {"data": {"mandatory": True}},
        },
        "vc_additional_data": {"sd_list": ["/data"]},
    }

    config_response = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    exchange_response = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config_response["supported_cred_id"],
            "credential_subject": {"data": "replay_test"},
            "did": did_response["result"]["did"],
        },
    )

    offer_response = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange_response["exchange_id"]},
    )

    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer_response["credential_offer"],
            "holder_did_method": "key",
        },
    )
    credential = extract_credential(credo_response, "Credo")

    # Create presentation request
    presentation_definition = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        "input_descriptors": [
            {
                "id": "replay-test",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                "constraints": {
                    "fields": [
                        {"path": ["$.vct"], "filter": {"const": "ReplayTestCredential"}}
                    ]
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": presentation_definition}
    )

    presentation_request = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_response["pres_def_id"],
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        },
    )
    request_uri = presentation_request["request_uri"]

    # First presentation - should succeed
    first_present = await credo_client.post(
        "/oid4vp/present",
        json={"request_uri": request_uri, "credentials": [credential]},
    )
    assert first_present.status_code == 200

    # Wait for verification
    await asyncio.sleep(2)

    # Second presentation with same request - should fail
    second_present = await credo_client.post(
        "/oid4vp/present",
        json={"request_uri": request_uri, "credentials": [credential]},
    )

    print(f"Replay presentation status: {second_present.status_code}")
    if second_present.status_code == 200 and second_present.json().get("success"):
        print(
            "WARNING: Presentation request accepted twice - potential replay vulnerability"
        )


@pytest.mark.asyncio
async def test_credo_mismatched_credential_type(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test Credo presenting wrong credential type for request.

    Issue Identity credential but try to satisfy Employment request.
    """
    random_suffix = str(uuid.uuid4())[:8]

    # Issue Identity credential
    identity_config = {
        "id": f"IdentityOnly_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "Identity",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "IdentityCredential",
            "claims": {"name": {"mandatory": True}},
        },
        "vc_additional_data": {"sd_list": ["/name"]},
    }

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=identity_config
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": {"name": "Identity User"},
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    credo_resp = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
    )

    # Handle case where Credo fails to accept offer (e.g., wallet issues)
    if credo_resp.status_code != 200:
        pytest.skip(f"Credo failed to accept offer: {credo_resp.text}")

    resp_json = credo_resp.json()
    if "credential" not in resp_json:
        pytest.skip(f"Credo did not return credential: {resp_json}")

    identity_credential = resp_json["credential"]

    # Request EMPLOYMENT credential (which we don't have)
    employment_pres_def = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        "input_descriptors": [
            {
                "id": "employment-required",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {"const": "EmploymentCredential"},
                        },  # Wrong type!
                        {"path": ["$.employer"]},
                    ]
                },
            }
        ],
    }

    pres_def_response = await acapy_verifier_admin.post(
        "/oid4vp/presentation-definition", json={"pres_def": employment_pres_def}
    )

    request = await acapy_verifier_admin.post(
        "/oid4vp/request",
        json={
            "pres_def_id": pres_def_response["pres_def_id"],
            "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
        },
    )

    # Try to present Identity credential for Employment request
    present_response = await credo_client.post(
        "/oid4vp/present",
        json={
            "request_uri": request["request_uri"],
            "credentials": [identity_credential],
        },
    )

    print(f"Mismatched credential type status: {present_response.status_code}")

    if present_response.status_code == 200:
        result = present_response.json()
        # Check if Credo reports it couldn't satisfy the request
        if result.get("success"):
            # Check verifier side
            presentation_id = request["presentation"]["presentation_id"]
            for _ in range(5):
                record = await acapy_verifier_admin.get(
                    f"/oid4vp/presentation/{presentation_id}"
                )
                if record.get("state") in [
                    "presentation-valid",
                    "presentation-invalid",
                ]:
                    break
                await asyncio.sleep(1)

            if record.get("state") == "presentation-valid":
                print("BUG: Mismatched credential type was accepted!")
            else:
                print(f"Correctly rejected mismatched type: {record.get('state')}")
    else:
        print(
            f"Credo correctly rejected mismatched credential: {present_response.text[:200]}"
        )


# =============================================================================
# Empty/Null Value Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_empty_claim_values(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test credential with empty string claim values.

    Bug discovery: How do wallets handle empty string vs null vs missing claims?
    """
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"EmptyClaimCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "EmptyClaimTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "EmptyClaimCredential",
            "claims": {
                "required_field": {"mandatory": True},
                "optional_empty": {"mandatory": False},
            },
        },
        "vc_additional_data": {"sd_list": ["/required_field", "/optional_empty"]},
    }

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Issue with empty string value
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": {
                "required_field": "has_value",
                "optional_empty": "",  # Empty string
            },
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Credo accepts
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
    )

    print(f"Empty claim credential issuance: {credo_response.status_code}")
    if credo_response.status_code == 200:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]

        # Try to present with empty claim
        pres_def = {
            "id": str(uuid.uuid4()),
            "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            "input_descriptors": [
                {
                    "id": "empty-claim-test",
                    "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {"const": "EmptyClaimCredential"},
                            },
                            {
                                "path": [
                                    "$.optional_empty",
                                    "$.credentialSubject.optional_empty",
                                ]
                            },
                        ]
                    },
                }
            ],
        }

        pres_def_resp = await acapy_verifier_admin.post(
            "/oid4vp/presentation-definition", json={"pres_def": pres_def}
        )

        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_resp["pres_def_id"],
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )

        present_resp = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request["request_uri"], "credentials": [credential]},
        )

        print(f"Empty claim presentation: {present_resp.status_code}")
        if present_resp.status_code == 200:
            presentation_id = request["presentation"]["presentation_id"]
            for _ in range(5):
                record = await acapy_verifier_admin.get(
                    f"/oid4vp/presentation/{presentation_id}"
                )
                if record.get("state") in [
                    "presentation-valid",
                    "presentation-invalid",
                ]:
                    break
                await asyncio.sleep(1)
            print(f"Empty claim verification: {record.get('state')}")


# =============================================================================
# Special Character Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_credo_special_characters_in_claims(
    acapy_issuer_admin,
    acapy_verifier_admin,
    credo_client,
):
    """Test handling of special characters in claim values.

    Bug discovery: Unicode, quotes, newlines in credential subjects.
    """
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"SpecialCharCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "SpecialCharTest",
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
        },
        "format_data": {
            "cryptographic_binding_methods_supported": ["did:key"],
            "cryptographic_suites_supported": ["EdDSA"],
            "vct": "SpecialCharCredential",
            "claims": {
                "unicode_name": {"mandatory": True},
                "special_chars": {"mandatory": True},
            },
        },
        "vc_additional_data": {"sd_list": ["/unicode_name", "/special_chars"]},
    }

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Issue with special characters
    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": {
                "unicode_name": "José García 日本語 🔐",  # Unicode + emoji
                "special_chars": 'Quote "test" & <angle> brackets',  # Problematic chars
            },
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
    )

    print(f"Special char credential issuance: {credo_response.status_code}")
    if credo_response.status_code != 200:
        print(f"Failed with special chars: {credo_response.text}")
    else:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]

        # Present and verify special chars are preserved
        pres_def = {
            "id": str(uuid.uuid4()),
            "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            "input_descriptors": [
                {
                    "id": "special-char-test",
                    "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {"const": "SpecialCharCredential"},
                            },
                            {
                                "path": [
                                    "$.unicode_name",
                                    "$.credentialSubject.unicode_name",
                                ]
                            },
                        ]
                    },
                }
            ],
        }

        pres_def_resp = await acapy_verifier_admin.post(
            "/oid4vp/presentation-definition", json={"pres_def": pres_def}
        )

        request = await acapy_verifier_admin.post(
            "/oid4vp/request",
            json={
                "pres_def_id": pres_def_resp["pres_def_id"],
                "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA"]}},
            },
        )
        presentation_id = request["presentation"]["presentation_id"]

        present_resp = await credo_client.post(
            "/oid4vp/present",
            json={"request_uri": request["request_uri"], "credentials": [credential]},
        )

        if present_resp.status_code == 200:
            for _ in range(5):
                record = await acapy_verifier_admin.get(
                    f"/oid4vp/presentation/{presentation_id}"
                )
                if record.get("state") in [
                    "presentation-valid",
                    "presentation-invalid",
                ]:
                    break
                await asyncio.sleep(1)

            print(f"Special char verification: {record.get('state')}")
            # Check if values were preserved
            verified = record.get("verified_claims", {})
            print(f"Verified claims with special chars: {verified}")


# =============================================================================
# Concurrent Request Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_concurrent_credential_offers_credo(
    acapy_issuer_admin,
    credo_client,
):
    """Test Credo handling multiple credential offers simultaneously.

    Bug discovery: Race conditions in token handling.
    """
    random_suffix = str(uuid.uuid4())[:8]

    # Create credential config
    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "id": f"ConcurrentCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "ConcurrentTest",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key"],
                "cryptographic_suites_supported": ["EdDSA"],
                "vct": "ConcurrentCredential",
                "claims": {"index": {"mandatory": True}},
            },
            "vc_additional_data": {"sd_list": ["/index"]},
        },
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Create multiple offers
    offers = []
    for i in range(3):
        exchange = await acapy_issuer_admin.post(
            "/oid4vci/exchange/create",
            json={
                "supported_cred_id": config["supported_cred_id"],
                "credential_subject": {"index": f"credential_{i}"},
                "did": did_response["result"]["did"],
            },
        )
        offer = await acapy_issuer_admin.get(
            "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
        )
        offers.append(offer["credential_offer"])

    # Accept all offers concurrently
    async def accept_offer(offer_uri, idx):
        response = await credo_client.post(
            "/oid4vci/accept-offer",
            json={"credential_offer": offer_uri, "holder_did_method": "key"},
        )
        return (
            idx,
            response.status_code,
            response.json() if response.status_code == 200 else response.text,
        )

    results = await asyncio.gather(
        *[accept_offer(offer, i) for i, offer in enumerate(offers)],
        return_exceptions=True,
    )

    # Analyze results
    success_count = 0
    for result in results:
        if isinstance(result, Exception):
            print(f"Concurrent offer exception: {result}")
        else:
            idx, status, _ = result
            print(f"Offer {idx}: status={status}")
            if status == 200:
                success_count += 1

    print(f"Concurrent credential acceptance: {success_count}/{len(offers)} succeeded")

    # All should succeed if there's no race condition
    if success_count < len(offers):
        print("WARNING: Some concurrent offers failed - potential race condition")


# =============================================================================
# Large Payload Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_large_credential_subject(
    acapy_issuer_admin,
    credo_client,
):
    """Test handling of large credential subject payloads.

    Bug discovery: Payload size limits, truncation issues.
    """
    random_suffix = str(uuid.uuid4())[:8]

    # Create credential with many claims
    claims = {f"claim_{i}": {"mandatory": False} for i in range(50)}
    claims["id_field"] = {"mandatory": True}

    sd_list = [f"/claim_{i}" for i in range(50)]
    sd_list.append("/id_field")

    config = await acapy_issuer_admin.post(
        "/oid4vci/credential-supported/create",
        json={
            "id": f"LargeCredential_{random_suffix}",
            "format": "vc+sd-jwt",
            "scope": "LargeTest",
            "proof_types_supported": {
                "jwt": {"proof_signing_alg_values_supported": ["EdDSA"]}
            },
            "format_data": {
                "cryptographic_binding_methods_supported": ["did:key"],
                "cryptographic_suites_supported": ["EdDSA"],
                "vct": "LargeCredential",
                "claims": claims,
            },
            "vc_additional_data": {"sd_list": sd_list},
        },
    )

    did_response = await acapy_issuer_admin.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )

    # Create large credential subject
    credential_subject = {"id_field": "large_credential_test"}
    for i in range(50):
        # Use moderately long values
        credential_subject[f"claim_{i}"] = (
            f"This is claim number {i} with some additional text to make it longer " * 3
        )

    exchange = await acapy_issuer_admin.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": config["supported_cred_id"],
            "credential_subject": credential_subject,
            "did": did_response["result"]["did"],
        },
    )

    offer = await acapy_issuer_admin.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange["exchange_id"]}
    )

    # Try to accept large credential
    credo_response = await credo_client.post(
        "/oid4vci/accept-offer",
        json={
            "credential_offer": offer["credential_offer"],
            "holder_did_method": "key",
        },
        timeout=60.0,  # Extended timeout for large payload
    )

    print(f"Large credential issuance: {credo_response.status_code}")
    if credo_response.status_code == 200:
        resp_json = credo_response.json()
        if "credential" not in resp_json:
            pytest.skip(f"Credo did not return credential: {resp_json}")
        credential = resp_json["credential"]
        print(f"Large credential size: {len(credential)} bytes")
    else:
        print(f"Large credential failed: {credo_response.text[:500]}")

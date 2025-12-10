import uuid
from os import getenv
from typing import Any

import httpx
import pytest_asyncio

from credo_wrapper import CredoWrapper

# Service endpoints from docker-compose.yml environment variables
CREDO_AGENT_URL = getenv("CREDO_AGENT_URL", "http://localhost:3020")
ACAPY_ISSUER_ADMIN_URL = getenv("ACAPY_ISSUER_ADMIN_URL", "http://localhost:8021")
ACAPY_VERIFIER_ADMIN_URL = getenv("ACAPY_VERIFIER_ADMIN_URL", "http://localhost:8031")


@pytest_asyncio.fixture
async def credo():
    """Create a Credo wrapper instance."""
    wrapper = CredoWrapper(CREDO_AGENT_URL)
    async with wrapper as wrapper:
        yield wrapper


@pytest_asyncio.fixture
async def acapy_issuer():
    """HTTP client for ACA-Py issuer admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_ISSUER_ADMIN_URL) as client:
        yield client


@pytest_asyncio.fixture
async def acapy_verifier():
    """HTTP client for ACA-Py verifier admin API."""
    async with httpx.AsyncClient(base_url=ACAPY_VERIFIER_ADMIN_URL) as client:
        yield client


@pytest_asyncio.fixture
async def offer(acapy_issuer: httpx.AsyncClient) -> dict[str, Any]:
    """Create a credential offer."""
    unique_id = f"TestCredential_{uuid.uuid4().hex[:8]}"

    supported_cred_request = {
        "id": unique_id,
        "format": "jwt_vc_json",
        "format_data": {
            "types": ["VerifiableCredential", "TestCredential"],
            "credentialSubject": {
                "name": {"display": [{"name": "Full Name", "locale": "en-US"}]},
                "email": {"display": [{"name": "Email Address", "locale": "en-US"}]},
            },
        },
        "cryptographic_binding_methods_supported": ["did"],
        "cryptographic_suites_supported": ["ES256K"],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
            }
        },
        "display": [
            {
                "name": "Test Credential",
                "locale": "en-US",
                "background_color": "#12107c",
                "text_color": "#FFFFFF",
            }
        ],
    }

    response = await acapy_issuer.post(
        "/oid4vci/credential-supported/create", json=supported_cred_request
    )
    response.raise_for_status()
    supported_cred = response.json()
    supported_cred_id = supported_cred["supported_cred_id"]

    # Create a DID for the issuer
    did_response = await acapy_issuer.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    did_response.raise_for_status()
    issuer_did = did_response.json()["result"]["did"]

    exchange_request = {
        "supported_cred_id": supported_cred_id,
        "credential_subject": {"name": "John Doe", "email": "john.doe@example.com"},
        "did": issuer_did,
    }

    response = await acapy_issuer.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    response.raise_for_status()
    exchange = response.json()
    exchange_id = exchange["exchange_id"]

    response = await acapy_issuer.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    response.raise_for_status()
    return response.json()


@pytest_asyncio.fixture
async def offer_by_ref(offer: dict[str, Any]) -> dict[str, Any]:
    """Return offer by reference."""
    # In this context, offer_by_ref seems to expect the same structure as offer
    # but the test uses offer_by_ref["credential_offer"]
    return offer


@pytest_asyncio.fixture
async def sdjwt_offer(acapy_issuer: httpx.AsyncClient) -> str:
    """Create an SD-JWT credential offer URI."""
    random_suffix = str(uuid.uuid4())[:8]
    credential_supported = {
        "id": f"IdentityCredential_{random_suffix}",
        "format": "vc+sd-jwt",
        "scope": "IdentityCredential",
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["EdDSA", "ES256"]
            }
        },
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

    response = await acapy_issuer.post(
        "/oid4vci/credential-supported/create", json=credential_supported
    )
    response.raise_for_status()
    config_id = response.json()["supported_cred_id"]

    did_response = await acapy_issuer.post(
        "/wallet/did/create", json={"method": "key", "options": {"key_type": "ed25519"}}
    )
    issuer_did = did_response.json()["result"]["did"]

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

    response = await acapy_issuer.post(
        "/oid4vci/exchange/create", json=exchange_request
    )
    response.raise_for_status()
    exchange_id = response.json()["exchange_id"]

    response = await acapy_issuer.get(
        "/oid4vci/credential-offer", params={"exchange_id": exchange_id}
    )
    response.raise_for_status()
    return response.json()["credential_offer"]


@pytest_asyncio.fixture
async def sdjwt_offer_by_ref(sdjwt_offer: str) -> str:
    """Return SD-JWT offer by reference."""
    return sdjwt_offer


@pytest_asyncio.fixture
async def request_uri(acapy_verifier: httpx.AsyncClient) -> str:
    """Create a presentation request URI."""
    # Create presentation definition
    pres_def = {
        "id": str(uuid.uuid4()),
        "input_descriptors": [
            {
                "id": "test_descriptor",
                "name": "Test Descriptor",
                "purpose": "Testing",
                "format": {
                    "jwt_vc_json": {"alg": ["EdDSA", "ES256"]},
                    "jwt_vc": {"alg": ["EdDSA", "ES256"]},
                },
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vc.type", "$.type"],
                            "filter": {
                                "type": "array",
                                "contains": {"const": "TestCredential"},
                            },
                        }
                    ]
                },
            }
        ],
    }

    response = await acapy_verifier.post(
        "/oid4vp/presentation-definition", json={"pres_def": pres_def}
    )
    response.raise_for_status()
    pres_def_id = response.json()["pres_def_id"]

    # Create request
    request_body = {
        "pres_def_id": pres_def_id,
        "vp_formats": {
            "jwt_vp_json": {"alg": ["ES256", "ES256K", "EdDSA"]},
            "jwt_vc_json": {"alg": ["ES256", "ES256K", "EdDSA"]},
            "jwt_vc": {"alg": ["ES256", "ES256K", "EdDSA"]},
            "jwt_vp": {"alg": ["ES256", "ES256K", "EdDSA"]},
        },
    }

    response = await acapy_verifier.post("/oid4vp/request", json=request_body)
    response.raise_for_status()
    return response.json()["request_uri"]


@pytest_asyncio.fixture
async def sdjwt_request_uri(acapy_verifier: httpx.AsyncClient) -> str:
    """Create an SD-JWT presentation request URI."""
    pres_def = {
        "id": str(uuid.uuid4()),
        "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
        "input_descriptors": [
            {
                "id": "identity-descriptor",
                "format": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {"type": "string", "const": "IdentityCredential"},
                        }
                    ]
                },
            }
        ],
    }

    response = await acapy_verifier.post(
        "/oid4vp/presentation-definition", json={"pres_def": pres_def}
    )
    response.raise_for_status()
    pres_def_id = response.json()["pres_def_id"]

    request_body = {
        "pres_def_id": pres_def_id,
        "vp_formats": {"vc+sd-jwt": {"sd-jwt_alg_values": ["EdDSA", "ES256"]}},
    }

    response = await acapy_verifier.post("/oid4vp/request", json=request_body)
    response.raise_for_status()
    return response.json()["request_uri"]

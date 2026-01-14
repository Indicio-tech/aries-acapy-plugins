from os import getenv
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
import pytest_asyncio
from acapy_controller import Controller
from aiohttp import ClientSession
import httpx

from oid4vci_client.client import OpenID4VCIClient


def _env_url(*names: str, default: str) -> str:
    """Return the first non-empty environment variable value from names."""

    for name in names:
        value = getenv(name)
        if value:
            return value
    return default


ISSUER_ADMIN_ENDPOINT = _env_url(
    "ISSUER_ADMIN_ENDPOINT",
    "ACAPY_ISSUER_ADMIN_URL",
    "ACAPY_ADMIN_URL",
    default="http://localhost:3001",
)

OID4VCI_ENDPOINT = _env_url(
    "ACAPY_ISSUER_OID4VCI_URL",
    "OID4VCI_ENDPOINT",
    "OID4VCI_URL",
    default="http://acapy-issuer:8022",
)


@pytest_asyncio.fixture(scope="session")
async def controller():
    """Connect to Issuer."""
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with controller:
        yield controller


@pytest.fixture
def test_client():
    client = OpenID4VCIClient()
    yield client


@pytest_asyncio.fixture(scope="session")
async def issuer_did(controller: Controller):
    result = await controller.post(
        "/did/jwk/create",
        json={
            "key_type": "p256",
        },
    )
    assert "did" in result
    did = result["did"]
    yield did


@pytest_asyncio.fixture(scope="session")
async def supported_cred_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create/jwt",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": "UniversityDegreeCredential",
            # "types": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        },
    )
    yield supported["supported_cred_id"]


@pytest_asyncio.fixture
async def offer(controller: Controller, issuer_did: str, supported_cred_id: str):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    yield offer


@pytest_asyncio.fixture
async def offer_by_ref(controller: Controller, issuer_did: str, supported_cred_id: str):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )

    exchange_param = {"exchange_id": exchange["exchange_id"]}
    offer_ref_full = await controller.get(
        "/oid4vci/credential-offer-by-ref",
        params=exchange_param,
    )

    credential_offer_uri = offer_ref_full["credential_offer_uri"]

    for placeholder in (
        "${OID4VCI_ENDPOINT:-http://localhost:8022}",
        "${OID4VCI_ENDPOINT}",
    ):
        if placeholder in credential_offer_uri:
            credential_offer_uri = credential_offer_uri.replace(placeholder, OID4VCI_ENDPOINT)
            break

    offer_ref = urlparse(credential_offer_uri)
    offer_ref = parse_qs(offer_ref.query)["credential_offer"][0]
    async with ClientSession(headers=controller.headers) as session:
        async with session.request(
            "GET", url=offer_ref, params=exchange_param, headers=controller.headers
        ) as offer:
            yield await offer.json()


@pytest_asyncio.fixture
async def sdjwt_supported_cred_id(controller: Controller, issuer_did: str):
    """Create an SD-JWT VC supported credential."""
    try:
        supported = await controller.post(
            "/oid4vci/credential-supported/create/sd-jwt",
            json={
                "format": "vc+sd-jwt",
                "id": "IDCard",
                "cryptographic_binding_methods_supported": ["jwk"],
                "display": [
                    {
                        "name": "ID Card",
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF",
                    }
                ],
                "vct": "ExampleIDCard",
                "claims": {
                    "given_name": {
                        "mandatory": True,
                        "value_type": "string",
                    },
                    "family_name": {
                        "mandatory": True,
                        "value_type": "string",
                    },
                    "age_equal_or_over": {
                        "12": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "14": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "16": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "18": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "21": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "65": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                    },
                },
                "sd_list": [
                    "/given_name",
                    "/family_name",
                    "/age_equal_or_over/12",
                    "/age_equal_or_over/14",
                    "/age_equal_or_over/16",
                    "/age_equal_or_over/18",
                    "/age_equal_or_over/21",
                    "/age_equal_or_over/65",
                ],
            },
        )
        yield supported["supported_cred_id"]
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 400 and "already exists" in exc.response.text:
            # Re-use the existing supported credential ID
            yield "IDCard"
        else:
            raise


@pytest_asyncio.fixture
async def sdjwt_offer(
    controller: Controller, issuer_did: str, sdjwt_supported_cred_id: str
):
    """Create a cred offer for an SD-JWT VC."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": sdjwt_supported_cred_id,
            "credential_subject": {
                "given_name": "Erika",
                "family_name": "Mustermann",
                "source_document_type": "id_card",
                "age_equal_or_over": {
                    "12": True,
                    "14": True,
                    "16": True,
                    "18": True,
                    "21": True,
                    "65": False,
                },
            },
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = offer["credential_offer"]

    yield offer_uri


@pytest_asyncio.fixture
async def sdjwt_offer_by_ref(
    controller: Controller, issuer_did: str, sdjwt_supported_cred_id: str
):
    """Create a cred offer for an SD-JWT VC."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": sdjwt_supported_cred_id,
            "credential_subject": {
                "given_name": "Erika",
                "family_name": "Mustermann",
                "source_document_type": "id_card",
                "age_equal_or_over": {
                    "12": True,
                    "14": True,
                    "16": True,
                    "18": True,
                    "21": True,
                    "65": False,
                },
            },
            "verification_method": issuer_did + "#0",
        },
    )

    exchange_param = {"exchange_id": exchange["exchange_id"]}
    offer_ref_full = await controller.get(
        "/oid4vci/credential-offer-by-ref",
        params=exchange_param,
    )

    credential_offer_uri = offer_ref_full["credential_offer_uri"]

    for placeholder in (
        "${OID4VCI_ENDPOINT:-http://localhost:8022}",
        "${OID4VCI_ENDPOINT}",
    ):
        if placeholder in credential_offer_uri:
            credential_offer_uri = credential_offer_uri.replace(placeholder, OID4VCI_ENDPOINT)
            break

    offer_ref = urlparse(credential_offer_uri)
    offer_ref = parse_qs(offer_ref.query)["credential_offer"][0]
    async with ClientSession(headers=controller.headers) as session:
        async with session.request(
            "GET", url=offer_ref, params=exchange_param, headers=controller.headers
        ) as offer:
            yield (await offer.json())["credential_offer"]


@pytest_asyncio.fixture
async def presentation_definition_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    record = await controller.post(
        "/oid4vp/presentation-definition",
        json={
            "pres_def": {
                "id": str(uuid4()),
                "purpose": "Present basic profile info",
                "format": {
                    "jwt_vc_json": {"alg": ["ES256"]},
                    "jwt_vp_json": {"alg": ["ES256"]},
                    "jwt_vc": {"alg": ["ES256"]},
                    "jwt_vp": {"alg": ["ES256"]},
                },
                "input_descriptors": [
                    {
                        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
                        "name": "Profile",
                        "purpose": "Present basic profile info",
                        "constraints": {
                            "fields": [
                                {
                                    "name": "name",
                                    "path": [
                                        "$.vc.credentialSubject.name",
                                        "$.credentialSubject.name",
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "pattern": "^.{1,64}$",
                                    },
                                },
                            ]
                        },
                    }
                ],
            }
        },
    )
    yield record["pres_def_id"]


@pytest_asyncio.fixture
async def sdjwt_presentation_definition_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    record = await controller.post(
        "/oid4vp/presentation-definition",
        json={
            "pres_def": {
                "id": str(uuid4()),
                "purpose": "Present basic profile info",
                "format": {"vc+sd-jwt": {}},
                "input_descriptors": [
                    {
                        "id": "ID Card",
                        "name": "Profile",
                        "purpose": "Present basic profile info",
                        "constraints": {
                            "limit_disclosure": "required",
                            "fields": [
                                {"path": ["$.vct"], "filter": {"type": "string"}},
                                {"path": ["$.family_name"]},
                                {"path": ["$.given_name"]},
                            ],
                        },
                    }
                ],
            }
        },
    )
    yield record["pres_def_id"]


@pytest_asyncio.fixture
async def request_uri(
    controller: Controller, issuer_did: str, presentation_definition_id: str
):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vp/request",
        json={
            "pres_def_id": presentation_definition_id,
            "vp_formats": {
                "jwt_vc_json": {"alg": ["ES256", "EdDSA"]},
                "jwt_vp_json": {"alg": ["ES256", "EdDSA"]},
                "jwt_vc": {"alg": ["ES256", "EdDSA"]},
                "jwt_vp": {"alg": ["ES256", "EdDSA"]},
            },
        },
    )
    yield exchange["request_uri"]


@pytest_asyncio.fixture
async def sdjwt_request_uri(
    controller: Controller, issuer_did: str, sdjwt_presentation_definition_id: str
):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vp/request",
        json={
            "pres_def_id": sdjwt_presentation_definition_id,
            "vp_formats": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256", "EdDSA"],
                    "kb-jwt_alg_values": ["ES256", "EdDSA"],
                }
            },
        },
    )
    yield exchange["request_uri"]

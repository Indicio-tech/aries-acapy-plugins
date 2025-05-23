from typing import Any, Dict
import uuid
import pytest
import pytest_asyncio
from acapy_controller.controller import Controller
from credo_wrapper import CredoWrapper
from sphereon_wrapper import SphereaonWrapper
from isomdl_wrapper import ISOMDLWrapper


@pytest_asyncio.fixture(scope="module")
async def mdl_supported_cred_id(controller: Controller, issuer_did: str):
    """Create an mDL supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "format": "mso_mdoc",
            # "id": "org.iso.18013.5.1.mDL",
            "id": str(uuid.uuid4()),
            "cryptographic_binding_methods_supported": ["jwk"],
            "format_data": {
                "doctype": "org.iso.18013.5.1.mDL",
                "claims": {
                    "org.iso.18013.5.1": {
                        "given_name": {},
                        "last_name": {},
                    }
                    # TODO: add additional detail to model an mDL
                },
            },
            "vc_additional_data": {},
        },
    )
    print(f"SUPPORTED: {supported}")
    yield supported["supported_cred_id"]


@pytest_asyncio.fixture
async def mdl_offer(
    controller: Controller, issuer_did: str, mdl_supported_cred_id: str
):
    """Create a cred offer for an SD-JWT VC."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            # TODO: add values to match the supported credential
            "supported_cred_id": mdl_supported_cred_id,
            "credential_subject": {
                "org.iso.18013.5.1": {
                    "given_name": "Test",
                    "test_name": "Surname",
                }
            },
            "did": issuer_did,
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = offer["credential_offer_uri"]

    yield offer_uri


@pytest.mark.interop
@pytest.mark.asyncio
async def test_mdl_credo_accept_credential_offer(credo: CredoWrapper, mdl_offer: str):
    """Test Credo accepting an mDL offer."""
    await credo.openid4vci_accept_offer(mdl_offer)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_mdl_sphereon_accept_credential_offer(
    sphereon: SphereaonWrapper, mdl_offer: str
):
    """Test Sphereon accepting an mDL offer."""
    await sphereon.accept_mdl_credential_offer(mdl_offer)

@pytest.mark.interop
@pytest.mark.asyncio
async def test_mdl_isomdl_accept_credential_offer(
    isomdl: ISOMDLWrapper, mdl_offer: str, controller: Controller, issuer_did: str
):
    result = await controller.post(
        "/oid4vci/cert/get",
        json={
            "did": issuer_did,
        },
    )
    assert "cert" in result
    certificate = result["cert"]
    import ssl
    import base64

    pem_cert = ssl.DER_cert_to_PEM_cert(base64.b64decode(certificate))
    cert = pem_cert
    print(f"Certificate: {certificate}")
    print(f"cert: {cert}")

    """Test isomdl accepting an mDL offer."""
    await isomdl.accept_mdl_credential_offer(cert, mdl_offer)

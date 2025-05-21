from typing import Any, Dict
import uuid
import pytest
import pytest_asyncio
from acapy_controller.controller import Controller
from credo_wrapper import CredoWrapper
from sphereon_wrapper import SphereaonWrapper


@pytest_asyncio.fixture
async def mdl_supported_cred_id(controller: Controller, issuer_did: str):
    """Create an mDL supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "format": "mso_mdoc",
            #"id": "org.iso.18013.5.1.mDL",
            "id": str(uuid.uuid4()),
            "cryptographic_binding_methods_supported": ["jwk"],
            "format_data": {
                "doctype": "org.iso.18013.5.1.mDL",
                "credentialSubject": {
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
            "credential_subject": {},
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
async def test_mdl_accept_credential_offer(credo: CredoWrapper, mdl_offer: str):
   """Test OOB DIDExchange Protocol."""
   await credo.openid4vci_accept_offer(mdl_offer)


@pytest.mark.interop
@pytest.mark.asyncio
async def test_sphereon_pre_auth(sphereon: SphereaonWrapper, mdl_offer: str):
    """Test receive offer for pre auth code flow."""
    await sphereon.accept_mdl_credential_offer(mdl_offer)

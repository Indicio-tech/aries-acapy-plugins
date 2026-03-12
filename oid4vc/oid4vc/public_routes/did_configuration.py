"""DIF Well-Known DID Configuration endpoint.

Spec: https://identity.foundation/.well-known/resources/did-configuration/
"""

import datetime
import logging
import time
from urllib.parse import urlparse

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from aiohttp import web
from aiohttp_apispec import docs

from ..config import Config
from ..did_utils import retrieve_or_create_did_jwk
from ..jwt import jwt_sign

LOGGER = logging.getLogger(__name__)

_DID_CONFIGURATION_CONTEXT = (
    "https://identity.foundation/.well-known/did-configuration/v1"
)
_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"


@docs(tags=["oid4vc"], summary="DIF Well-Known DID Configuration")
async def did_configuration(request: web.Request) -> web.Response:
    """Return a DIF Well-Known DID Configuration document.

    The document contains a signed Domain Linkage Credential JWT that
    cryptographically binds the deployment's DID to its origin URL,
    allowing verifiers to confirm the issuer controls the domain.

    Spec: https://identity.foundation/.well-known/resources/did-configuration/
    """
    context: AdminRequestContext = request["context"]
    config = Config.from_settings(context.settings)
    public_url = config.endpoint

    # Derive the ``origin`` (scheme + host, no path/query/fragment).
    try:
        parsed = urlparse(public_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        origin = public_url

    now = int(time.time())
    issuance_dt = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)
    expiry_dt = issuance_dt + datetime.timedelta(days=365)

    def _iso(dt: datetime.datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        async with context.profile.session() as session:
            jwk_info = await retrieve_or_create_did_jwk(session)
        did = jwk_info.did
        vm = f"{did}#0"
    except (WalletNotFoundError, WalletError) as err:
        LOGGER.error("Cannot sign DID Configuration document: %s", err)
        raise web.HTTPInternalServerError(
            reason="Could not retrieve signing key"
        ) from err

    # Domain Linkage Credential per DIF spec §5
    dlc_payload = {
        "@context": [_VC_CONTEXT, _DID_CONFIGURATION_CONTEXT],
        "issuer": did,
        "issuanceDate": _iso(issuance_dt),
        "expirationDate": _iso(expiry_dt),
        "type": ["VerifiableCredential", "DomainLinkageCredential"],
        "credentialSubject": {
            "id": did,
            "origin": origin,
        },
    }

    try:
        signed_jwt = await jwt_sign(
            context.profile,
            headers={"kid": vm, "typ": "JWT"},
            payload=dlc_payload,
            verification_method=vm,
        )
    except (WalletNotFoundError, WalletError) as err:
        LOGGER.error("Could not sign Domain Linkage Credential: %s", err)
        raise web.HTTPInternalServerError(
            reason="Could not sign Domain Linkage Credential"
        ) from err

    document = {
        "@context": _DID_CONFIGURATION_CONTEXT,
        "linked_dids": [signed_jwt],
    }
    response = web.json_response(document)
    response.headers["Cache-Control"] = "no-store"
    return response
